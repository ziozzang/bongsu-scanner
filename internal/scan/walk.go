package scan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// defaultMaxTotalBytes preserves the archive spool budget.
const defaultMaxTotalBytes = 512 << 20

// defaultWalkMaxTotalBytes bounds total parsed metadata, not retained memory.
const defaultWalkMaxTotalBytes = 4 << 30

// maxRecordedPaths caps the skipped and excluded path lists kept in
// ScanMetadata; beyond it only the counters grow.
const maxRecordedPaths = 200

// errWalkLimit stops a walk once Options.MaxFiles is reached. It never
// escapes DirectoryContext: the partial result is returned with
// ScanMetadata.LimitReached set.
var errWalkLimit = errors.New("walk limit reached")

// mountInfoPath is the mount table of the current mount namespace. It is a
// variable so tests can substitute a fixture.
var mountInfoPath = "/proc/self/mountinfo"

// excludedMountTypes are filesystem types whose mount points are never
// entered: kernel pseudo filesystems, network shares, and container, snap or
// image mounts whose contents would be misattributed to the scanned root.
// Prefix entries (trailing "*") match a family such as cgroup/cgroup2 or
// nfs/nfs4.
var excludedMountTypes = []string{
	"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup*", "securityfs",
	"debugfs", "tracefs", "fusectl", "configfs", "pstore", "bpf", "mqueue",
	"hugetlbfs", "binfmt_misc", "autofs", "efivarfs", "selinuxfs", "ramfs",
	"nfs*", "cifs", "smb*", "fuse.*", "9p", "overlay", "squashfs", "nsfs", "rpc_pipefs",
}

// defaultHostExcludes are root-relative paths skipped by host scans unless
// Options.NoDefaultExcludes is set: pseudo filesystems, temporary and
// removable storage, container/VM/snap image stores (their package
// databases belong to other roots), and per-user caches. Patterns use
// filepath.Match syntax.
var defaultHostExcludes = []string{
	"proc", "sys", "dev", "run", "tmp", "var/tmp", "mnt", "media", "lost+found", "swapfile",
	"var/lib/docker", "var/lib/containerd", "var/lib/containers", "var/lib/flatpak",
	"var/lib/machines", "var/lib/libvirt/images", "snap", "var/snap", "var/cache/apt/archives",
	"home/*/.cache", "root/.cache",
	"home/*/.local/share/containers", "root/.local/share/containers",
	"home/*/.local/share/docker", "root/.local/share/docker",
	// The Go module cache holds a go.mod for every downloaded module version;
	// cataloging it would attribute thousands of foreign dependencies to the host.
	"home/*/go/pkg/mod", "root/go/pkg/mod",
}

// mountEntry is one line of /proc/self/mountinfo.
type mountEntry struct {
	ID         int
	Parent     int
	Dev        string // "major:minor"
	Root       string // path inside the filesystem that is mounted ("/" unless a bind mount)
	MountPoint string
	FSType     string
	Source     string
}

// parseMountInfo reads mountinfo(5) lines. Malformed lines are skipped.
func parseMountInfo(r io.Reader) []mountEntry {
	var out []mountEntry
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(fields) < sep+3 {
			continue
		}
		id, _ := strconv.Atoi(fields[0])
		parent, _ := strconv.Atoi(fields[1])
		out = append(out, mountEntry{
			ID:         id,
			Parent:     parent,
			Dev:        fields[2],
			Root:       unescapeMount(fields[3]),
			MountPoint: unescapeMount(fields[4]),
			FSType:     fields[sep+1],
			Source:     unescapeMount(fields[sep+2]),
		})
	}
	return out
}

// unescapeMount decodes the octal escapes mountinfo uses for space, tab,
// newline and backslash.
func unescapeMount(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func loadMounts() []mountEntry {
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseMountInfo(f)
}

func excludedMountType(fstype string) bool {
	for _, t := range excludedMountTypes {
		if strings.HasSuffix(t, "*") {
			if strings.HasPrefix(fstype, strings.TrimSuffix(t, "*")) {
				return true
			}
		} else if fstype == t {
			return true
		}
	}
	return false
}

// mountExclusions maps paths strictly below root that must not be
// entered or read to their filesystem type. Only excluded types are listed unless
// oneFS is set, in which case every mount point below the root (bind mounts
// included) is a boundary. realRoot is root with symlinks resolved, the form
// mountinfo uses; keys are translated back to the root the walk sees.
func mountExclusions(root, realRoot string, mounts []mountEntry, oneFS bool) map[string]string {
	out := map[string]string{}
	prefix := realRoot
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	for _, m := range mounts {
		if m.MountPoint == realRoot || !strings.HasPrefix(m.MountPoint, prefix) {
			continue
		}
		if !oneFS && !excludedMountType(m.FSType) {
			continue
		}
		p := filepath.Join(root, m.MountPoint[len(prefix):])
		out[p] = m.FSType
	}
	return out
}

// excludeRules holds the compiled exclusion set for one walk root.
type excludeRules struct {
	exactAbs  map[string]string // cleaned absolute path -> reason
	exactRel  map[string]string // root-relative slash path -> reason
	exactBase map[string]string // base name -> reason
	globs     []globRule
}

type globRule struct {
	pattern string
	kind    globKind
	reason  string
	dirOnly bool
}

type globKind int

const (
	globAbs  globKind = iota // matched against the absolute path
	globRel                  // matched against the root-relative slash path
	globBase                 // matched against the base name only
)

func isGlob(p string) bool { return strings.ContainsAny(p, "*?[") }

func newExcludeRules() *excludeRules {
	return &excludeRules{exactAbs: map[string]string{}, exactRel: map[string]string{}, exactBase: map[string]string{}}
}

// add registers one pattern. Absolute patterns match the absolute path;
// relative patterns containing a separator match the root-relative path;
// bare names match any entry with that base name (like tar --exclude).
func (e *excludeRules) add(pattern, reason string, dirOnly bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return
	}
	switch {
	case filepath.IsAbs(pattern):
		pattern = filepath.Clean(pattern)
		if isGlob(pattern) {
			e.globs = append(e.globs, globRule{pattern: pattern, kind: globAbs, reason: reason, dirOnly: dirOnly})
		} else {
			e.exactAbs[pattern] = reason
		}
	case strings.Contains(pattern, "/"):
		pattern = strings.TrimPrefix(path.Clean(filepath.ToSlash(pattern)), "./")
		if isGlob(pattern) {
			e.globs = append(e.globs, globRule{pattern: pattern, kind: globRel, reason: reason, dirOnly: dirOnly})
		} else {
			e.exactRel[pattern] = reason
		}
	default:
		if isGlob(pattern) {
			e.globs = append(e.globs, globRule{pattern: pattern, kind: globBase, reason: reason, dirOnly: dirOnly})
		} else {
			e.exactBase[pattern] = reason
		}
	}
}

func (e *excludeRules) match(abs, rel string, isDir bool) (string, bool) {
	if r, ok := e.exactAbs[abs]; ok {
		return r, true
	}
	if r, ok := e.exactRel[rel]; ok {
		return r, true
	}
	if r, ok := e.exactBase[path.Base(rel)]; ok {
		return r, true
	}
	for _, g := range e.globs {
		if g.dirOnly && !isDir {
			continue
		}
		subject := abs
		switch g.kind {
		case globRel:
			subject = rel
		case globBase:
			subject = path.Base(rel)
		}
		if ok, _ := filepath.Match(g.pattern, subject); ok {
			return g.reason, true
		}
	}
	return "", false
}

// compileExcludes builds the rule set: default host exclusions (directory
// patterns anchored at root) plus user patterns, which also apply to files.
func compileExcludes(root string, opts Options, hostPolicy bool) *excludeRules {
	rules := newExcludeRules()
	if hostPolicy && !opts.NoDefaultExcludes {
		for _, p := range defaultHostExcludes {
			rules.add(filepath.Join(root, p), "default", true)
		}
	}
	for _, p := range opts.Exclude {
		rules.add(p, "user", false)
	}
	return rules
}

// walkState accumulates file hashes, incremental catalogs and scan counters.
type walkState struct {
	workers  int
	parallel *parallelWalk
	spool    *walkSpool

	ctx        context.Context
	opts       Options
	root       string
	hostPolicy bool
	hashFiles  bool // record every regular file's SHA-256
	probe      bool // extract Go build info from ELF executables
	maxBytes   int64

	fs          store
	catalog     cataloger
	binaries    cataloger // merged last to preserve metadata-before-binary precedence
	meta        ScanMetadata
	indexed     int
	totalBytes  int64 // metadata bytes currently held for parsing
	parsedBytes int64 // cumulative non-critical metadata bytes parsed
	budgetHit   bool
	rootDev     uint64
	rules       *excludeRules
	mounts      map[string]string // path -> fstype of a mount that is not entered or read
	safeRoot    *os.Root
	preloaded   map[string]bool

	// Retain at most 64 directory descriptors along the DFS stack. Children
	// are opened relative to a verified parent, without resolving ancestors
	// again. Deeper trees fall back to safeRoot's confined resolution.
	currentDir  *os.File
	currentPath string
	openDirs    int

	// testHook, when set, runs before each directory entry is processed.
	// Tests use it to delete or cancel mid-walk.
	testHook func(p string)
}

func newWalkState(ctx context.Context, root string, opts Options, hostPolicy bool) *walkState {
	w := &walkState{
		ctx:        ctx,
		opts:       opts,
		root:       root,
		hostPolicy: hostPolicy,
		hashFiles:  opts.IncludeFileHashes && !hostPolicy,
		probe:      !opts.SkipBinaries,
		maxBytes:   opts.MaxTotalBytes,
		fs:         store{},
		rules:      compileExcludes(root, opts, hostPolicy),
	}
	if w.maxBytes <= 0 {
		w.maxBytes = defaultWalkMaxTotalBytes
	}
	w.workers = min(8, runtime.NumCPU())
	if opts.Workers > 0 {
		w.workers = opts.Workers
	}
	// BONGSU_WALK_WORKERS remains as an operator override for experiments.
	if n, err := strconv.Atoi(os.Getenv("BONGSU_WALK_WORKERS")); err == nil && n > 0 {
		w.workers = n
	}
	w.meta.EUID = os.Geteuid()
	realRoot := root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		realRoot = resolved
	}
	w.mounts = mountExclusions(root, realRoot, loadMounts(), opts.OneFileSystem)
	if opts.OneFileSystem {
		if info, err := os.Lstat(root); err == nil {
			w.rootDev = deviceOf(info)
		}
	}
	return w
}

// deviceOf returns the st_dev of a file, or 0 when unavailable.
func deviceOf(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		return uint64(st.Dev)
	}
	return 0
}

// metadata finalizes the ScanMetadata for the result.
func (w *walkState) metadata() ScanMetadata {
	m := w.meta
	m.Partial = m.PermissionDenied > 0 || m.SkippedErrors > 0 || m.MetadataSkipped > 0 || m.LimitReached != ""
	return m
}

func (w *walkState) checkCtx() error {
	if w.ctx == nil {
		return nil
	}
	return w.ctx.Err()
}

// skip records a path that could not be read and continues the walk.
func (w *walkState) skip(p string, err error) {
	if errors.Is(err, fs.ErrPermission) {
		w.meta.PermissionDenied++
		if w.parallel != nil {
			w.parallel.recordPath(p, false)
		} else if len(w.meta.SkippedPaths) < maxRecordedPaths {
			w.meta.SkippedPaths = append(w.meta.SkippedPaths, p)
		}
		report(w.opts, "walk", "permission denied: "+p, true)
		return
	}
	w.meta.SkippedErrors++
	report(w.opts, "walk", fmt.Sprintf("skipped %s: %v", p, err), true)
}

func (w *walkState) exclude(reason, p string) {
	w.meta.ExcludedCount++
	if w.parallel != nil {
		w.parallel.recordPath(reason+" "+p, true)
	} else if len(w.meta.Excluded) < maxRecordedPaths {
		w.meta.Excluded = append(w.meta.Excluded, reason+" "+p)
	}
	report(w.opts, "walk", fmt.Sprintf("excluded (%s): %s", reason, p), true)
}

func (w *walkState) rel(p string) string {
	// Walk paths are already clean descendants. Avoid cleaning and comparing
	// every component again; keep the general fallback for other callers.
	if p == w.root {
		return "."
	}
	if w.root == string(filepath.Separator) && strings.HasPrefix(p, w.root) {
		return filepath.ToSlash(p[1:])
	}
	if strings.HasPrefix(p, w.root) && len(p) > len(w.root) && p[len(w.root)] == filepath.Separator {
		return filepath.ToSlash(p[len(w.root)+1:])
	}
	rel, err := filepath.Rel(w.root, p)
	if err != nil {
		return filepath.ToSlash(strings.TrimPrefix(p, w.root))
	}
	return filepath.ToSlash(rel)
}

// walkTree walks root depth-first without following symlinks. Unreadable or
// vanished entries are counted in w.meta and skipped; the only errors
// returned are context cancellation and errWalkLimit.
func walkTree(ctx context.Context, root string, opts Options, w *walkState) error {
	if w.ctx == nil {
		w.ctx = ctx
	}
	if err := w.checkCtx(); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: not a directory", root)
	}
	w.safeRoot, err = os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() {
		if w.safeRoot != nil {
			w.safeRoot.Close()
			w.safeRoot = nil
		}
	}()
	w.preloaded = make(map[string]bool)
	if err := w.preloadInventory("."); err != nil {
		return err
	}
	// A file cap selects an exact DFS prefix, so retain the sequential path.
	// Hooks inspect the sequential descriptor stack and are also kept there.
	if w.workers > 1 && opts.MaxFiles <= 0 && w.testHook == nil && w.openDirs == 0 {
		err = w.walkParallel(root)
		if errors.Is(err, errParallelBudget) {
			// Parallel reservations cannot choose the same budget-limited DFS
			// prefix. Drain first, discard speculative results, then replay.
			w.safeRoot.Close()
			fresh := newWalkState(ctx, root, opts, w.hostPolicy)
			fresh.workers = 1
			fresh.meta.InContainer = w.meta.InContainer
			*w = *fresh
			err = walkTree(ctx, root, opts, w)
		}
	} else {
		err = w.walkDir(root)
	}
	if ctxErr := w.checkCtx(); ctxErr != nil {
		return ctxErr
	}
	return err
}

// openWalkFile rejects a symlink at the final component. os.Root also
// confines ancestor resolution if an already visited directory is replaced.
func (w *walkState) openWalkFile(p string, directory bool) (*os.File, fs.FileInfo, error) {
	flags := os.O_RDONLY
	if runtime.GOOS == "linux" {
		flags |= syscall.O_NOFOLLOW | syscall.O_NONBLOCK
		if directory {
			flags |= syscall.O_DIRECTORY
		}
	} else {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, nil, err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("%s: symlink replaced walk entry", p)
		}
	}
	var f *os.File
	var err error
	if runtime.GOOS == "linux" && w.currentDir != nil && filepath.Dir(p) == w.currentPath {
		// p is an immediate child from ReadDir: no slash or ".." can escape
		// the verified descriptor. O_NOFOLLOW also rejects a replaced child.
		var fd int
		for {
			fd, err = unix.Openat(int(w.currentDir.Fd()), filepath.Base(p), flags|unix.O_CLOEXEC, 0)
			if err != syscall.EINTR {
				break
			}
		}
		if err != nil {
			err = &os.PathError{Op: "openat", Path: p, Err: err}
		} else {
			f = os.NewFile(uintptr(fd), p)
		}
	} else if w.safeRoot != nil {
		f, err = w.safeRoot.OpenFile(w.rel(p), flags, 0)
	} else {
		f, err = os.OpenFile(p, flags, 0)
	}
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err == nil && ((directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular())) {
		err = fmt.Errorf("%s: walk entry changed type", p)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// Critical inventories are read before unrelated trees can spend the metadata
// budget, including RPM databases at both historical and current locations.
// Lstat each component, then open without following symlinks; os.Root also
// prevents an ancestor replacement from escaping the scan root.
func (w *walkState) preloadInventory(rel string) error {
	if err := w.checkCtx(); err != nil {
		return err
	}
	p := filepath.Join(w.root, rel)
	info, err := w.safeRoot.Lstat(rel)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 {
		// The normal walk accounts for unreadable/vanished paths once.
		return nil
	}
	if _, excluded := w.rules.match(p, w.rel(p), info.IsDir()); excluded {
		return nil
	}
	if _, excluded := w.mounts[p]; excluded {
		return nil
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() || (!interesting(rel) && !isRPMDatabase(rel)) {
			return nil
		}
		w.preloaded[p] = true
		return w.visitFileWithBudget(p, fs.FileInfoToDirEntry(info), true)
	}
	f, info, err := w.openWalkFile(p, true)
	if err != nil {
		return nil
	}
	defer f.Close()
	if w.opts.OneFileSystem && w.rootDev != 0 && deviceOf(info) != 0 && deviceOf(info) != w.rootDev {
		return nil
	}
	children := map[string][]string{
		".":   {"etc", "usr", "var", "lib"},
		"etc": {"os-release"}, "usr": {"lib"},
		"usr/lib": {"os-release", "apk", "sysimage"}, "lib": {"apk"},
		"usr/lib/sysimage":     {"rpm"},
		"usr/lib/sysimage/rpm": {"rpmdb.sqlite", "Packages", "Packages.db"},
		"lib/apk":              {"db"}, "usr/lib/apk": {"db"},
		"lib/apk/db": {"installed"}, "usr/lib/apk/db": {"installed"},
		"var": {"lib"}, "var/lib": {"dpkg", "rpm"},
		"var/lib/rpm":  {"rpmdb.sqlite", "Packages", "Packages.db"},
		"var/lib/dpkg": {"status", "status.d"},
	}[filepath.ToSlash(rel)]
	if filepath.ToSlash(rel) == "var/lib/dpkg/status.d" {
		entries, _ := f.ReadDir(-1)
		for _, d := range entries {
			if d.Type().IsRegular() {
				children = append(children, d.Name())
			}
		}
		sort.Strings(children)
	}
	for _, child := range children {
		if err := w.preloadInventory(filepath.Join(rel, child)); err != nil {
			return err
		}
	}
	return w.checkCtx()
}

func (w *walkState) walkDir(dir string) error {
	if err := w.checkCtx(); err != nil {
		return err
	}
	f, info, err := w.openWalkFile(dir, true)
	if err != nil {
		w.skip(dir, err)
		return nil
	}
	if w.opts.OneFileSystem && w.rootDev != 0 && deviceOf(info) != 0 && deviceOf(info) != w.rootDev {
		f.Close()
		w.exclude("onefs", dir)
		return nil
	}
	if w.parallel != nil {
		// An unbuffered handoff transfers the already verified descriptor to
		// an idle worker. With no idle worker, continue DFS on this stack.
		w.parallel.tasks.Add(1)
		select {
		case w.parallel.jobs <- walkDirectory{dir, f}:
			return nil
		default:
			w.parallel.tasks.Done()
		}
	}
	return w.walkOpenedDir(dir, f)
}

func (w *walkState) walkOpenedDir(dir string, f *os.File) error {
	entries, err := f.ReadDir(-1)
	parent, parentPath := w.currentDir, w.currentPath
	w.currentDir, w.currentPath = nil, ""
	if runtime.GOOS == "linux" && w.openDirs < 64 {
		w.currentDir, w.currentPath = f, dir
		w.openDirs++
		defer func() { f.Close(); w.openDirs-- }()
	} else {
		f.Close()
	}
	defer func() { w.currentDir, w.currentPath = parent, parentPath }()
	if err != nil {
		// Keep whatever was listed before the error (EIO, ESTALE, vanished).
		w.skip(dir, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	prefix := dir
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	for _, d := range entries {
		// ReadDir names are single components, never "." or "..".
		p := prefix + d.Name()
		if w.testHook != nil {
			w.testHook(p)
		}
		typ := d.Type()
		switch {
		case typ.IsDir():
			if err := w.enterDir(p, d); err != nil {
				return err
			}
		case typ&fs.ModeSymlink != 0:
			// Never followed: symlinked metadata resolves through its target
			// path, and directory symlinks would create loops.
		case typ.IsRegular():
			if err := w.visitFile(p, d); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *walkState) enterDir(p string, d fs.DirEntry) error {
	rel := w.rel(p)
	if reason, ok := w.rules.match(p, rel, true); ok {
		w.exclude(reason, p)
		return nil
	}
	if fstype, ok := w.mounts[p]; ok {
		w.exclude("mount:"+fstype, p)
		return nil
	}
	if w.opts.OneFileSystem && w.rootDev != 0 {
		info, err := d.Info()
		if err != nil {
			w.skip(p, err)
			return nil
		}
		if dev := deviceOf(info); dev != 0 && dev != w.rootDev {
			w.exclude("onefs", p)
			return nil
		}
	}
	return w.walkDir(p)
}

func (w *walkState) progressTick() {
	n, indexed := w.meta.FilesVisited, w.indexed
	if w.parallel != nil {
		n = w.parallel.visited.Add(1)
		indexed = int(w.parallel.indexed.Load())
	}
	step := int64(1000)
	if n >= 10000 {
		step = 10000
	}
	if n%step == 0 {
		report(w.opts, "walk", fmt.Sprintf("visited %d regular files, indexed %d", n, indexed), false)
	}
}

func (w *walkState) visitFile(p string, d fs.DirEntry) error {
	if w.preloaded[p] {
		return w.checkCtx()
	}
	return w.visitFileWithBudget(p, d, false)
}

func (w *walkState) skipMetadata(p, reason string) {
	w.meta.MetadataSkipped++
	report(w.opts, "walk", "skipped ("+reason+"): "+p, true)
}

func (w *walkState) hitBudget() {
	if !w.budgetHit {
		w.budgetHit = true
		w.meta.LimitReached = joinLimit(w.meta.LimitReached, "max-total-bytes")
		report(w.opts, "walk", fmt.Sprintf("warning: metadata budget of %d bytes exhausted; further package metadata files are skipped", w.maxBytes), false)
	}
}

// fileModeSize stats an immediate child without rewalking its ancestors.
// Only regularity, executable bits and size are needed here. All other types
// are represented as ModeIrregular; the opened file is still checked by fstat.
func (w *walkState) fileModeSize(p string, d fs.DirEntry) (fs.FileMode, int64, error) {
	if runtime.GOOS == "linux" && w.currentDir != nil && filepath.Dir(p) == w.currentPath {
		var st unix.Stat_t
		var err error
		for {
			err = unix.Fstatat(int(w.currentDir.Fd()), d.Name(), &st, unix.AT_SYMLINK_NOFOLLOW)
			if err != syscall.EINTR {
				break
			}
		}
		if err != nil {
			return 0, 0, &os.PathError{Op: "lstat", Path: p, Err: err}
		}
		mode := fs.FileMode(st.Mode & 0o777)
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			mode |= fs.ModeIrregular
		}
		return mode, st.Size, nil
	}
	info, err := d.Info()
	if err != nil {
		return 0, 0, err
	}
	return info.Mode(), info.Size(), nil
}

func (w *walkState) visitFileWithBudget(p string, d fs.DirEntry, exempt bool) error {
	if err := w.checkCtx(); err != nil {
		return err
	}
	w.meta.FilesVisited++
	w.progressTick()
	if w.opts.MaxFiles > 0 && w.meta.FilesVisited > w.opts.MaxFiles {
		w.meta.FilesVisited--
		w.meta.LimitReached = joinLimit(w.meta.LimitReached, "max-files")
		report(w.opts, "walk", fmt.Sprintf("file limit reached (%d); stopping walk", w.opts.MaxFiles), false)
		return errWalkLimit
	}
	rel := w.rel(p)
	if reason, ok := w.rules.match(p, rel, false); ok {
		w.exclude(reason, p)
		return nil
	}
	if fstype, ok := w.mounts[p]; ok {
		w.exclude("mount:"+fstype, p)
		return nil
	}
	// Parser inputs live only until addFile returns. Ordinary files are
	// hashed/probed without buffering their contents.
	rpm := isRPMDatabase(rel)
	keep := interesting(rel) || rpm
	if !keep && !w.hashFiles && !w.probe {
		return nil
	}
	mode, size, err := w.fileModeSize(p, d)
	if err != nil {
		w.skip(p, err)
		return nil
	}
	if !mode.IsRegular() {
		return nil
	}
	probe := w.probe && mode&0o111 != 0 && size >= 4 && size <= maxGoBinary
	fileLimit := int64(maxMetadata)
	if rpm {
		fileLimit = maxRPMDatabase
	}
	// Reserve before reading. If the shared budget cannot cover this file,
	// cancel and replay sequentially rather than change which paths fit.
	if w.parallel != nil && keep && size <= fileLimit && !exempt {
		if !w.parallel.reserve(size) {
			return errParallelBudget
		}
		before := w.parsedBytes
		defer func() { w.parallel.bytes.Add(w.parsedBytes - before - size) }()
	}
	allowed := fileLimit
	if !exempt {
		allowed = min(allowed, max(0, w.maxBytes-w.parsedBytes))
	}
	if keep && size > fileLimit {
		w.skipMetadata(p, "metadata size limit")
		keep = false
	} else if keep && size > allowed {
		w.hitBudget()
		w.skipMetadata(p, "metadata budget")
		keep = false
	}
	if !keep && !w.hashFiles && !probe {
		return w.checkCtx()
	}
	if err := w.checkCtx(); err != nil {
		return err
	}
	f, openedInfo, err := w.openWalkFile(p, false)
	if err != nil {
		w.skip(p, err)
		return nil
	}
	defer f.Close()
	if w.opts.OneFileSystem && w.rootDev != 0 {
		if dev := deviceOf(openedInfo); dev != 0 && dev != w.rootDev {
			w.exclude("onefs", p)
			return nil
		}
	}
	switch {
	case keep && rpm:
		// Copy from the confined descriptor rather than reopening a mutable
		// host pathname. Large databases never enter a metadata byte slice.
		tmp, err := os.CreateTemp("", "bscan-rpm-*")
		if err != nil {
			w.skip(p, err)
			return nil
		}
		defer os.Remove(tmp.Name())
		h := sha256.New()
		var dst io.Writer = tmp
		if w.hashFiles {
			dst = io.MultiWriter(tmp, h)
		}
		n, err := io.Copy(dst, io.LimitReader(walkContextReader{w.ctx, f}, min(size, allowed)+1))
		closeErr := tmp.Close()
		if ctxErr := w.checkCtx(); ctxErr != nil {
			return ctxErr
		}
		if err != nil || closeErr != nil {
			w.skip(p, errors.Join(err, closeErr))
			return nil
		}
		if n > min(size, allowed) {
			w.skipMetadata(p, "metadata grew beyond read limit")
			return nil
		}
		rec := File{Path: rel, Size: n}
		count, err := w.catalogRPM(rec, tmp.Name())
		if err != nil {
			return err
		}
		if count != 0 {
			w.meta.SkippedErrors += count
			report(w.opts, "walk", fmt.Sprintf("%s: %d RPM database parse errors", rel, count), true)
		}
		if !exempt {
			w.parsedBytes += n
		}
		if w.hashFiles {
			rec.SHA256 = hex.EncodeToString(h.Sum(nil))
			w.fs[rel] = rec
		}
		w.indexed++
		if w.parallel != nil {
			w.parallel.indexed.Add(1)
		}
		report(w.opts, "file", fmt.Sprintf("%s (%d bytes)", rel, n), true)
	case keep:
		rec, err := readFileForWalk(w.ctx, rel, f, size, allowed)
		if err != nil {
			if ctxErr := w.checkCtx(); ctxErr != nil {
				return ctxErr
			}
			if errors.Is(err, errMetadataLimit) {
				w.skipMetadata(p, "metadata grew beyond read limit")
			} else {
				w.skip(p, err)
			}
			return nil
		}
		w.totalBytes = int64(len(rec.Data))
		if err := w.catalogFile(rec); err != nil {
			return err
		}
		if !exempt {
			w.parsedBytes += w.totalBytes
		}
		rec.Data = nil
		w.totalBytes = 0
		if w.hashFiles {
			w.fs[rel] = rec
		}
		w.indexed++
		if w.parallel != nil {
			w.parallel.indexed.Add(1)
		}
		report(w.opts, "file", fmt.Sprintf("%s (%d bytes)", rel, size), true)
	case w.hashFiles:
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(walkContextReader{w.ctx, f}, size+1))
		if ctxErr := w.checkCtx(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			w.skip(p, err)
			return nil
		}
		if n > size {
			w.skip(p, fmt.Errorf("file grew while hashing"))
			return nil
		}
		w.fs[rel] = File{Path: rel, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))}
		w.indexed++
		if w.parallel != nil {
			w.parallel.indexed.Add(1)
		}
		report(w.opts, "file", fmt.Sprintf("%s (%d bytes)", rel, size), true)
	}
	if err := w.checkCtx(); err != nil {
		return err
	}
	if probe {
		w.probeBinary(f, rel, size)
	}
	return w.checkCtx()
}

// probeBinary extracts Go build info from an ELF executable. The file is
// read through io.ReaderAt, so it does not matter that hashing consumed it.
func (w *walkState) probeBinary(f *os.File, rel string, size int64) {
	r := walkContextReaderAt{w.ctx, f}
	head := make([]byte, 4)
	if _, err := r.ReadAt(head, 0); err != nil || !isELF(head) {
		return
	}
	pkgs := goBinaryPackages(r, size, rel, "")
	if len(pkgs) == 0 {
		return
	}
	if w.parallel != nil {
		w.parallel.record(walkCatalog{path: rel, packages: pkgs, binary: true})
	} else {
		w.binaries.addPackages(pkgs)
	}
	report(w.opts, "binary", fmt.Sprintf("%s: %d packages from Go build info", rel, len(pkgs)), true)
}

// Go build-info probing uses ReaderAt instead of the metadata reader.
type walkContextReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (r walkContextReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if r.ctx != nil && r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	n, err := r.r.ReadAt(p, off)
	if r.ctx != nil && r.ctx.Err() != nil {
		return n, r.ctx.Err()
	}
	return n, err
}

func joinLimit(existing, add string) string {
	if existing == "" {
		return add
	}
	if strings.Contains(existing, add) {
		return existing
	}
	return existing + "," + add
}

// normalizeRoot cleans a directory target for policy decisions: "//", "/."
// and symlinks to "/" all identify the host root.
func normalizeRoot(target string) string {
	abs, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return filepath.Clean(target)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

// IsHostTarget reports whether target selects the local host: the "host"
// keyword or any spelling of the root directory.
func IsHostTarget(target string) bool {
	if target == "host" || target == "host://" {
		return true
	}
	return normalizeRoot(target) == "/"
}

var errParallelBudget = errors.New("parallel walk metadata reservation exhausted")

// walkDirectory owns an opened, type/device-checked directory. Handoffs use
// an unbuffered channel: at most workers tasks execute, with no pending queue.
// A busy pool falls back to DFS, retaining at most 64 parent FDs per worker.
type walkDirectory struct {
	path string
	file *os.File
}

// walkCatalog retains parsed discoveries, never input bytes. Replay keeps the
// original within-file order as well as DFS order across files; both matter
// for first-value fields and the catalog's bounded source list.
type walkCatalog struct {
	path     string
	packages []Package
	osr      *OSRelease
	rank     int
	binary   bool
	spool    *walkSpool
	offset   int64
	length   int64
	count    int
	encoder  *gob.Encoder
}

type parallelWalk struct {
	jobs       chan walkDirectory
	tasks      sync.WaitGroup
	visited    atomic.Int64
	indexed    atomic.Int64
	bytes      atomic.Int64
	maxBytes   int64
	mu         sync.Mutex
	progressMu sync.Mutex
	catalogs   []walkCatalog
	skipped    []string
	excluded   []string
	err        error
	cancel     context.CancelFunc
}

func (p *parallelWalk) reserve(size int64) bool {
	for {
		used := p.bytes.Load()
		if size < 0 || size > p.maxBytes-used {
			return false
		}
		if p.bytes.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

func (p *parallelWalk) record(c walkCatalog) {
	if len(c.packages) == 0 && c.count == 0 && c.osr == nil {
		return
	}
	c.encoder = nil
	p.mu.Lock()
	p.catalogs = append(p.catalogs, c)
	p.mu.Unlock()
}

// walkPathLess compares component by component, like the sequential DFS.
// Plain string sorting would put "a-b" before the contents of directory "a".
func walkPathLess(a, b string) bool {
	for i := 0; i < min(len(a), len(b)); i++ {
		if a[i] == b[i] {
			continue
		}
		if a[i] == '/' {
			return true
		}
		if b[i] == '/' {
			return false
		}
		return a[i] < b[i]
	}
	return len(a) < len(b)
}

func (p *parallelWalk) recordPath(value string, excluded bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := &p.skipped
	key := func(s string) string { return s }
	if excluded {
		list = &p.excluded
		key = func(s string) string { _, path, _ := strings.Cut(s, " "); return path }
	}
	i := sort.Search(len(*list), func(i int) bool { return !walkPathLess(key((*list)[i]), key(value)) })
	if i >= maxRecordedPaths {
		return
	}
	*list = append(*list, "")
	copy((*list)[i+1:], (*list)[i:])
	(*list)[i] = value
	if len(*list) > maxRecordedPaths {
		*list = (*list)[:maxRecordedPaths]
	}
}

// walkSpool streams package records to an unlinked temporary file. Only a
// bounded write buffer and one file's parsed input remain live per worker.
// The directory queue and the deterministic replay index contain no packages.
type walkSpool struct {
	file   *os.File
	buffer *bufio.Writer
	size   int64
}

func (s *walkSpool) Write(data []byte) (int, error) {
	n, err := s.buffer.Write(data)
	s.size += int64(n)
	return n, err
}

func (w *walkState) spoolPackage(c *walkCatalog, pkg Package) error {
	if w.spool == nil {
		f, err := os.CreateTemp("", "bscan-walk-*")
		if err != nil {
			return fmt.Errorf("walk result spool: %w", err)
		}
		if err := os.Remove(f.Name()); err != nil {
			f.Close()
			return fmt.Errorf("unlink walk result spool: %w", err)
		}
		w.spool = &walkSpool{file: f, buffer: bufio.NewWriterSize(f, 64<<10)}
	}
	if c.spool == nil {
		c.spool, c.offset = w.spool, w.spool.size
		c.encoder = gob.NewEncoder(w.spool)
	}
	if err := c.encoder.Encode(pkg); err != nil {
		return fmt.Errorf("write walk result spool: %w", err)
	}
	c.count++
	c.length = w.spool.size - c.offset
	return nil
}

func (w *walkState) catalogFile(f File) error {
	if w.parallel == nil {
		w.catalog.addFile(f)
		return nil
	}
	if len(f.Data) == 0 {
		return nil
	}
	c := walkCatalog{path: f.Path}
	if rank := osReleaseRank(f.Path); rank != 0 {
		if o := parseOSRelease(f.Data); o.ID != "" {
			c.osr, c.rank = &o, rank
		}
	}
	var err error
	scanFile(f, func(pkg Package) {
		if err == nil {
			err = w.spoolPackage(&c, pkg)
		}
	})
	if err != nil {
		return err
	}
	w.parallel.record(c)
	return nil
}

func (w *walkState) catalogRPM(f File, diskPath string) (int, error) {
	if w.parallel == nil {
		return w.catalog.addRPMFile(f, diskPath), nil
	}
	c := walkCatalog{path: f.Path}
	var err error
	n := scanRPMDatabase(f, diskPath, func(pkg Package) {
		if err == nil {
			err = w.spoolPackage(&c, pkg)
		}
	})
	if err != nil {
		return n, err
	}
	w.parallel.record(c)
	return n, nil
}

func (w *walkState) walkParallel(root string) error {
	ctx, cancel := context.WithCancel(w.ctx)
	defer cancel()
	p := &parallelWalk{jobs: make(chan walkDirectory), maxBytes: w.maxBytes, cancel: cancel}
	p.visited.Store(w.meta.FilesVisited)
	p.indexed.Store(int64(w.indexed))
	p.bytes.Store(w.parsedBytes)
	opts := w.opts
	if progress := opts.Progress; progress != nil {
		opts.Progress = func(event Progress) {
			p.progressMu.Lock()
			defer p.progressMu.Unlock()
			progress(event)
		}
	}
	// The critical inventory catalog stays untouched until every worker has
	// stopped. Only the caller replays discoveries; no cataloger is shared.
	states := make([]*walkState, w.workers-1)
	defer func() {
		if w.spool != nil {
			w.spool.file.Close()
			w.spool = nil
		}
		for _, local := range states {
			if local.spool != nil {
				local.spool.file.Close()
			}
		}
	}()
	var workers sync.WaitGroup
	for i := range states {
		local := &walkState{
			ctx: ctx, opts: opts, root: w.root, hostPolicy: w.hostPolicy,
			hashFiles: w.hashFiles, probe: w.probe, maxBytes: w.maxBytes,
			fs: store{}, rootDev: w.rootDev, rules: w.rules, mounts: w.mounts,
			safeRoot: w.safeRoot, preloaded: w.preloaded, parallel: p,
		}
		states[i] = local
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range p.jobs {
				err := local.checkCtx()
				if err == nil {
					err = local.walkOpenedDir(task.path, task.file)
				} else {
					task.file.Close()
				}
				if err != nil {
					p.mu.Lock()
					if p.err == nil {
						p.err = err
						p.cancel()
					}
					p.mu.Unlock()
				}
				p.tasks.Done()
			}
		}()
	}
	// The caller is the final worker, so the concurrency bound also covers
	// the root task. Root work must not be handed off before children exist.
	originalCtx, originalOpts := w.ctx, w.opts
	w.ctx, w.opts, w.parallel = ctx, opts, p
	f, info, err := w.openWalkFile(root, true)
	if err != nil {
		w.skip(root, err)
		err = nil
	} else if w.opts.OneFileSystem && w.rootDev != 0 && deviceOf(info) != 0 && deviceOf(info) != w.rootDev {
		f.Close()
		w.exclude("onefs", root)
	} else {
		err = w.walkOpenedDir(root, f)
	}
	if err != nil {
		p.mu.Lock()
		if p.err == nil {
			p.err = err
		}
		p.cancel()
		p.mu.Unlock()
	}
	p.tasks.Wait()
	w.ctx, w.opts, w.parallel = originalCtx, originalOpts, nil
	close(p.jobs)
	workers.Wait()
	if p.err != nil {
		return p.err
	}
	if w.spool != nil {
		if err := w.spool.buffer.Flush(); err != nil {
			return fmt.Errorf("flush walk result spool: %w", err)
		}
	}
	for _, local := range states {
		if local.spool != nil {
			if err := local.spool.buffer.Flush(); err != nil {
				return fmt.Errorf("flush walk result spool: %w", err)
			}
		}
		w.meta.PermissionDenied += local.meta.PermissionDenied
		w.meta.SkippedErrors += local.meta.SkippedErrors
		w.meta.MetadataSkipped += local.meta.MetadataSkipped
		w.meta.ExcludedCount += local.meta.ExcludedCount
		w.indexed += local.indexed
		w.parsedBytes += local.parsedBytes
		for path, file := range local.fs {
			w.fs[path] = file
		}
	}
	w.meta.FilesVisited = p.visited.Load()
	w.meta.SkippedPaths = append(w.meta.SkippedPaths, p.skipped...)
	w.meta.SkippedPaths = w.meta.SkippedPaths[:min(len(w.meta.SkippedPaths), maxRecordedPaths)]
	w.meta.Excluded = append(w.meta.Excluded, p.excluded...)
	w.meta.Excluded = w.meta.Excluded[:min(len(w.meta.Excluded), maxRecordedPaths)]
	sort.SliceStable(p.catalogs, func(i, j int) bool {
		return walkPathLess(p.catalogs[i].path, p.catalogs[j].path)
	})
	for _, c := range p.catalogs {
		if c.binary {
			w.binaries.addPackages(c.packages)
			continue
		}
		if c.osr != nil && c.rank > w.catalog.osRank {
			w.catalog.osr, w.catalog.osRank = c.osr, c.rank
		}
		if c.spool != nil {
			decoder := gob.NewDecoder(io.NewSectionReader(c.spool.file, c.offset, c.length))
			for range c.count {
				if err := w.checkCtx(); err != nil {
					return err
				}
				var pkg Package
				if err := decoder.Decode(&pkg); err != nil {
					return fmt.Errorf("read walk result spool: %w", err)
				}
				w.catalog.addPackage(pkg)
			}
		}
	}
	return nil
}
