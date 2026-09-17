package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxMetadata = 16 << 20

type Options struct {
	IncludeFileHashes bool
	Now               time.Time
	Verbose           bool
	Progress          func(Progress)
	// Platform selects the image manifest from multi-architecture OCI
	// indexes, formatted "os/arch[/variant]". Empty means linux/<GOARCH>.
	Platform string
	// AllowDigestMismatch records layers whose content hash differs from the
	// declared digest with Verified=false instead of aborting the scan.
	AllowDigestMismatch bool

	// Exclude adds paths the local filesystem walk must not enter or index.
	// Absolute entries match the absolute path, relative entries containing
	// "/" match the root-relative path, and bare names match any entry with
	// that base name. All accept filepath.Match globs.
	Exclude []string
	// NoDefaultExcludes disables the built-in host exclusion list (/proc,
	// /sys, /var/lib/docker, user caches, ...). Mount-type boundaries still
	// apply.
	NoDefaultExcludes bool
	// OneFileSystem stops the walk at every mount point below the root, like
	// find -xdev; bind and network mounts are never entered.
	OneFileSystem bool
	// MaxFiles stops the walk after this many regular files (0 = unlimited).
	// The result is marked partial.
	MaxFiles int64
	// MaxTotalBytes caps metadata parsed by a local walk (0 = 4 GiB).
	// Critical OS inventories are exempt; skipped metadata is counted separately.
	MaxTotalBytes int64
	// SkipBinaries disables Go build-info extraction from ELF executables
	// found during a local walk.
	SkipBinaries bool
	// Workers bounds the number of directories walked concurrently during
	// host and directory scans (0 = min(8, NumCPU); 1 = sequential).
	Workers int
	// IncludeDeclared keeps dependencies declared by lock/requirement files
	// that live inside an installed package (for example a Gemfile.lock
	// bundled in an installed gem). They are not installed software and are
	// skipped by default; when kept they carry Evidence "declared".
	IncludeDeclared bool
	// NoHostMetadata leaves Result.Host empty for host scans.
	NoHostMetadata bool
	// RedactIPs drops IP addresses from the host metadata.
	RedactIPs bool
	// IncludeContainers makes TargetAll scan every running Docker container
	// after a host scan, each as its own Result.
	IncludeContainers bool
	// ContainersOptional permits host-only success when container enumeration fails.
	ContainersOptional bool
	// HostRoot overrides the directory scanned for the "host" target
	// (default "/"). Host policy (no file hashes, default excludes, host
	// metadata) still applies; tests use it to walk a fixture tree.
	HostRoot string

	// skipSourceHash is set for docker save/export temp files, which are not
	// stable source artifacts and must not be hashed or recorded.
	skipSourceHash bool
	// hostPolicy is set by Target for the host root: file hashes off, default
	// excludes on, ScanMetadata.InContainer detected.
	hostPolicy bool
}

type Progress struct {
	Stage   string
	Message string
	Detail  bool
}

func report(opts Options, stage, message string, detail bool) {
	if opts.Progress != nil && (!detail || opts.Verbose) {
		opts.Progress(Progress{Stage: stage, Message: message, Detail: detail})
	}
}

type store map[string]File

func Target(ctx context.Context, target string, opts Options) (Result, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	switch {
	case target == "host" || target == "host://":
		root := opts.HostRoot
		if root == "" {
			root = "/"
		}
		report(opts, "source", "local host filesystem selected (package metadata only; file SHA disabled)", false)
		return scanHost(ctx, root, opts)
	case strings.HasPrefix(target, "docker://"):
		report(opts, "source", "Docker image selected: "+strings.TrimPrefix(target, "docker://"), false)
		return dockerImage(ctx, strings.TrimPrefix(target, "docker://"), opts)
	case strings.HasPrefix(target, "container://"):
		report(opts, "source", "Docker container selected: "+strings.TrimPrefix(target, "container://"), false)
		return dockerContainer(ctx, strings.TrimPrefix(target, "container://"), opts)
	}
	st, err := os.Stat(target)
	if err != nil {
		return Result{}, err
	}
	if st.IsDir() {
		root := normalizeRoot(target)
		if root == "/" {
			// "/", "//", "/." and symlinks to the root are the host: apply
			// the host policy instead of hashing every file on the machine.
			report(opts, "source", fmt.Sprintf("treating %s as host scan (package metadata only; file SHA disabled)", target), false)
			return scanHost(ctx, root, opts)
		}
		report(opts, "source", "local directory selected: "+target, false)
		return DirectoryContext(ctx, root, filepath.Base(root), opts)
	}
	report(opts, "source", "local archive selected: "+target, false)
	return archiveContext(ctx, target, opts)
}

// TargetAll scans target like Target and, for host scans with
// Options.IncludeContainers, also every running Docker container. Each
// container is returned as its own Result named "host:container:<name>";
// its packages are never merged into the host inventory. Containers that
// fail to export are skipped and reported in the returned error alongside
// the successful results; only the host scan itself is fatal.
func TargetAll(ctx context.Context, target string, opts Options) ([]Result, error) {
	r, err := Target(ctx, target, opts)
	if err != nil {
		return nil, err
	}
	results := []Result{r}
	if r.SourceType != "host" || !opts.IncludeContainers {
		return results, nil
	}
	containers, err := runningContainers(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return results, err
		}
		report(opts, "docker", "warning: cannot list running containers, skipping --containers: "+err.Error(), false)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return results, ctxErr
		}
		if !opts.ContainersOptional {
			return results, err
		}
		return results, nil
	}
	report(opts, "docker", fmt.Sprintf("%d running container(s) to scan", len(containers)), false)
	var errs []error
	for _, c := range containers {
		report(opts, "docker", fmt.Sprintf("scanning running container %s (%s)", c.name, shortID(c.id)), false)
		cr, err := dockerContainer(ctx, c.id, opts)
		if err != nil {
			if ctx.Err() != nil {
				return results, err
			}
			report(opts, "docker", fmt.Sprintf("warning: container %s skipped: %v", c.name, err), false)
			errs = append(errs, fmt.Errorf("container %s: %w", c.name, err))
			continue
		}
		cr.Name = "host:container:" + c.name
		results = append(results, cr)
	}
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, errors.Join(errs...)
}

type runningContainer struct {
	id   string
	name string
}

// runningContainers lists running Docker containers with their full IDs.
// The name falls back to the short ID when docker reports none.
func runningContainers(ctx context.Context) ([]runningContainer, error) {
	out, err := runDocker(ctx, "ps", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}")
	if err != nil {
		return nil, err
	}
	var list []runningContainer
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if fields[0] == "" {
			continue
		}
		c := runningContainer{id: fields[0]}
		if len(fields) == 2 {
			c.name = strings.TrimPrefix(strings.SplitN(strings.TrimSpace(fields[1]), ",", 2)[0], "/")
		}
		if c.name == "" {
			c.name = shortID(c.id)
		}
		list = append(list, c)
	}
	return list, nil
}

// scanHost walks root under the host policy: no per-file hashes, default
// exclusions, absolute package sources, and host metadata.
func scanHost(ctx context.Context, root string, opts Options) (Result, error) {
	hostOpts := opts
	hostOpts.IncludeFileHashes = false
	hostOpts.hostPolicy = true
	r, err := DirectoryContext(ctx, root, "host", hostOpts)
	if err != nil {
		return Result{}, err
	}
	r.SourceType = "host"
	makeHostPackageSourcesAbsolute(r.Packages)
	// Package cataloging has already consumed the selected metadata files.
	// Do not emit those implementation-detail file digests in a host SBOM.
	r.Files = nil
	if opts.NoHostMetadata {
		report(opts, "metadata", "host metadata disabled (--no-host-metadata)", false)
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		return r, nil
	}
	metadata := collectHostMetadata(r.OSName, r.OSVersion)
	if opts.RedactIPs {
		metadata.IPAddresses = nil
	}
	r.Host = &metadata
	report(opts, "metadata", fmt.Sprintf("host=%s cpu=%d ram=%d bytes ip=%d",
		metadata.Hostname, metadata.CPUCount, metadata.MemoryBytes, len(metadata.IPAddresses)), false)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return r, nil
}

func makeHostPackageSourcesAbsolute(packages []Package) {
	for i := range packages {
		sources := strings.Split(packages[i].Source, ";")
		for j, source := range sources {
			if source != "" && !strings.HasPrefix(source, "/") {
				sources[j] = "/" + source
			}
		}
		packages[i].Source = strings.Join(sources, ";")
	}
}

// Directory scans a local directory tree without a cancellation context.
func Directory(root, name string, opts Options) (Result, error) {
	return DirectoryContext(context.Background(), root, name, opts)
}

// DirectoryContext walks root (see walkTree) and catalogs the package
// metadata it finds. Unreadable and vanished entries never abort the scan;
// they are counted in Result.Scan, which marks the result partial. The root
// directory "/" always gets the host policy. The only errors are an
// unreadable root and context cancellation.
func DirectoryContext(ctx context.Context, root, name string, opts Options) (Result, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if abs, err := filepath.Abs(filepath.Clean(root)); err == nil {
		root = abs
	}
	hostPolicy := opts.hostPolicy || root == "/"
	if hostPolicy {
		opts.IncludeFileHashes = false
	}
	w := newWalkState(ctx, root, opts, hostPolicy)
	report(opts, "walk", "walking local filesystem: "+root, false)
	if hostPolicy {
		w.meta.InContainer = detectContainer()
		if w.meta.InContainer {
			report(opts, "walk", "warning: running inside a container; the host scan covers this container's filesystem, not the underlying host", false)
		}
		if w.meta.EUID != 0 {
			report(opts, "walk", fmt.Sprintf("warning: running as uid %d; package databases under /root, /var/lib/docker may be unreadable", w.meta.EUID), false)
		}
	}
	if len(w.mounts) > 0 {
		report(opts, "walk", fmt.Sprintf("%d mount point(s) below the root will not be entered", len(w.mounts)), true)
	}
	err := walkTree(ctx, root, opts, w)
	if err != nil && !errors.Is(err, errWalkLimit) {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	meta := w.metadata()
	report(opts, "walk", fmt.Sprintf("scan summary: visited=%d indexed=%d denied=%d errors=%d metadata-skipped=%d excluded=%d partial=%t",
		meta.FilesVisited, w.indexed, meta.PermissionDenied, meta.SkippedErrors, meta.MetadataSkipped, meta.ExcludedCount, meta.Partial), false)
	if meta.Partial {
		report(opts, "walk", fmt.Sprintf("warning: partial scan (denied=%d errors=%d metadata-skipped=%d limit=%q); the inventory may be incomplete",
			meta.PermissionDenied, meta.SkippedErrors, meta.MetadataSkipped, meta.LimitReached), false)
	}
	report(opts, "catalog", "finishing streamed package catalog", false)
	extra, _ := w.binaries.finish()
	for _, p := range extra {
		// Binary discoveries are already deduplicated. Replay their bounded
		// source list separately to preserve mergePackage's source cap.
		for _, source := range strings.Split(p.Source, ";") {
			p.Source = source
			w.catalog.addPackage(p)
		}
	}
	r := Result{Name: name, Source: root, SourceType: "directory", ScannedAt: opts.Now.UTC(), Scan: &meta}
	r.Packages, r.OS = w.catalog.finish()
	reportDeclaredPolicy(opts, &meta, w.catalog.declaredSkipped)
	if r.OS != nil {
		r.OSName, r.OSVersion = r.OS.ID, r.OS.VersionID
	}
	if w.hashFiles {
		r.Files = make([]File, 0, len(w.fs))
		for _, f := range w.fs {
			r.Files = append(r.Files, f)
		}
		sort.Slice(r.Files, func(i, j int) bool { return r.Files[i].Path < r.Files[j].Path })
	}
	report(opts, "catalog", fmt.Sprintf("catalog complete: %d packages; os=%s %s", len(r.Packages), r.OSName, r.OSVersion), false)
	for _, p := range r.Packages {
		report(opts, "package", fmt.Sprintf("%s %s (%s)", p.Name, p.Version, p.Type), true)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return r, nil
}

// Archive scans a local tar (optionally gzip/bzip2 compressed, detected by
// magic bytes): a docker save archive, an OCI image layout, or a plain root
// filesystem. See image.go for the implementation.
func Archive(file string, opts Options) (Result, error) {
	return archiveContext(context.Background(), file, opts)
}

// digestPath maps an OCI digest ("sha256:abc") to its blob path in a layout.
func digestPath(d string) string {
	p := strings.SplitN(d, ":", 2)
	if len(p) != 2 {
		return d
	}
	return "blobs/" + p[0] + "/" + p[1]
}

// walkContextReader checks cancellation between filesystem reads. A read
// already blocked in the kernel cannot be interrupted by this wrapper.
type walkContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r walkContextReader) Read(p []byte) (int, error) {
	if r.ctx != nil {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
	}
	n, err := r.r.Read(p)
	if r.ctx != nil && r.ctx.Err() != nil {
		return n, r.ctx.Err()
	}
	return n, err
}

var errMetadataLimit = errors.New("metadata exceeds read limit")

// readFileForWalk bounds both allocation and growth beyond the stat snapshot.
// Archive readers retain their separate entry-boundary handling in readFile.
func readFileForWalk(ctx context.Context, name string, r io.Reader, size, allowed int64) (File, error) {
	limit := min(size, allowed, int64(maxMetadata))
	if limit < 0 {
		return File{}, errMetadataLimit
	}
	// The stat snapshot already bounds the read. Allocate once, including
	// one sentinel byte to detect growth, instead of ReadAll's repeated
	// geometric expansions. Keep EOF, read-error and cancellation precedence.
	data := make([]byte, 0, int(limit)+1)
	reader := walkContextReader{ctx, r}
	for len(data) < cap(data) {
		n, err := reader.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err != io.EOF {
				return File{}, err
			}
			break
		}
	}
	if int64(len(data)) > limit {
		return File{}, errMetadataLimit
	}
	if ctx != nil && ctx.Err() != nil {
		return File{}, ctx.Err()
	}
	digest := sha256.Sum256(data)
	return File{Path: name, Size: size, SHA256: hex.EncodeToString(digest[:]), Data: data}, nil
}

func readFile(name string, r io.Reader, size int64, layer string) (File, error) {
	h := sha256.New()
	var data []byte
	if size <= maxMetadata && interesting(name) {
		b, err := io.ReadAll(io.TeeReader(r, h))
		if err != nil {
			return File{}, err
		}
		data = b
	} else if _, err := io.Copy(h, r); err != nil {
		return File{}, err
	}
	return File{Path: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil)), Data: data, Layer: layer}, nil
}

// clean normalizes an archive entry name to a root-relative slash path:
// backslashes become slashes, leading "/" and "./" are dropped, and "." (the
// root itself) becomes "". Names that still start with ".." escape the root
// and are rejected by callers via unsafePath.
func clean(p string) string {
	p = path.Clean(strings.TrimLeft(strings.ReplaceAll(p, "\\", "/"), "/"))
	if p == "." {
		return ""
	}
	return strings.TrimPrefix(p, "./")
}

func interesting(p string) bool {
	if isJavaArchive(p) || isInstalledNPMPackage(p) || isInstalledGemspec(p) {
		return true
	}
	p = strings.TrimPrefix(strings.ToLower(p), "/")
	base := path.Base(p)
	switch p {
	// Only the root's own os-release counts; nested copies (container
	// layers, chroots, test fixtures) must not override the host identity.
	case "etc/os-release", "usr/lib/os-release",
		"var/lib/dpkg/status", "lib/apk/db/installed", "usr/lib/apk/db/installed":
		return true
	}
	if strings.HasPrefix(p, "var/lib/dpkg/status.d/") && !strings.HasSuffix(base, ".md5sums") {
		return true
	}
	if isRPMDatabase(p) {
		return true
	}
	switch base {
	case "package-lock.json", ".package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
		"go.mod", "requirements.txt", "poetry.lock", "pipfile.lock", "uv.lock", "pkg-info",
		"cargo.lock", "pom.properties", "gemfile.lock", "composer.lock", "packages.lock.json":
		return true
	}
	return strings.HasSuffix(p, ".dist-info/metadata") || strings.HasSuffix(p, ".egg-info") || strings.HasSuffix(base, ".deps.json")
}

// buildResult catalogs a merged filesystem without image metadata; extra
// carries packages found outside metadata files (Go binary build info).
// Image and archive scans use assembleResult (image.go) directly.
func buildResult(name, source, kind string, fs store, layers []File, extra []Package, now time.Time, opts Options) Result {
	return assembleResult(name, source, kind, fs, layers, nil, extra, now, opts)
}

func digestFile(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
