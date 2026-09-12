package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func packageNames(r Result) map[string]Package {
	out := map[string]Package{}
	for _, p := range r.Packages {
		name := p.Name
		if p.Type == "golang" && p.Namespace != "" {
			name = p.Namespace + "/" + name
		}
		out[name] = p
	}
	return out
}

func TestWalkPermissionDeniedIsCountedAndContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/go.mod":      "module a\nrequire example.com/a v1.0.0\n",
		"denied/go.mod": "module hidden\nrequire example.com/hidden v9.9.9\n",
		"z/go.mod":      "module z\nrequire example.com/z v2.0.0\n",
	})
	denied := filepath.Join(root, "denied")
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(denied, 0o755) })

	r, err := DirectoryContext(context.Background(), root, "t", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Scan == nil {
		t.Fatal("Scan metadata missing")
	}
	if r.Scan.PermissionDenied != 1 || !r.Scan.Partial || r.Scan.SkippedErrors != 0 {
		t.Fatalf("scan metadata = %+v", r.Scan)
	}
	if len(r.Scan.SkippedPaths) != 1 || r.Scan.SkippedPaths[0] != denied {
		t.Fatalf("skipped paths = %v", r.Scan.SkippedPaths)
	}
	if r.Scan.EUID != os.Geteuid() {
		t.Fatalf("euid = %d", r.Scan.EUID)
	}
	got := packageNames(r)
	if _, ok := got["example.com/hidden"]; ok {
		t.Fatal("package from unreadable directory was cataloged")
	}
	if _, ok := got["example.com/a"]; !ok {
		t.Fatalf("sibling before denied directory missing: %v", got)
	}
	if _, ok := got["example.com/z"]; !ok {
		t.Fatalf("sibling after denied directory missing: %v", got)
	}
}

func TestWalkContinuesWhenEntriesVanish(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/go.mod":           "module a\nrequire example.com/a v1.0.0\n",
		"b/sub/go.mod":       "module b\n",
		"c/go.mod":           "module c\nrequire example.com/c v1.0.0\n",
		"d/gone.go.mod":      "",
		"d/requirements.txt": "requests==1.0\n",
	})
	opts := Options{}
	w := newWalkState(context.Background(), root, opts, false)
	w.testHook = func(p string) {
		switch filepath.Base(p) {
		case "a":
			// Directory b disappears after listing, before it is opened.
			os.RemoveAll(filepath.Join(root, "b"))
		case "requirements.txt":
			// A file listed by ReadDir vanishes before Info/Open.
			os.Remove(p)
		}
	}
	if err := walkTree(context.Background(), root, opts, w); err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	meta := w.metadata()
	if meta.SkippedErrors != 2 || meta.PermissionDenied != 0 || !meta.Partial {
		t.Fatalf("metadata = %+v", meta)
	}
	pkgs, _ := w.catalog.finish()
	got := packageNames(Result{Packages: pkgs})
	if _, ok := got["example.com/c"]; !ok {
		t.Fatalf("walk did not continue after vanished directory: %v", got)
	}
	if _, ok := got["requests"]; ok {
		t.Fatal("vanished file was cataloged")
	}
}

func keys(fs store) []string {
	var out []string
	for k := range fs {
		out = append(out, k)
	}
	return out
}

func TestWalkExcludePatterns(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"keep/go.mod":                "module keep\nrequire example.com/keep v1.0.0\n",
		"skipabs/go.mod":             "module skipabs\nrequire example.com/abs v1.0.0\n",
		"nested/deep/go.mod":         "module nested\nrequire example.com/rel v1.0.0\n",
		"x/node_modules/go.mod":      "module nm\nrequire example.com/base v1.0.0\n",
		"y/node_modules/go.mod":      "module nm2\nrequire example.com/base2 v1.0.0\n",
		"glob/app-1/go.mod":          "module g1\nrequire example.com/glob1 v1.0.0\n",
		"glob/app-2/go.mod":          "module g2\nrequire example.com/glob2 v1.0.0\n",
		"files/keep.txt":             "",
		"files/drop.log":             "",
		"files/requirements.txt":     "requests==1.0\n",
		"files/requirements.txt.bak": "",
	})
	r, err := DirectoryContext(context.Background(), root, "t", Options{
		IncludeFileHashes: true,
		Exclude: []string{
			filepath.Join(root, "skipabs"),    // absolute exact
			"nested/deep",                     // root-relative exact
			"node_modules",                    // bare name, anywhere
			filepath.Join(root, "glob/app-*"), // absolute glob
			"*.log",                           // bare glob applies to files
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := packageNames(r)
	for _, absent := range []string{"example.com/abs", "example.com/rel", "example.com/base", "example.com/base2", "example.com/glob1", "example.com/glob2"} {
		if _, ok := got[absent]; ok {
			t.Errorf("excluded package %s was cataloged", absent)
		}
	}
	if _, ok := got["example.com/keep"]; !ok {
		t.Errorf("kept package missing: %v", got)
	}
	if _, ok := got["requests"]; !ok {
		t.Errorf("requirements.txt was not cataloged: %v", got)
	}
	paths := map[string]bool{}
	for _, f := range r.Files {
		paths[f.Path] = true
	}
	if paths["files/drop.log"] || !paths["files/keep.txt"] {
		t.Errorf("file exclusion wrong: %v", paths)
	}
	if r.Scan.ExcludedCount != 7 || len(r.Scan.Excluded) != 7 {
		t.Errorf("excluded = %d %v", r.Scan.ExcludedCount, r.Scan.Excluded)
	}
	for _, e := range r.Scan.Excluded {
		if !strings.HasPrefix(e, "user ") {
			t.Errorf("exclusion reason missing: %q", e)
		}
	}
	if r.Scan.Partial {
		t.Errorf("exclusions must not mark the scan partial: %+v", r.Scan)
	}
}

func TestWalkContextCancellation(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{}
	for i := 0; i < 50; i++ {
		files[fmt.Sprintf("d%02d/f", i)] = ""
	}
	writeTree(t, root, files)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DirectoryContext(ctx, root, "t", Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled context: err = %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	w := newWalkState(ctx, root, Options{}, false)
	visited := 0
	w.testHook = func(p string) {
		visited++
		if visited == 5 {
			cancel()
		}
	}
	err := walkTree(ctx, root, Options{}, w)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-walk cancel: err = %v", err)
	}
	if visited > 8 {
		t.Fatalf("walk continued after cancellation: %d entries visited", visited)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if _, err := DirectoryContext(ctx, root, "t", Options{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: err = %v", err)
	}
}

func TestWalkMaxFiles(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("f%02d.txt", i)] = "x"
	}
	writeTree(t, root, files)
	r, err := DirectoryContext(context.Background(), root, "t", Options{IncludeFileHashes: true, MaxFiles: 7})
	if err != nil {
		t.Fatal(err)
	}
	if r.Scan.FilesVisited != 7 || len(r.Files) != 7 {
		t.Fatalf("visited=%d files=%d", r.Scan.FilesVisited, len(r.Files))
	}
	if !r.Scan.Partial || r.Scan.LimitReached != "max-files" {
		t.Fatalf("limit not recorded: %+v", r.Scan)
	}
	r, err = DirectoryContext(context.Background(), root, "t", Options{IncludeFileHashes: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Scan.FilesVisited != 20 || r.Scan.Partial {
		t.Fatalf("unlimited walk: %+v", r.Scan)
	}
}

func TestWalkMetadataBudget(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/go.mod": "module a\nrequire example.com/a v1.0.0\n",
		"b/go.mod": "module b\nrequire example.com/b v1.0.0\n",
	})
	r, err := DirectoryContext(context.Background(), root, "t", Options{MaxTotalBytes: 40})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 1 || r.Scan.SkippedErrors != 0 || r.Scan.MetadataSkipped != 1 || !strings.Contains(r.Scan.LimitReached, "max-total-bytes") || !r.Scan.Partial {
		t.Fatalf("budget: packages=%d scan=%+v", len(r.Packages), r.Scan)
	}
}

func TestWalkExtractsGoBinaryPackages(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("no test executable:", err)
	}
	root := t.TempDir()
	bin := filepath.Join(root, "usr", "local", "bin", "tool")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, self, bin, 0o755)
	// Same content without the executable bit must not be probed.
	copyFile(t, self, filepath.Join(root, "usr", "local", "bin", "tool.dat"), 0o644)

	r, err := DirectoryContext(context.Background(), root, "t", Options{})
	if err != nil {
		t.Fatal(err)
	}
	var stdlib []Package
	for _, p := range r.Packages {
		if p.Name == "stdlib" && p.Type == "golang" {
			stdlib = append(stdlib, p)
		}
	}
	if len(stdlib) != 1 {
		t.Fatalf("stdlib packages = %+v (all: %d)", stdlib, len(r.Packages))
	}
	if stdlib[0].Source != "usr/local/bin/tool" {
		t.Fatalf("binary package source = %q", stdlib[0].Source)
	}
	if stdlib[0].Version != goVersionNumber(runtime.Version()) {
		t.Fatalf("go version = %q, want %q", stdlib[0].Version, goVersionNumber(runtime.Version()))
	}

	r, err = DirectoryContext(context.Background(), root, "t", Options{SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 0 {
		t.Fatalf("SkipBinaries still produced %+v", r.Packages)
	}
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

const mountInfoFixture = `24 29 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw
25 29 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
29 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw,errors=remount-ro
32 24 0:27 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:8 - cgroup2 cgroup2 rw,nsdelegate
48 29 259:5 / /data rw,relatime shared:88 - ext4 /dev/nvme1n1p2 rw
49 29 259:5 /projects /srv/projects rw,relatime shared:89 - ext4 /dev/nvme1n1p2 rw
50 29 0:60 / /mnt/share rw,relatime shared:90 - nfs4 fileserver:/export rw,vers=4.2
51 29 0:61 / /mnt/my\040docs rw,relatime shared:91 - cifs //nas/docs rw
121 29 0:53 / /var/lib/docker/overlay2/abc/merged rw,relatime shared:359 - overlay overlay rw,lowerdir=/x
130 29 7:1 / /snap/core/1 ro,nodev,relatime shared:99 - squashfs /dev/loop1 ro
garbage line without separator
`

func TestParseMountInfo(t *testing.T) {
	mounts := parseMountInfo(strings.NewReader(mountInfoFixture))
	if len(mounts) != 10 {
		t.Fatalf("parsed %d entries, want 10", len(mounts))
	}
	byPoint := map[string]mountEntry{}
	for _, m := range mounts {
		byPoint[m.MountPoint] = m
	}
	if m := byPoint["/mnt/my docs"]; m.FSType != "cifs" || m.Source != "//nas/docs" {
		t.Fatalf("escaped mount point not decoded: %+v", byPoint)
	}
	if m := byPoint["/srv/projects"]; m.Root != "/projects" || m.Dev != "259:5" || m.ID != 49 || m.Parent != 29 {
		t.Fatalf("bind mount fields = %+v", m)
	}
	if m := byPoint["/"]; m.FSType != "ext4" {
		t.Fatalf("root entry = %+v", m)
	}

	ex := mountExclusions("/", "/", mounts, false)
	for _, want := range []string{"/sys", "/proc", "/sys/fs/cgroup", "/mnt/share", "/mnt/my docs", "/var/lib/docker/overlay2/abc/merged", "/snap/core/1"} {
		if _, ok := ex[want]; !ok {
			t.Errorf("%s not auto-excluded: %v", want, ex)
		}
	}
	for _, keep := range []string{"/", "/data", "/srv/projects"} {
		if _, ok := ex[keep]; ok {
			t.Errorf("%s excluded without OneFileSystem", keep)
		}
	}
	if ex["/mnt/share"] != "nfs4" || ex["/sys/fs/cgroup"] != "cgroup2" {
		t.Errorf("fstype recorded wrong: %v", ex)
	}

	ex = mountExclusions("/", "/", mounts, true)
	if _, ok := ex["/data"]; !ok {
		t.Errorf("OneFileSystem did not exclude /data: %v", ex)
	}
	if _, ok := ex["/srv/projects"]; !ok {
		t.Errorf("OneFileSystem did not exclude bind mount: %v", ex)
	}
	if _, ok := ex["/"]; ok {
		t.Errorf("root itself excluded")
	}

	// Scanning below a mount point: only nested mounts count, translated to
	// the (possibly symlinked) root the walk uses.
	ex = mountExclusions("/link/docker", "/var/lib/docker", mounts, false)
	if len(ex) != 1 || ex["/link/docker/overlay2/abc/merged"] != "overlay" {
		t.Errorf("nested exclusions = %v", ex)
	}
}

func TestExcludedMountTypes(t *testing.T) {
	for _, fstype := range []string{"proc", "sysfs", "tmpfs", "cgroup", "cgroup2", "nfs", "nfs4", "cifs", "smb3", "fuse.sshfs", "overlay", "squashfs", "9p", "nsfs", "autofs"} {
		if !excludedMountType(fstype) {
			t.Errorf("%s should be excluded", fstype)
		}
	}
	for _, fstype := range []string{"ext4", "xfs", "btrfs", "zfs", "vfat", "fuseblk"} {
		if excludedMountType(fstype) {
			t.Errorf("%s should be walked", fstype)
		}
	}
}

func TestWalkSkipsMountPointsFromMountInfo(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/os-release":            "ID=hostos\nVERSION_ID=1\n",
		"srv/go.mod":                "module srv\nrequire example.com/srv v1.0.0\n",
		"mnt/nfs/go.mod":            "module nfs\nrequire example.com/nfs v1.0.0\n",
		"opt/overlay/merged/go.mod": "module ovl\nrequire example.com/overlay v1.0.0\n",
		"data/go.mod":               "module data\nrequire example.com/data v1.0.0\n",
	})
	fixture := filepath.Join(t.TempDir(), "mountinfo")
	real, _ := filepath.EvalSymlinks(root)
	content := fmt.Sprintf(`1 0 0:1 / %s rw - ext4 /dev/root rw
2 1 0:2 / %s/mnt/nfs rw - nfs4 server:/x rw
3 1 0:3 / %s/opt/overlay/merged rw - overlay overlay rw
4 1 8:1 / %s/data rw - ext4 /dev/sdb1 rw
`, real, real, real, real)
	if err := os.WriteFile(fixture, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := mountInfoPath
	mountInfoPath = fixture
	t.Cleanup(func() { mountInfoPath = old })

	r, err := DirectoryContext(context.Background(), root, "t", Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := packageNames(r)
	if _, ok := got["example.com/nfs"]; ok {
		t.Error("entered an nfs mount")
	}
	if _, ok := got["example.com/overlay"]; ok {
		t.Error("entered an overlay mount")
	}
	if _, ok := got["example.com/data"]; !ok {
		t.Error("ext4 mount skipped without OneFileSystem")
	}
	if _, ok := got["example.com/srv"]; !ok {
		t.Error("plain directory skipped")
	}
	if r.Scan.ExcludedCount != 2 {
		t.Errorf("excluded = %v", r.Scan.Excluded)
	}
	for _, e := range r.Scan.Excluded {
		if !strings.HasPrefix(e, "mount:nfs4 ") && !strings.HasPrefix(e, "mount:overlay ") {
			t.Errorf("exclusion reason = %q", e)
		}
	}

	r, err = DirectoryContext(context.Background(), root, "t", Options{OneFileSystem: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := packageNames(r)["example.com/data"]; ok {
		t.Error("OneFileSystem entered a nested mount")
	}
}

func TestNormalizeRootTreatsRootSpellingsAsHost(t *testing.T) {
	for _, target := range []string{"/", "//", "/.", "/../", "///./"} {
		if got := normalizeRoot(target); got != "/" {
			t.Errorf("normalizeRoot(%q) = %q", target, got)
		}
		if !IsHostTarget(target) {
			t.Errorf("IsHostTarget(%q) = false", target)
		}
	}
	if !IsHostTarget("host") || !IsHostTarget("host://") {
		t.Error("host keyword not recognized")
	}
	dir := t.TempDir()
	for _, target := range []string{dir, dir + "/.", dir + "//", "."} {
		if IsHostTarget(target) {
			t.Errorf("IsHostTarget(%q) = true", target)
		}
	}
	link := filepath.Join(t.TempDir(), "rootlink")
	if err := os.Symlink("/", link); err == nil && !IsHostTarget(link) {
		t.Errorf("symlink to / not treated as host")
	}
}

func TestHostPolicyAppliesToFixtureRoot(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/os-release":      "ID=hostos\nVERSION_ID=7\n",
		"var/lib/dpkg/status": "Package: libc6\nStatus: install ok installed\nVersion: 2.39-1\nArchitecture: amd64\n\n",
		"srv/app/go.mod":      "module app\nrequire example.com/app v1.0.0\n",
		"proc/1/go.mod":       "module proc\nrequire example.com/proc v1.0.0\n",
		"var/lib/docker/overlay2/x/diff/etc/os-release": "ID=alpine\nVERSION_ID=3.20\n",
		"var/lib/docker/overlay2/x/diff/app/go.mod":     "module ctr\nrequire example.com/container v1.0.0\n",
		"home/alice/.cache/go-build/go.mod":             "module cache\nrequire example.com/cache v1.0.0\n",
		"home/alice/go/pkg/mod/example.com/m@v1/go.mod": "module m\nrequire example.com/modcache v1.0.0\n",
		"home/alice/project/go.mod":                     "module proj\nrequire example.com/project v1.0.0\n",
		"root/.local/share/containers/storage/go.mod":   "module podman\nrequire example.com/podman v1.0.0\n",
		"snap/core/go.mod":                              "module snap\nrequire example.com/snap v1.0.0\n",
		"usr/bin/plain.txt":                             "not indexed under host policy",
	})
	var logs []string
	r, err := Target(context.Background(), "host", Options{
		HostRoot:          root,
		IncludeFileHashes: true, // must be forced off by the host policy
		Progress:          func(p Progress) { logs = append(logs, p.Message) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceType != "host" || r.Name != "host" || r.Files != nil {
		t.Fatalf("host result: type=%s name=%s files=%d", r.SourceType, r.Name, len(r.Files))
	}
	if r.OSName != "hostos" || r.OSVersion != "7" {
		t.Fatalf("os = %s %s (container os-release leaked?)", r.OSName, r.OSVersion)
	}
	got := packageNames(r)
	for _, want := range []string{"libc6", "example.com/app", "example.com/project"} {
		if _, ok := got[want]; !ok {
			t.Errorf("host package %s missing: %v", want, keysOf(got))
		}
	}
	for _, absent := range []string{"example.com/proc", "example.com/container", "example.com/cache", "example.com/modcache", "example.com/podman", "example.com/snap"} {
		if _, ok := got[absent]; ok {
			t.Errorf("excluded location leaked package %s", absent)
		}
	}
	if got["example.com/app"].Source != "/srv/app/go.mod" {
		t.Errorf("host package source = %q", got["example.com/app"].Source)
	}
	if r.Scan == nil || r.Scan.ExcludedCount != 6 {
		t.Fatalf("scan metadata = %+v", r.Scan)
	}
	for _, e := range r.Scan.Excluded {
		if !strings.HasPrefix(e, "default ") {
			t.Errorf("default exclusion reason missing: %q", e)
		}
	}
	if r.Host == nil || r.Host.Hostname == "" || r.Host.Architecture == "" {
		t.Fatalf("host metadata = %+v", r.Host)
	}
	if !containsString(logs, "scan summary:") {
		t.Errorf("summary log missing: %v", logs)
	}
	if os.Geteuid() != 0 && !containsString(logs, "warning: running as uid") {
		t.Errorf("non-root warning missing: %v", logs)
	}

	// NoDefaultExcludes walks everything; NoHostMetadata/RedactIPs trim the result.
	r, err = Target(context.Background(), "host", Options{HostRoot: root, NoDefaultExcludes: true, NoHostMetadata: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := packageNames(r)["example.com/container"]; !ok {
		t.Error("NoDefaultExcludes still skipped /var/lib/docker")
	}
	if r.OSName != "hostos" {
		t.Errorf("nested os-release overrode the root: %s", r.OSName)
	}
	if r.Host != nil {
		t.Error("NoHostMetadata left Host set")
	}
	r, err = Target(context.Background(), "host", Options{HostRoot: root, RedactIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Host == nil || r.Host.IPAddresses != nil {
		t.Errorf("RedactIPs: host = %+v", r.Host)
	}
}

func keysOf(m map[string]Package) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func containsString(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestTargetAllReturnsSingleResultForDirectories(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"go.mod": "module a\nrequire example.com/a v1.0.0\n"})
	results, err := TargetAll(context.Background(), root, Options{IncludeContainers: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].SourceType != "directory" || results[0].Scan == nil {
		t.Fatalf("results = %+v", results)
	}
	if results[0].Name != filepath.Base(root) || results[0].Source != root {
		t.Fatalf("name=%q source=%q", results[0].Name, results[0].Source)
	}
}

func TestRunningContainerParsing(t *testing.T) {
	// Exercise the name fallback logic through the same splitting the
	// docker ps output goes through.
	lines := "abc123def456789\tweb\n0123456789abcdef0123\t\n\nfeed\tone,two\n"
	var list []runningContainer
	for _, line := range strings.Split(lines, "\n") {
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
	if len(list) != 3 || list[0].name != "web" || list[1].name != "0123456789ab" || list[2].name != "one" {
		t.Fatalf("parsed = %+v", list)
	}
}

func TestFilterHostIPs(t *testing.T) {
	got := filterHostIPs([]interfaceAddrs{
		{Name: "lo", Addrs: []string{"127.0.0.1/8", "::1/128"}},
		{Name: "eth0", Addrs: []string{"192.168.1.10/24", "fe80::1/64", "2001:db8::1/64", "169.254.7.7/16"}},
		{Name: "docker0", Addrs: []string{"172.17.0.1/16"}},
		{Name: "br-1a2b3c", Addrs: []string{"172.18.0.1/16"}},
		{Name: "veth9f", Addrs: []string{"fe80::2/64"}},
		{Name: "virbr0", Addrs: []string{"192.168.122.1/24"}},
		{Name: "cni0", Addrs: []string{"10.244.0.1/24"}},
		{Name: "flannel.1", Addrs: []string{"10.244.0.0/32"}},
		{Name: "cali1234", Addrs: []string{"10.1.1.1/32"}},
		{Name: "lxcbr0", Addrs: []string{"10.0.3.1/24"}},
		{Name: "tap0", Addrs: []string{"10.9.9.1/24"}},
		{Name: "tun0", Addrs: []string{"10.8.0.2/24"}},
		{Name: "wlan0", Addrs: []string{"10.0.0.5/24", "0.0.0.0/0", "bad"}},
		{Name: "eth1", Addrs: []string{"10.0.0.5/24"}}, // duplicate
	})
	want := []string{"10.0.0.5", "192.168.1.10", "2001:db8::1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("filtered IPs = %v, want %v", got, want)
	}
}

func TestInContainerDetection(t *testing.T) {
	hostMounts := parseMountInfo(strings.NewReader(mountInfoFixture))
	if inContainerFrom(false, "0::/init.scope\n", hostMounts) {
		t.Error("plain host detected as container")
	}
	if !inContainerFrom(true, "", nil) {
		t.Error("/.dockerenv ignored")
	}
	for _, cg := range []string{
		"0::/system.slice/docker-abcdef.scope\n",
		"12:pids:/kubepods/burstable/pod1/abc\n",
		"0::/lxc/mycontainer\n",
		"0::/system.slice/containerd.service/x\n",
	} {
		if !inContainerFrom(false, cg, nil) {
			t.Errorf("cgroup %q not detected", cg)
		}
	}
	overlayRoot := []mountEntry{{MountPoint: "/", FSType: "overlay"}, {MountPoint: "/proc", FSType: "proc"}}
	if !inContainerFrom(false, "0::/\n", overlayRoot) {
		t.Error("overlay root not detected")
	}
}

func TestHostSourcesAllAbsolute(t *testing.T) {
	packages := []Package{{Source: "a/go.mod;b/go.mod;/c/go.mod"}, {}}
	makeHostPackageSourcesAbsolute(packages)
	if packages[0].Source != "/a/go.mod;/b/go.mod;/c/go.mod" || packages[1].Source != "" {
		t.Fatalf("unexpected sources: %+v", packages)
	}
}
