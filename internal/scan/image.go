package scan

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// maxImageLayers and maxIndexManifests bound how many layer or manifest
// references one image may declare. Docker itself stops at 127 layers; a
// manifest that repeats one blob hundreds of thousands of times would
// otherwise multiply the decompression work by the reference count.
const (
	maxImageLayers    = 1024
	maxIndexManifests = 1024
)

// maxGoBinary bounds how large an ELF executable may be before it is skipped
// for Go build-info extraction (the file is still hashed).
var maxGoBinary int64 = 64 << 20

// These limits are variables so serial tests can exercise the same boundaries
// with small inputs. Tests must restore them before returning.
var maxLayerBytes int64 = 16 << 30

// maxFileMetadata bounds image retention and walk metadata reads. The source
// readers retain maxMetadata as their production upper bound.
var maxFileMetadata int64 = maxMetadata

// Bound the zstd history window independently of the decompressed byte limits.
const maxZstdMemory = 256 << 20

func newZstdReader(rd io.Reader) (io.ReadCloser, error) {
	dec, err := zstd.NewReader(rd, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxZstdMemory))
	if err != nil {
		return nil, err
	}
	return dec.IOReadCloser(), nil
}

// contextReader bounds each read so cancellation is checked at least every MiB.
// It deliberately exposes no WriterTo/ReaderFrom fast path that bypasses Read.
type contextReader struct {
	ctx context.Context
	rd  io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > 1<<20 {
		p = p[:1<<20]
	}
	return r.rd.Read(p)
}

// decompressionReader rejects excess bytes, including padding after tar EOF.
type decompressionReader struct {
	rd        io.Reader
	remaining int64
}

func (r *decompressionReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var extra [1]byte
		n, err := r.rd.Read(extra[:])
		if n > 0 {
			return 0, errors.New("decompression limit exceeded")
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.rd.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func boundedArchiveReader(ctx context.Context, rd io.Reader) io.Reader {
	return &decompressionReader{rd: contextReader{ctx, rd}, remaining: maxLayerBytes}
}

func digestArchiveFile(ctx context.Context, file string) (string, error) {
	f, err := os.Open(file) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
	if err != nil {
		return "", err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	h := sha256.New()
	if _, err := io.Copy(h, contextReader{ctx, f}); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), ctx.Err()
}

const (
	mediaTypeOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mediaTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeOCILayer       = "application/vnd.oci.image.layer.v1.tar"
	mediaTypeOCILayerGzip   = "application/vnd.oci.image.layer.v1.tar+gzip"
	mediaTypeOCILayerZstd   = "application/vnd.oci.image.layer.v1.tar+zstd"
	mediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
)

// extractGoBinary is the hook used for ELF executables found inside archives.
// It is a variable so tests can observe the calls without a real Go binary.
var extractGoBinary = goBinaryPackages

// dockerRefPattern is a deliberately permissive check for docker image and
// container references; the real validation happens in the docker CLI. It
// mainly guarantees a reference can never start with "-" (flag injection).
var dockerRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)

func validateDockerRef(ref string) error {
	if strings.TrimSpace(ref) == "" {
		return errors.New("empty Docker reference")
	}
	if strings.HasPrefix(ref, "-") || !dockerRefPattern.MatchString(ref) {
		return fmt.Errorf("invalid reference %q", ref)
	}
	return nil
}

// runDocker runs the docker CLI, returning stdout. On failure the error
// carries the daemon's stderr (for example "No such container: x").
func runDocker(ctx context.Context, label string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- Fixed docker executable, separate argv, validated references after --; no shell is invoked.
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("docker %s: %w", label, ctx.Err())
	}
	msg := strings.TrimSpace(stderr.String())
	if msg == "" {
		msg = strings.TrimSpace(stdout.String())
	}
	if msg != "" {
		return nil, fmt.Errorf("docker %s: %w: %s", label, err, msg)
	}
	return nil, fmt.Errorf("docker %s: %w", label, err)
}

// runDockerToFile streams a docker command's stdout into path, which bscan
// owns and removes on failure. Using stdout instead of docker's -o flag
// avoids the ".tmp-<name>" sibling files that docker creates and does not
// clean up when the process is killed mid-export (cancellation, timeouts).
func runDockerToFile(ctx context.Context, label, path string, args ...string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- path is the bscan-created temporary archive from tempArchive, never user input.
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- Fixed docker executable, separate argv, validated references after --; no shell is invoked.
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = f, &stderr
	runErr := cmd.Run()
	closeErr := f.Close()
	if runErr == nil && closeErr == nil {
		return nil
	}
	_ = os.Remove(path)
	if ctx.Err() != nil {
		return fmt.Errorf("docker %s: %w", label, ctx.Err())
	}
	if runErr == nil {
		return fmt.Errorf("docker %s: %w", label, closeErr)
	}
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return fmt.Errorf("docker %s: %w: %s", label, runErr, msg)
	}
	return fmt.Errorf("docker %s: %w", label, runErr)
}

func tempArchive(pattern string) (string, error) {
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

type dockerImageInspect struct {
	ID           string   `json:"Id"`
	RepoTags     []string `json:"RepoTags"`
	RepoDigests  []string `json:"RepoDigests"`
	Created      string   `json:"Created"`
	Os           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
	Variant      string   `json:"Variant"`
}

func dockerInspectImage(ctx context.Context, ref string) (dockerImageInspect, error) {
	var out dockerImageInspect
	raw, err := runDocker(ctx, "image inspect", "image", "inspect", "--format", "{{json .}}", "--", ref)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &out); err != nil {
		return out, fmt.Errorf("docker image inspect: %w", err)
	}
	return out, nil
}

// mergeInspect fills image metadata from docker image inspect without
// overriding values already learned from the archive itself.
func mergeInspect(img *ImageMetadata, insp dockerImageInspect) {
	if img.ID == "" {
		img.ID = insp.ID
	}
	img.Tags = appendUnique(img.Tags, insp.RepoTags...)
	img.RepoDigests = appendUnique(img.RepoDigests, insp.RepoDigests...)
	if img.OS == "" {
		img.OS = insp.Os
	}
	if img.Architecture == "" {
		img.Architecture = insp.Architecture
	}
	if img.Variant == "" {
		img.Variant = insp.Variant
	}
	if img.Created == "" {
		img.Created = insp.Created
	}
}

func appendUnique(list []string, values ...string) []string {
	for _, v := range values {
		if v == "" {
			continue
		}
		dup := false
		for _, have := range list {
			if have == v {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, v)
		}
	}
	return list
}

// dockerImage scans docker://REF via docker image save.
func dockerImage(ctx context.Context, ref string, opts Options) (Result, error) {
	if err := validateDockerRef(ref); err != nil {
		return Result{}, err
	}
	tmpPath, err := tempArchive("bongsu-image-*.tar")
	if err != nil {
		return Result{}, err
	}
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.Remove(tmpPath)
	}()
	report(opts, "docker", "exporting image with docker image save", false)
	if err := runDockerToFile(ctx, "image save", tmpPath, "image", "save", "--", ref); err != nil {
		return Result{}, err
	}
	archiveOpts := opts
	// The temporary docker-save tar is an implementation detail, not a
	// stable source artifact, so its digest is neither computed nor recorded.
	archiveOpts.skipSourceHash = true
	r, err := archiveContext(ctx, tmpPath, archiveOpts)
	if err != nil {
		return Result{}, err
	}
	r.Name, r.Source, r.SourceType, r.SourceHash = ref, "docker://"+ref, "docker-image", ""
	if r.Image == nil {
		r.Image = &ImageMetadata{}
	}
	if insp, err := dockerInspectImage(ctx, ref); err == nil {
		mergeInspect(r.Image, insp)
	} else if ctx.Err() != nil {
		return Result{}, err
	} else {
		report(opts, "docker", "image inspect unavailable: "+err.Error(), true)
	}
	report(opts, "docker", fmt.Sprintf("image id=%s os=%s arch=%s tags=%s", r.Image.ID, r.Image.OS, r.Image.Architecture, strings.Join(r.Image.Tags, ",")), false)
	return r, nil
}

// dockerContainer scans container://REF via docker export, which flattens the
// container's current root filesystem including its writable layer.
func dockerContainer(ctx context.Context, ref string, opts Options) (Result, error) {
	if err := validateDockerRef(ref); err != nil {
		return Result{}, err
	}
	report(opts, "docker", "inspecting container", false)
	out, err := runDocker(ctx, "container inspect", "container", "inspect", "--format",
		"{{.Id}}|{{.Image}}|{{.Name}}|{{.State.Status}}", "--", ref)
	if err != nil {
		return Result{}, err
	}
	fields := strings.SplitN(strings.TrimSpace(string(out)), "|", 4)
	if len(fields) != 4 || fields[0] == "" {
		return Result{}, fmt.Errorf("docker container inspect: unexpected output %q", strings.TrimSpace(string(out)))
	}
	containerID, imageID, name, status := fields[0], fields[1], strings.TrimPrefix(fields[2], "/"), fields[3]
	report(opts, "docker", fmt.Sprintf("container %s (%s) image=%s status=%s", name, shortID(containerID), imageID, status), false)
	tmpPath, err := tempArchive("bongsu-container-*.tar")
	if err != nil {
		return Result{}, err
	}
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.Remove(tmpPath)
	}()
	report(opts, "docker", "exporting container root filesystem with docker export", false)
	if err := runDockerToFile(ctx, "export", tmpPath, "export", "--", containerID); err != nil {
		return Result{}, err
	}
	archiveOpts := opts
	archiveOpts.skipSourceHash = true
	r, err := rootfsArchive(ctx, tmpPath, archiveOpts)
	if err != nil {
		return Result{}, err
	}
	r.Name, r.Source, r.SourceType, r.SourceHash = ref, "container://"+ref, "container", ""
	image := &ImageMetadata{ID: imageID, ContainerID: containerID}
	if imageID != "" {
		if insp, err := dockerInspectImage(ctx, imageID); err == nil {
			mergeInspect(image, insp)
		} else if ctx.Err() != nil {
			return Result{}, err
		} else {
			report(opts, "docker", "image inspect unavailable: "+err.Error(), true)
		}
	}
	r.Image = image
	return r, nil
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// archive formats detected from magic bytes rather than file extensions.
type archiveFormat int

const (
	formatTar archiveFormat = iota
	formatGzip
	formatBzip2
	formatZstd
)

func detectFormat(head []byte) archiveFormat {
	switch {
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		// A tar header: its leading bytes are a file name, so they must not
		// be mistaken for a compression magic (e.g. an entry named "BZh...").
		return formatTar
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		return formatGzip
	case len(head) >= 4 && head[0] == 0x28 && head[1] == 0xb5 && head[2] == 0x2f && head[3] == 0xfd:
		return formatZstd
	case len(head) >= 4 && head[0]&0xf0 == 0x50 && head[1] == 0x2a && head[2] == 0x4d && head[3] == 0x18:
		// Zstandard skippable frames may precede the first compressed frame.
		return formatZstd
	case len(head) >= 3 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h':
		return formatBzip2
	}
	// An old v7 header or an empty archive of zero blocks: let archive/tar decide.
	return formatTar
}

func sniffFile(file string) (archiveFormat, error) {
	f, err := os.Open(file) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
	if err != nil {
		return formatTar, err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	head := make([]byte, 512)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return formatTar, err
	}
	return detectFormat(head[:n]), nil
}

// decompress wraps f according to format. Callers close both the reader and f.
func decompress(format archiveFormat, f *os.File, file string) (io.ReadCloser, error) {
	switch format {
	case formatGzip:
		gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("archive %s: %w", file, err)
		}
		return gz, nil
	case formatBzip2:
		return io.NopCloser(bzip2.NewReader(bufio.NewReaderSize(f, 1<<20))), nil
	case formatZstd:
		rd, err := newZstdReader(bufio.NewReaderSize(f, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("archive %s: zstd: %w", file, err)
		}
		return rd, nil
	}
	return f, nil
}

// outerEntry locates one regular file inside the outer archive. Seekable
// (uncompressed) archives are read in place through offset/size; compressed
// archives are buffered in memory or, for large blobs, in a temp file.
type outerEntry struct {
	Size   int64
	offset int64
	data   []byte
	temp   string
	entry  int // tar header ordinal, also preserved by hard links
}

type outerArchive struct {
	path             string
	file             *os.File // original uncompressed archive
	spool            *os.File // decompressed outer stream, written only during indexing
	seekable         bool
	entries          map[string]outerEntry
	names            []string // every entry name, including directories and links
	tempDir          string
	ctx              context.Context
	format           archiveFormat
	retained, budget int64
}

func (a *outerArchive) Close() {
	if a.spool != nil {
		_ = a.spool.Close()
		a.spool = nil
	}
	if a.file != nil {
		_ = a.file.Close()
		a.file = nil
	}
	if a.tempDir != "" {
		_ = os.RemoveAll(a.tempDir)
		a.tempDir = ""
	}
}

func (a *outerArchive) has(name string) bool {
	_, ok := a.entries[name]
	return ok
}

// open returns a reader over the entry and a function to release it.
func (a *outerArchive) open(name string) (io.Reader, func(), error) {
	e, ok := a.entries[name]
	if !ok {
		return nil, nil, fmt.Errorf("entry %q missing", name)
	}
	if a.file == nil && e.temp == "" && e.data == nil && a.tempDir != "" {
		if err := a.retain([]string{name}); err != nil {
			return nil, nil, err
		}
		e = a.entries[name]
	}
	switch {
	case a.file != nil:
		return io.NewSectionReader(a.file, e.offset, e.Size), func() {}, nil
	case e.temp != "":
		if a.spool != nil && e.temp == a.spool.Name() {
			return io.NewSectionReader(a.spool, e.offset, e.Size), func() {}, nil
		}
		f, err := os.Open(e.temp)
		if err != nil {
			return nil, nil, err
		}
		return f, func() { _ = f.Close() }, nil
	case e.data != nil:
		return bytes.NewReader(e.data), func() {}, nil
	}
	return nil, nil, fmt.Errorf("entry %q has no buffered content", name)
}

// retain caches selected metadata in memory within the retention budget. Larger
// entries reuse their range in the spool written during indexing; no request
// ever reopens or decompresses the original outer archive.
func (a *outerArchive) retain(names []string) error {
	if a.seekable {
		return nil
	}
	wanted := map[int][]string{}
	for _, name := range names {
		name = clean(name)
		e, ok := a.entries[name]
		if ok && e.data == nil && e.temp == "" {
			wanted[e.entry] = append(wanted[e.entry], name)
		}
	}
	ordinals := make([]int, 0, len(wanted))
	for ordinal := range wanted {
		ordinals = append(ordinals, ordinal)
	}
	sort.Ints(ordinals)
	for _, ordinal := range ordinals {
		names := wanted[ordinal]
		if a.spool == nil {
			return errors.New("outer archive has no decompressed spool")
		}
		e := a.entries[names[0]]
		if e.Size <= maxFileMetadata && e.Size <= a.budget-a.retained {
			data := make([]byte, e.Size)
			if _, err := io.ReadFull(contextReader{a.ctx, io.NewSectionReader(a.spool, e.offset, e.Size)}, data); err != nil {
				return err
			}
			e.data = data
			a.retained += int64(len(data))
		} else {
			e.temp = a.spool.Name()
		}
		for _, name := range names {
			a.entries[name] = e
		}
	}
	return a.ctx.Err()
}

// bytes returns the content of a small metadata entry.
func (a *outerArchive) bytes(name string) ([]byte, error) {
	e, ok := a.entries[name]
	if !ok {
		return nil, fmt.Errorf("entry %q missing", name)
	}
	if e.Size > maxFileMetadata {
		return nil, fmt.Errorf("entry %q too large (%d bytes)", name, e.Size)
	}
	if e.data != nil {
		return e.data, nil
	}
	rd, done, err := a.open(name)
	if err != nil {
		return nil, err
	}
	defer done()
	if data := a.entries[name].data; data != nil {
		return data, nil
	}
	return io.ReadAll(rd)
}

func isRegular(h *tar.Header) bool {
	if h.Typeflag == tar.TypeLink {
		return false
	}
	return h.Typeflag == tar.TypeReg || h.FileInfo().Mode().IsRegular()
}

func unsafePath(name string) bool {
	return name == "" || name == ".." || strings.HasPrefix(name, "../")
}

// indexOuter walks the outer archive's headers. For uncompressed archives it
// only records offsets (archive/tar seeks past the data), so indexing a
// multi-gigabyte docker save costs a few header reads. For compressed
// archives, one bounded pass spills the stream and records offsets into it.
// Entries can precede their manifest, so the spool also stages entries whose
// references are not yet known. MaxTotalBytes overrides the cumulative outer
// decompression limit (default 16 GiB), as well as the metadata retention budget.
// All subsequent reads use cached offsets and consume no decompression budget.
func indexOuter(ctx context.Context, file string, format archiveFormat, buffer bool, opts Options) (*outerArchive, error) {
	f, err := os.Open(file) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
	if err != nil {
		return nil, err
	}
	a := &outerArchive{path: file, entries: map[string]outerEntry{}, ctx: ctx, format: format, budget: opts.MaxTotalBytes}
	if a.budget <= 0 {
		a.budget = defaultMaxTotalBytes
	}
	stream, err := decompress(format, f, file)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	var rd io.Reader = stream
	if format == formatTar {
		a.file, a.seekable = f, true
	} else {
		defer func() {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = f.Close()
		}()
		defer func() {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = stream.Close()
		}()
		limit := opts.MaxTotalBytes
		if limit <= 0 {
			limit = maxLayerBytes
		}
		rd = &decompressionReader{rd: contextReader{ctx, rd}, remaining: limit}
	}
	fail := func(err error) (*outerArchive, error) {
		a.Close()
		return nil, err
	}
	if !a.seekable {
		a.tempDir, err = os.MkdirTemp("", "bongsu-archive-*")
		if err != nil {
			return fail(err)
		}
		a.spool, err = os.CreateTemp(a.tempDir, "outer-*.tar")
		if err != nil {
			return fail(err)
		}
		rd = io.TeeReader(rd, a.spool)
	}
	tr := tar.NewReader(rd)
	entry := 0
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(fmt.Errorf("archive %s: %w", file, err))
		}
		if h.Size > maxLayerBytes {
			return fail(fmt.Errorf("archive entry %s: decompression limit exceeded", h.Name))
		}
		entry++
		name := clean(h.Name)
		if unsafePath(name) {
			continue
		}
		a.names = append(a.names, name)
		switch {
		case h.Typeflag == tar.TypeLink:
			if e, ok := a.entries[clean(h.Linkname)]; ok {
				a.entries[name] = e
			}
		case isRegular(h):
			if !buffer {
				report(opts, "archive-entry", fmt.Sprintf("%s (%d bytes)", name, h.Size), true)
			}
			e := outerEntry{Size: h.Size, entry: entry}
			backing := a.file
			if backing == nil {
				backing = a.spool
			}
			off, err := backing.Seek(0, io.SeekCurrent)
			if err != nil {
				return fail(err)
			}
			e.offset = off
			a.entries[name] = e
		}
	}
	if !a.seekable {
		// Tar EOF can precede padding or another compressed frame/member. Count and check
		// the entire decompressed stream, including its checksum and tail.
		if _, err := io.Copy(io.Discard, rd); err != nil {
			return fail(fmt.Errorf("archive %s: %w", file, err))
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return a, nil
}

// rootfsDirs are the top-level directories whose presence marks a plain root
// filesystem archive (docker export, debootstrap tarballs, ...).
var rootfsDirs = []string{"etc", "usr", "var", "lib", "lib64", "bin", "sbin", "opt", "home", "root", "srv", "boot"}

func rootfsTrace(name string) bool {
	for _, d := range rootfsDirs {
		if name == d || strings.HasPrefix(name, d+"/") {
			return true
		}
	}
	return false
}

// classifyOuter decides how the archive should be interpreted:
// "docker-archive", "oci-archive", "archive" (plain root filesystem or a
// tree with package metadata), or "" when nothing recognizable was found.
func classifyOuter(a *outerArchive) string {
	if a.has("manifest.json") {
		return "docker-archive"
	}
	if a.has("index.json") {
		return "oci-archive"
	}
	for _, name := range a.names {
		if rootfsTrace(name) || interestingPackageMetadata(name) {
			return "archive"
		}
	}
	return ""
}

// archiveContext is the implementation behind Archive and Target for local
// archives, docker save output, and docker export output.
func archiveContext(ctx context.Context, file string, opts Options) (Result, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	format, err := sniffFile(file)
	if err != nil {
		return Result{}, err
	}
	digest := ""
	if !opts.skipSourceHash {
		report(opts, "hash", "calculating source archive SHA-256", false)
		if digest, err = digestArchiveFile(ctx, file); err != nil {
			return Result{}, err
		}
	}
	report(opts, "archive", "indexing tar entries", false)
	outer, err := indexOuter(ctx, file, format, false, opts)
	if err != nil {
		return Result{}, err
	}
	defer outer.Close()
	kind := classifyOuter(outer)
	u := newUnpacker(ctx, opts)
	defer u.Close()
	var layers []File
	var image *ImageMetadata
	switch kind {
	case "docker-archive", "oci-archive":
		if kind == "docker-archive" {
			layers, image, err = u.unpackDockerArchive(outer)
		} else {
			layers, image, err = u.unpackOCIArchive(outer)
		}
		if err != nil {
			return Result{}, err
		}
	case "archive":
		report(opts, "archive", "plain root filesystem archive detected", false)
		rootFile, rootFormat := file, format
		if outer.spool != nil {
			rootFile, rootFormat = outer.spool.Name(), formatTar
		}
		if err := applyRootfsFile(u, rootFile, rootFormat); err != nil {
			return Result{}, err
		}
	default:
		return Result{}, fmt.Errorf("archive %s: no image manifest or root filesystem found", file)
	}
	if err := u.finish(); err != nil {
		return Result{}, err
	}
	report(opts, "archive", fmt.Sprintf("%s ready: %d files, %d layers", kind, len(u.fs), len(layers)), false)
	r := assembleRPMResult(filepath.Base(file), file, kind, u.fs, layers, image, u.extraPackages(), opts.Now, opts, u.rpmFiles, u.kinds)
	u.applyBinaryMetadata(&r)
	r.SourceHash = digest
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return r, nil
}

// rootfsArchive scans a tar known to be a flattened root filesystem (docker
// export) without requiring recognizable directory names.
func rootfsArchive(ctx context.Context, file string, opts Options) (Result, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	format, err := sniffFile(file)
	if err != nil {
		return Result{}, err
	}
	digest := ""
	if !opts.skipSourceHash {
		if digest, err = digestArchiveFile(ctx, file); err != nil {
			return Result{}, err
		}
	}
	u := newUnpacker(ctx, opts)
	defer u.Close()
	report(opts, "archive", "indexing root filesystem tar", false)
	if err := applyRootfsFile(u, file, format); err != nil {
		return Result{}, err
	}
	if err := u.finish(); err != nil {
		return Result{}, err
	}
	report(opts, "archive", fmt.Sprintf("root filesystem ready: %d files", len(u.fs)), false)
	r := assembleRPMResult(filepath.Base(file), file, "archive", u.fs, nil, nil, u.extraPackages(), opts.Now, opts, u.rpmFiles, u.kinds)
	u.applyBinaryMetadata(&r)
	r.SourceHash = digest
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return r, nil
}

func applyRootfsFile(u *unpacker, file string, format archiveFormat) error {
	f, err := os.Open(file) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	stream, err := decompress(format, f, file)
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = stream.Close()
	}()
	rd := boundedArchiveReader(u.ctx, stream)
	if err := u.applyTarSource(rd, "", func() (io.Reader, func(), error) {
		f, err := os.Open(file) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
		if err != nil {
			return nil, nil, err
		}
		r, err := decompress(format, f, file)
		if err != nil {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = f.Close()
			return nil, nil, err
		}
		return r, func() { // Cleanup only; read errors or the primary operation error are handled separately.
			_ = r.Close() // Cleanup only; read errors or the primary operation error are handled separately.
			_ = f.Close()
		}, nil
	}); err != nil {
		return fmt.Errorf("archive %s: %w", file, err)
	}
	if _, err := io.Copy(io.Discard, rd); err != nil {
		return fmt.Errorf("archive %s: %w", file, err)
	}
	return u.ctx.Err()
}

func assembleRPMResult(name, source, kind string, fs store, layers []File, image *ImageMetadata, extra []Package, now time.Time, opts Options, rpmFiles map[string]string, directoryKinds ...map[string]byte) Result {
	files := make([]File, 0, len(fs))
	for _, f := range fs {
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	r := Result{Name: name, Source: source, SourceType: kind, ScannedAt: now.UTC(), Files: files, Layers: layers, Image: image}
	report(opts, "catalog", fmt.Sprintf("cataloging package metadata from %d files (+%d packages from binaries)", len(files), len(extra)), false)
	var c cataloger
	c.includeDeclared = opts.IncludeDeclared
	// Use the final merged directory view, including empty directories and
	// whiteouts, to select declarations backed by nested node_modules.
	for _, kinds := range directoryKinds {
		for name, kind := range kinds {
			if kind == tar.TypeDir && path.Base(name) == "node_modules" {
				c.observePath(name + "/package.json")
			}
		}
	}
	var meta ScanMetadata
	for _, f := range files {
		switch {
		case diskMetadataLimit(f.Path) != 0 && f.Size > diskMetadataLimit(f.Path):
			meta.MetadataSkipped++
			report(opts, "catalog", f.Path+": metadata size limit", true)
		case isJavaArchive(f.Path):
			skipped, failures := scanJavaFile(f, rpmFiles[f.Path], c.addPackage)
			meta.MetadataSkipped += skipped
			meta.SkippedErrors += failures
		case isRPMDatabase(f.Path) && rpmFiles[f.Path] != "":
			count := c.addRPMFile(f, rpmFiles[f.Path])
			meta.SkippedErrors += count
			if count != 0 {
				report(opts, "catalog", fmt.Sprintf("%s: %d RPM database parse errors", f.Path, count), true)
			}
		default:
			c.addFile(f)
		}
	}
	meta.MetadataSkipped += c.metadataSkipped
	c.addPackages(extra)
	r.Packages, r.OS = c.finish()
	if meta.MetadataSkipped != 0 || meta.SkippedErrors != 0 {
		meta.Partial = true
	}
	reportDeclaredPolicy(opts, &meta, c.declaredSkipped)
	if meta.Partial || meta.DeclaredSkipped != 0 {
		r.Scan = &meta
	}
	if r.OS != nil {
		r.OSName, r.OSVersion = r.OS.ID, r.OS.VersionID
	}
	report(opts, "catalog", fmt.Sprintf("catalog complete: %d packages; os=%s %s", len(r.Packages), r.OSName, r.OSVersion), false)
	for _, p := range r.Packages {
		report(opts, "package", fmt.Sprintf("%s %s (%s)", p.Name, p.Version, p.Type), true)
	}
	return r
}

// unpacker merges layer tars into one filesystem view following the OCI
// layer specification (whiteouts, opaque directories, hard links).
type unpacker struct {
	ctx          context.Context
	opts         Options
	fs           store
	symlinks     map[string]symlinkRec
	binaries     map[string][]Package // Go build-info packages keyed by binary path
	binaryBudget binaryProbeBudget
	kinds        map[string]byte
	// children indexes kinds by parent directory ("" for the root) so
	// whiteouts remove a subtree in time proportional to its size rather
	// than to the whole merged filesystem.
	children map[string]map[string]struct{}
	contents map[string]archiveContent
	sources  []archiveSource
	rpmFiles map[string]string // final filesystem paths to disk-backed RPM/Java archive contents
	tempDir  string
}

// archiveContent identifies the original tar entry, so hard links retain the
// original bytes even if their target path is subsequently replaced.
type archiveContent struct{ source, entry int }
type archiveSource func() (io.Reader, func(), error)

type symlinkRec struct {
	target string
	layer  string
}

func newUnpacker(ctx context.Context, opts Options) *unpacker {
	return &unpacker{ctx: ctx, opts: opts, fs: store{}, kinds: map[string]byte{}, children: map[string]map[string]struct{}{}, symlinks: map[string]symlinkRec{}, binaries: map[string][]Package{}, contents: map[string]archiveContent{}, rpmFiles: map[string]string{}}
}

// parentDir is path.Dir with the root spelled "" like every other root-relative name.
func parentDir(name string) string {
	if dir := path.Dir(name); dir != "." && dir != "/" {
		return dir
	}
	return ""
}

// setKind records name in kinds and in its parent's child index.
func (u *unpacker) setKind(name string, kind byte) {
	u.kinds[name] = kind
	dir := parentDir(name)
	set := u.children[dir]
	if set == nil {
		set = map[string]struct{}{}
		u.children[dir] = set
	}
	set[name] = struct{}{}
}

// Close releases RPM/Java archive contents on success, error, and cancellation.
func (u *unpacker) Close() {
	if u.tempDir != "" {
		_ = os.RemoveAll(u.tempDir)
		u.tempDir = ""
	}
}

// spoolRPM copies RPM databases and Java archives through the bounded reader;
// no contents byte slice
// is retained. The unpacker owns successful copies until cataloging finishes.
func (u *unpacker) spoolRPM(r io.Reader, size int64) (string, error) {
	if u.tempDir == "" {
		dir, err := os.MkdirTemp("", "bongsu-image-rpm-*")
		if err != nil {
			return "", err
		}
		u.tempDir = dir
	}
	tmp, err := os.CreateTemp(u.tempDir, "rpm-*")
	if err != nil {
		return "", err
	}
	_, copyErr := io.CopyN(tmp, contextReader{u.ctx, r}, size)
	err = errors.Join(copyErr, tmp.Close(), u.ctx.Err())
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// remove drops name unless it was created by the layer currently being
// applied: whiteouts only ever hide content from lower layers.
func (u *unpacker) remove(name string, added map[string]bool) {
	if added[name] {
		return
	}
	if diskPath := u.rpmFiles[name]; diskPath != "" {
		delete(u.rpmFiles, name)
		referenced := false
		for _, other := range u.rpmFiles {
			if other == diskPath {
				referenced = true
				break
			}
		}
		if !referenced {
			_ = os.Remove(diskPath)
		}
	}
	delete(u.kinds, name)
	if dir := parentDir(name); u.children[dir] != nil {
		delete(u.children[dir], name)
		if len(u.children[dir]) == 0 {
			delete(u.children, dir)
		}
	}
	delete(u.fs, name)
	delete(u.contents, name)
	delete(u.symlinks, name)
	delete(u.binaries, name)
}

// removeUnder hides everything below prefix ("" means the whole tree). Every
// retained path is registered in kinds together with its implicit parents,
// so the child index reaches the entire subtree; entries added by the
// current layer are kept but still descended into.
func (u *unpacker) removeUnder(prefix string, added map[string]bool) {
	var walk func(dir string)
	walk = func(dir string) {
		for child := range u.children[dir] {
			walk(child)
			u.remove(child, added)
		}
	}
	walk(strings.TrimSuffix(prefix, "/"))
}

func (u *unpacker) applyTarSource(rd io.Reader, layer string, reopen archiveSource) error {
	source := len(u.sources)
	u.sources = append(u.sources, reopen)
	entry := 0
	tr := tar.NewReader(boundedArchiveReader(u.ctx, rd))
	added := map[string]bool{}
	for {
		if err := u.ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			return u.ctx.Err()
		}
		if err != nil {
			return err
		}
		entry++
		name := clean(h.Name)
		if unsafePath(name) {
			continue
		}
		base := path.Base(name)
		if strings.HasPrefix(base, ".wh.") {
			dir := path.Dir(name)
			if base == ".wh..wh..opq" {
				prefix := ""
				if dir != "." {
					prefix = dir + "/"
				}
				u.removeUnder(prefix, added)
			} else {
				victim := path.Join(dir, strings.TrimPrefix(base, ".wh."))
				u.remove(victim, added)
				u.removeUnder(victim+"/", added)
			}
			continue
		}
		// Track implicit parents too, without rescanning the whole filesystem
		// for every regular entry. A parent may itself replace a lower file.
		for parent := path.Dir(name); parent != "." && parent != "/"; parent = path.Dir(parent) {
			if u.kinds[parent] == tar.TypeDir {
				break
			}
			u.remove(parent, nil)
			u.setKind(parent, tar.TypeDir)
			added[parent] = true
		}
		// A non-directory entry replaces an entire directory tree.
		if h.Typeflag == tar.TypeDir {
			if u.kinds[name] != tar.TypeDir {
				u.remove(name, nil)
			}
			u.setKind(name, tar.TypeDir)
			added[name] = true
		} else {
			if u.kinds[name] == tar.TypeDir {
				u.removeUnder(name+"/", nil)
			}
			u.remove(name, nil)
			u.setKind(name, h.Typeflag)
			added[name] = true
		}
		switch {
		case h.Typeflag == tar.TypeLink:
			target := clean(h.Linkname)
			rec, ok := u.fs[target]
			if !ok {
				continue
			}
			rec.Path, rec.Layer = name, layer
			u.fs[name] = rec
			if diskPath := u.rpmFiles[target]; diskPath != "" {
				u.rpmFiles[name] = diskPath
			}
			content, hasContent := u.contents[target]
			delete(u.contents, name)
			if hasContent {
				u.contents[name] = content
			}
			if pkgs, ok := u.binaries[target]; ok {
				copies := append([]Package(nil), pkgs...)
				for i := range copies {
					copies[i].Source, copies[i].Layer = name, layer
				}
				u.binaries[name] = copies
			} else {
				delete(u.binaries, name)
			}
			delete(u.symlinks, name)
			added[name] = true
		case h.Typeflag == tar.TypeSymlink:
			delete(u.fs, name)
			delete(u.contents, name)
			delete(u.binaries, name)
			delete(u.symlinks, name)
			if target := resolveLink(name, h.Linkname); target != "" {
				u.symlinks[name] = symlinkRec{target: target, layer: layer}
				added[name] = true
			}
		case isRegular(h):
			delete(u.contents, name)
			delete(u.binaries, name)
			delete(u.symlinks, name)
			rec, err := u.readEntry(name, tr, h, layer)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			u.fs[name] = rec
			if rec.Data == nil && u.rpmFiles[name] == "" && h.Size <= max(maxRPMDatabase, maxJavaArchive) && reopen != nil {
				u.contents[name] = archiveContent{source: source, entry: entry}
			}
			added[name] = true
		}
	}
}

// resolveLink turns a symlink target into a root-relative path, or "" when
// it escapes the archive root.
func resolveLink(name, link string) string {
	link = strings.ReplaceAll(link, "\\", "/")
	var target string
	if strings.HasPrefix(link, "/") {
		target = clean(link)
	} else {
		target = clean(path.Join(path.Dir(name), link))
	}
	if unsafePath(target) {
		return ""
	}
	return target
}

func isELF(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

// goBinaryCandidate reports whether a regular file should be probed for an
// ELF header: executable bit set or no file extension, and not too large.
func goBinaryCandidate(name string, mode int64, size int64) bool {
	if size < 4 || size > maxGoBinary {
		return false
	}
	return mode&0o111 != 0 || path.Ext(path.Base(name)) == "" || runtimeLibraryCandidate(name)
}

// readEntry hashes one regular file. Metadata files selected by interesting
// keep their content; ELF executables are handed to the Go build-info
// extractor and discarded afterwards.
func (u *unpacker) readEntry(name string, r io.Reader, h *tar.Header, layer string) (File, error) {
	size := h.Size
	if size > maxLayerBytes {
		return File{}, errors.New("decompression limit exceeded")
	}
	r = contextReader{u.ctx, r}
	sum := sha256.New()
	diskLimit := diskMetadataLimit(name)
	keep := size <= maxFileMetadata && interestingPackageMetadata(name) && diskLimit == 0
	// Larger archive binaries are only hashed: retaining their full contents
	// would exceed the per-file 8 MiB probing budget.
	probe := !u.opts.SkipBinaries && size <= maxBinaryScanBytes && goBinaryCandidate(name, h.Mode, size)
	var data []byte
	switch {
	case diskLimit != 0 && size <= diskLimit:
		diskPath, err := u.spoolRPM(io.TeeReader(r, sum), size)
		if err != nil {
			return File{}, err
		}
		u.rpmFiles[name] = diskPath
	case keep:
		data = make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil {
			return File{}, err
		}
		sum.Write(data)
		if probe && isNativeBinary(data) && u.binaryBudget.take() {
			u.recordBinary(name, layer, data)
		}
	case probe:
		head := make([]byte, 4)
		n, err := io.ReadFull(r, head)
		if err != nil {
			return File{}, err
		}
		sum.Write(head[:n])
		if isNativeBinary(head) && u.binaryBudget.take() {
			buf := make([]byte, size)
			copy(buf, head)
			if _, err := io.ReadFull(r, buf[4:]); err != nil {
				return File{}, err
			}
			sum.Write(buf[4:])
			u.recordBinary(name, layer, buf)
		} else if _, err := io.Copy(sum, r); err != nil {
			return File{}, err
		}
	default:
		if _, err := io.Copy(sum, r); err != nil {
			return File{}, err
		}
	}
	if err := u.ctx.Err(); err != nil {
		return File{}, err
	}
	return File{Path: name, Size: size, SHA256: hex.EncodeToString(sum.Sum(nil)), Data: data, Layer: layer}, nil
}

// applyBinaryMetadata preserves catalog completeness information while adding
// the same probe-limit signal used by directory scans.
func (u *unpacker) applyBinaryMetadata(r *Result) {
	if u.binaryBudget.count.Load() <= maxClassifiedBinaries {
		return
	}
	if r.Scan == nil {
		r.Scan = &ScanMetadata{}
	}
	r.Scan.Partial = true
	r.Scan.LimitReached = joinLimit(r.Scan.LimitReached, "max-binaries")
}

// The caller reserves a probe before allocating the binary buffer.
func (u *unpacker) recordBinary(name, layer string, data []byte) {
	r := boundedBinaryReader(bytes.NewReader(data))
	pkgs := extractGoBinary(r, int64(len(data)), name, layer)
	pkgs = append(pkgs, binaryPackages(r, int64(len(data)), name, layer, u.opts)...)
	if len(pkgs) == 0 {
		return
	}
	u.binaries[name] = pkgs
	report(u.opts, "binary", fmt.Sprintf("%s: %d packages from binary", name, len(pkgs)), true)
}

// finish resolves symlinked metadata files (etc/os-release ->
// ../usr/lib/os-release) once all layers are merged so tar ordering and
// cross-layer targets do not matter.
func (u *unpacker) finish() error {
	for name, link := range u.symlinks {
		if _, exists := u.fs[name]; exists || !interestingPackageMetadata(name) {
			continue
		}
		target := link.target
		for depth := 0; depth < 8; depth++ {
			if rec, ok := u.fs[target]; ok {
				rec.Path, rec.Layer = name, link.layer
				u.fs[name] = rec
				if diskPath := u.rpmFiles[target]; diskPath != "" {
					u.rpmFiles[name] = diskPath
				}
				if content, ok := u.contents[target]; ok {
					u.contents[name] = content
				}
				break
			}
			next, ok := u.symlinks[target]
			if !ok {
				break
			}
			target = next.target
		}
	}
	return u.restoreMetadataLinks()
}

// restoreMetadataLinks rereads only sources containing final metadata aliases.
// Discarded files stay out of memory; each selected entry is bounded by
// metadataFileLimit, and aliases share their contents.
func (u *unpacker) restoreMetadataLinks() error {
	// Aliases may cross between an in-memory metadata file and a disk-backed
	// RPM database or Java archive. Preserve the destination's retention policy.
	for name, rec := range u.fs {
		if !interestingPackageMetadata(name) {
			continue
		}
		if diskMetadataLimit(name) != 0 && rec.Data != nil && rec.Size <= diskMetadataLimit(name) {
			diskPath, err := u.spoolRPM(bytes.NewReader(rec.Data), rec.Size)
			if err != nil {
				return err
			}
			u.rpmFiles[name] = diskPath
			rec.Data = nil
			u.fs[name] = rec
		} else if diskMetadataLimit(name) == 0 && rec.Data == nil && rec.Size <= maxFileMetadata && u.rpmFiles[name] != "" {
			data, err := os.ReadFile(u.rpmFiles[name])
			if err != nil {
				return err
			}
			rec.Data = data
			u.fs[name] = rec
		}
	}
	wanted := map[int]map[int][]string{}
	for name, content := range u.contents {
		if !interestingPackageMetadata(name) || u.fs[name].Size > metadataFileLimit(name) {
			continue
		}
		if wanted[content.source] == nil {
			wanted[content.source] = map[int][]string{}
		}
		wanted[content.source][content.entry] = append(wanted[content.source][content.entry], name)
	}
	for source, entries := range wanted {
		if err := u.restoreSource(u.sources[source], entries); err != nil {
			return fmt.Errorf("restore linked metadata: %w", err)
		}
	}
	return nil
}

func (u *unpacker) restoreSource(reopen archiveSource, entries map[int][]string) error {
	rd, done, err := reopen()
	if err != nil {
		return err
	}
	defer done()
	tr := tar.NewReader(boundedArchiveReader(u.ctx, rd))
	for entry := 1; len(entries) > 0; entry++ {
		if err := u.ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err != nil {
			return err
		}
		names := entries[entry]
		if len(names) == 0 {
			continue
		}
		if !isRegular(h) || h.Size < 0 || h.Size > max(maxRPMDatabase, maxJavaArchive) {
			return fmt.Errorf("source entry for %s changed", names[0])
		}
		hasRPM, hasMetadata := false, false
		for _, name := range names {
			if diskMetadataLimit(name) != 0 {
				hasRPM = true
			} else {
				hasMetadata = true
			}
		}
		var data []byte
		var diskPath string
		sum := sha256.New()
		if hasRPM {
			diskPath, err = u.spoolRPM(io.TeeReader(tr, sum), h.Size)
			if err != nil {
				return err
			}
			if hasMetadata {
				if h.Size > maxFileMetadata {
					return fmt.Errorf("source entry for %s changed", names[0])
				}
				data, err = os.ReadFile(diskPath) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
				if err != nil {
					return err
				}
			}
		} else {
			if h.Size > maxFileMetadata {
				return fmt.Errorf("source entry for %s changed", names[0])
			}
			data = make([]byte, h.Size)
			if _, err := io.ReadFull(tr, data); err != nil {
				return err
			}
			sum.Write(data)
		}
		for _, name := range names {
			rec := u.fs[name]
			if rec.Size != h.Size || rec.SHA256 != hex.EncodeToString(sum.Sum(nil)) {
				return fmt.Errorf("source content for %s changed", name)
			}
			if diskMetadataLimit(name) != 0 {
				u.rpmFiles[name] = diskPath
				rec.Data = nil
			} else {
				rec.Data = data
			}
			u.fs[name] = rec
		}
		delete(entries, entry)
	}
	return nil
}

// layerSource reopens the already indexed blob, including disk-backed blobs
// from compressed outer archives. It creates no additional temporary files.
func layerSource(a *outerArchive, name string) archiveSource {
	return func() (io.Reader, func(), error) {
		rd, done, err := a.open(name)
		if err != nil {
			return nil, nil, err
		}
		br := bufio.NewReader(rd)
		head, err := br.Peek(512)
		if err != nil && err != io.EOF {
			done()
			return nil, nil, err
		}
		switch detectFormat(head) {
		case formatGzip:
			gz, err := gzip.NewReader(br)
			if err != nil {
				done()
				return nil, nil, err
			}
			return gz, func() { // Cleanup only; read errors or the primary operation error are handled separately.
				_ = gz.Close()
				done()
			}, nil
		case formatZstd:
			zr, err := newZstdReader(br)
			if err != nil {
				done()
				return nil, nil, err
			}
			return zr, func() { // Cleanup only; read errors or the primary operation error are handled separately.
				_ = zr.Close()
				done()
			}, nil
		}
		return br, done, nil
	}
}

func (u *unpacker) extraPackages() []Package {
	names := make([]string, 0, len(u.binaries))
	for name := range u.binaries {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Package
	for _, name := range names {
		out = append(out, u.binaries[name]...)
	}
	return out
}

// layerCheck carries what the manifest/config declare about a layer.
type layerCheck struct {
	name      string // label for progress and errors (path or digest)
	digest    string // declared blob digest, "" when unknown
	diffID    string // declared uncompressed tar digest, "" when unknown
	mediaType string
	reopen    archiveSource
}

// applyLayer merges one layer blob, computing the blob digest and the
// diff_id in a single pass and comparing both with the declared values.
func (u *unpacker) applyLayer(rd io.Reader, size int64, want layerCheck) (LayerInfo, error) {
	blobHash := sha256.New()
	br := bufio.NewReaderSize(io.TeeReader(contextReader{u.ctx, rd}, blobHash), 1<<20)
	head, err := br.Peek(512)
	if err != nil && err != io.EOF {
		return LayerInfo{}, fmt.Errorf("layer %s: %w", want.name, err)
	}
	var body io.Reader = br
	var diffHash hash.Hash
	mediaType := want.mediaType
	format := detectFormat(head)
	if strings.Contains(mediaType, "zstd") {
		format = formatZstd
	}
	switch format {
	case formatGzip:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return LayerInfo{}, fmt.Errorf("layer %s: %w", want.name, err)
		}
		defer func() {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = gz.Close()
		}()
		diffHash = sha256.New()
		body = io.TeeReader(gz, diffHash)
		if mediaType == "" {
			mediaType = mediaTypeOCILayerGzip
		}
	case formatZstd:
		zr, err := newZstdReader(br)
		if err != nil {
			return LayerInfo{}, fmt.Errorf("layer %s: zstd: %w", want.name, err)
		}
		defer func() {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = zr.Close()
		}()
		diffHash = sha256.New()
		body = io.TeeReader(zr, diffHash)
		if mediaType == "" {
			mediaType = mediaTypeOCILayerZstd
		}
	case formatBzip2:
		return LayerInfo{}, fmt.Errorf("layer %s: bzip2-compressed layers are not supported", want.name)
	default:
		if mediaType == "" {
			mediaType = mediaTypeOCILayer
		}
	}
	body = boundedArchiveReader(u.ctx, body)
	if err := u.applyTarSource(body, want.name, want.reopen); err != nil {
		return LayerInfo{}, fmt.Errorf("layer %s: %w", want.name, err)
	}
	// Drain trailing padding so both digests cover the entire blob.
	if _, err := io.Copy(io.Discard, body); err != nil {
		return LayerInfo{}, fmt.Errorf("layer %s: %w", want.name, err)
	}
	if _, err := io.Copy(io.Discard, contextReader{u.ctx, br}); err != nil {
		return LayerInfo{}, fmt.Errorf("layer %s: %w", want.name, err)
	}
	info := LayerInfo{
		Digest:    "sha256:" + hex.EncodeToString(blobHash.Sum(nil)),
		Size:      size,
		MediaType: mediaType,
		Verified:  want.digest != "" || want.diffID != "",
	}
	info.DiffID = info.Digest
	if diffHash != nil {
		info.DiffID = "sha256:" + hex.EncodeToString(diffHash.Sum(nil))
	}
	var problems []string
	if want.digest != "" && want.digest != info.Digest {
		problems = append(problems, fmt.Sprintf("layer %s digest mismatch: declared %s actual %s", want.name, want.digest, info.Digest))
	}
	if want.diffID != "" && want.diffID != info.DiffID {
		problems = append(problems, fmt.Sprintf("layer %s diff_id mismatch: declared %s actual %s", want.name, want.diffID, info.DiffID))
	}
	if len(problems) > 0 {
		info.Verified = false
		if !u.opts.AllowDigestMismatch {
			return info, errors.New(strings.Join(problems, "; "))
		}
		for _, p := range problems {
			report(u.opts, "verify", "WARNING: "+p+" (continuing: digest mismatches allowed)", false)
		}
	}
	return info, u.ctx.Err()
}

type dockerManifest struct {
	Config       string                   `json:"Config"`
	RepoTags     []string                 `json:"RepoTags"`
	Layers       []string                 `json:"Layers"`
	LayerSources map[string]ociDescriptor `json:"LayerSources"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
	Created      string `json:"created"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

func (img *ImageMetadata) applyConfig(cfg imageConfig, raw []byte) {
	sum := sha256.Sum256(raw)
	img.ID = "sha256:" + hex.EncodeToString(sum[:])
	if cfg.OS != "" {
		img.OS = cfg.OS
	}
	if cfg.Architecture != "" {
		img.Architecture = cfg.Architecture
	}
	if cfg.Variant != "" {
		img.Variant = cfg.Variant
	}
	if cfg.Created != "" {
		img.Created = cfg.Created
	}
}

// blobDigestFromPath recovers the declared digest from a "blobs/sha256/<hex>"
// layer path as written by docker save on Docker 25+.
func blobDigestFromPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) == 3 && parts[0] == "blobs" && parts[1] == "sha256" && len(parts[2]) == 64 {
		return "sha256:" + parts[2]
	}
	return ""
}

// dockerConfigDigest also recognizes the content-addressed filename used by
// legacy Docker save archives. Arbitrary JSON filenames declare no digest.
func dockerConfigDigest(name string) string {
	if digest := blobDigestFromPath(name); digest != "" {
		return digest
	}
	if len(name) == 64+len(".json") && strings.HasSuffix(name, ".json") {
		hexDigest := strings.TrimSuffix(name, ".json")
		if _, err := hex.DecodeString(hexDigest); err == nil {
			return "sha256:" + strings.ToLower(hexDigest)
		}
	}
	return ""
}

func (u *unpacker) unpackDockerArchive(a *outerArchive) ([]File, *ImageMetadata, error) {
	report(u.opts, "archive", "Docker save manifest detected", false)
	raw, err := a.bytes("manifest.json")
	var manifests []dockerManifest
	if err != nil || json.Unmarshal(raw, &manifests) != nil || len(manifests) == 0 {
		return nil, nil, errors.New("invalid Docker manifest.json")
	}
	m := manifests[0]
	if len(manifests) > 1 {
		report(u.opts, "archive", fmt.Sprintf("manifest.json lists %d images; scanning only the first (%s)", len(manifests), strings.Join(m.RepoTags, ",")), false)
	}
	if len(m.Layers) > maxImageLayers {
		//lint:ignore ST1005 Docker is a proper noun; preserve the diagnostic spelling.
		return nil, nil, fmt.Errorf("Docker manifest declares %d layers (limit %d)", len(m.Layers), maxImageLayers)
	}
	image := &ImageMetadata{Tags: appendUnique(nil, m.RepoTags...)}
	var cfg imageConfig
	if m.Config != "" {
		cfgRaw, err := a.bytes(clean(m.Config))
		if err != nil {
			//lint:ignore ST1005 Docker is a proper noun; preserve the diagnostic spelling.
			return nil, nil, fmt.Errorf("Docker config %q: %w", m.Config, err)
		}
		if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
			//lint:ignore ST1005 Docker is a proper noun; preserve the diagnostic spelling.
			return nil, nil, fmt.Errorf("Docker config %q: %w", m.Config, err)
		}
		image.applyConfig(cfg, cfgRaw)
		declared := dockerConfigDigest(clean(m.Config))
		verified := declared != "" && declared == image.ID
		if declared != "" && !verified {
			msg := fmt.Sprintf("Docker config %q digest mismatch: declared %s actual %s", m.Config, declared, image.ID)
			if !u.opts.AllowDigestMismatch {
				return nil, nil, errors.New(msg)
			}
			report(u.opts, "verify", "WARNING: "+msg+" (continuing: digest mismatches allowed)", false)
		}
		report(u.opts, "verify", fmt.Sprintf("Docker config %q (verified=%t)", m.Config, verified), false)
	}
	if n := len(cfg.RootFS.DiffIDs); n > 0 && n != len(m.Layers) {
		//lint:ignore ST1005 Docker is a proper noun; preserve the diagnostic spelling.
		return nil, nil, fmt.Errorf("Docker config declares %d diff_ids but manifest lists %d layers", n, len(m.Layers))
	}
	if len(cfg.RootFS.DiffIDs) == 0 {
		report(u.opts, "verify", "image config declares no rootfs.diff_ids; layer contents cannot be verified", false)
	}
	// Retain selected layers from their cached outer offsets.
	if err := a.retain(m.Layers); err != nil {
		return nil, nil, err
	}
	var layers []File
	for i, layer := range m.Layers {
		name := clean(layer)
		e, ok := a.entries[name]
		if !ok {
			//lint:ignore ST1005 Docker is a proper noun; preserve the diagnostic spelling.
			return nil, nil, fmt.Errorf("Docker layer %q missing", layer)
		}
		want := layerCheck{name: layer, digest: blobDigestFromPath(name), reopen: layerSource(a, name)}
		if i < len(cfg.RootFS.DiffIDs) {
			want.diffID = cfg.RootFS.DiffIDs[i]
			if src, ok := m.LayerSources[want.diffID]; ok {
				want.mediaType = src.MediaType
				if src.Digest != "" {
					want.digest = src.Digest
				}
			}
		}
		rd, done, err := a.open(name)
		if err != nil {
			return nil, nil, err
		}
		report(u.opts, "layer", fmt.Sprintf("applying %s (%d bytes)", layer, e.Size), false)
		info, err := u.applyLayer(rd, e.Size, want)
		done()
		if err != nil {
			return nil, nil, err
		}
		image.Layers = append(image.Layers, info)
		layers = append(layers, File{Path: layer, Size: e.Size, SHA256: strings.TrimPrefix(info.Digest, "sha256:")})
		report(u.opts, "layer", fmt.Sprintf("applied %s (verified=%t); merged filesystem has %d files", layer, info.Verified, len(u.fs)), false)
	}
	u.setDockerIndexDigest(a, image)
	return layers, image, nil
}

// setDockerIndexDigest only attributes an index manifest to the filesystem
// after its config and ordered layers have been matched to the scanned bytes.
func (u *unpacker) setDockerIndexDigest(a *outerArchive, image *ImageMetadata) {
	raw, err := a.bytes("index.json")
	if err != nil {
		return
	}
	var idx ociIndex
	if json.Unmarshal(raw, &idx) != nil || len(idx.Manifests) != 1 || !isManifestType(idx.Manifests[0].MediaType) {
		return
	}
	d := idx.Manifests[0]
	manifestRaw, readErr := a.bytes(digestPath(d.Digest))
	sum := sha256.Sum256(manifestRaw)
	var manifest ociManifest
	reason := ""
	switch {
	case readErr != nil:
		reason = fmt.Sprintf("cannot read manifest: %v", readErr)
	case d.Digest != "sha256:"+hex.EncodeToString(sum[:]):
		reason = "manifest digest mismatch"
	case json.Unmarshal(manifestRaw, &manifest) != nil:
		reason = "invalid manifest JSON"
	case image.ID == "" || manifest.Config.Digest != image.ID:
		reason = "manifest config digest does not match scanned config"
	case len(manifest.Layers) != len(image.Layers):
		reason = "manifest layer count does not match applied layers"
	default:
		for i, layer := range manifest.Layers {
			applied := image.Layers[i]
			if layer.Digest == "" || (layer.Digest != applied.Digest && layer.Digest != applied.DiffID) {
				reason = fmt.Sprintf("manifest layer %d digest does not match applied layer", i)
				break
			}
		}
	}
	verified := reason == ""
	if verified {
		image.Digest = d.Digest
	} else {
		reason = ": " + reason
	}
	report(u.opts, "verify", fmt.Sprintf("Docker index manifest %s (verified=%t)%s", d.Digest, verified, reason), false)
}

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
}

func (p *ociPlatform) String() string {
	if p == nil {
		return "any"
	}
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

type ociIndex struct {
	MediaType   string            `json:"mediaType"`
	Manifests   []ociDescriptor   `json:"manifests"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ociManifest struct {
	MediaType   string            `json:"mediaType"`
	Config      ociDescriptor     `json:"config"`
	Layers      []ociDescriptor   `json:"layers"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func isIndexType(mt string) bool {
	return mt == mediaTypeOCIIndex || mt == mediaTypeDockerList
}

func isManifestType(mt string) bool {
	return mt == mediaTypeOCIManifest || mt == mediaTypeDockerManifest
}

func isAttestation(d ociDescriptor) bool {
	if d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown" {
		return true
	}
	return d.Annotations["vnd.docker.reference.type"] == "attestation-manifest"
}

func isForeignLayer(mt string) bool {
	return strings.Contains(mt, "nondistributable") || strings.Contains(mt, "foreign")
}

func refTags(annotations map[string]string) []string {
	var tags []string
	for _, key := range []string{"io.containerd.image.name", "org.opencontainers.image.ref.name"} {
		tags = appendUnique(tags, annotations[key])
	}
	return tags
}

// platformSpec is the requested os/arch[/variant].
type platformSpec struct {
	os, arch, variant string
}

var archAliases = map[string]string{"x86_64": "amd64", "x86-64": "amd64", "aarch64": "arm64", "armhf": "arm", "armv7l": "arm", "i386": "386", "x64": "amd64"}

func parsePlatform(s string) (platformSpec, error) {
	if strings.TrimSpace(s) == "" {
		return platformSpec{os: "linux", arch: runtime.GOARCH}, nil
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(s)), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return platformSpec{}, fmt.Errorf("invalid platform %q (want os/arch[/variant])", s)
	}
	p := platformSpec{os: parts[0], arch: parts[1]}
	if alias, ok := archAliases[p.arch]; ok {
		p.arch = alias
	}
	if len(parts) == 3 {
		p.variant = parts[2]
	}
	return p, nil
}

func (p platformSpec) String() string {
	if p.variant != "" {
		return p.os + "/" + p.arch + "/" + p.variant
	}
	return p.os + "/" + p.arch
}

func (p platformSpec) matches(d *ociPlatform) bool {
	if d == nil || d.OS != p.os || d.Architecture != p.arch {
		return false
	}
	return p.variant == "" || d.Variant == p.variant
}

type manifestCandidate struct {
	desc ociDescriptor
	tags []string
}

// collectManifests flattens nested indexes into image-manifest candidates,
// skipping attestation manifests.
func (u *unpacker) collectManifests(a *outerArchive, manifests []ociDescriptor, tags []string, depth int, out *[]manifestCandidate) error {
	if depth > 4 {
		return errors.New("OCI index nesting too deep")
	}
	if len(manifests) > maxIndexManifests || len(*out)+len(manifests) > maxIndexManifests {
		return fmt.Errorf("OCI index declares more than %d manifests", maxIndexManifests)
	}
	for _, d := range manifests {
		if isAttestation(d) {
			report(u.opts, "manifest", "skipping attestation manifest "+d.Digest, true)
			continue
		}
		t := tags
		if depth == 0 {
			t = refTags(d.Annotations)
		}
		mt := d.MediaType
		if mt == "" {
			raw, err := a.bytes(digestPath(d.Digest))
			if err != nil {
				return fmt.Errorf("OCI manifest %s: %w", d.Digest, err)
			}
			var probe struct {
				Manifests json.RawMessage `json:"manifests"`
			}
			mt = mediaTypeOCIManifest
			if json.Unmarshal(raw, &probe) == nil && probe.Manifests != nil {
				mt = mediaTypeOCIIndex
			}
		}
		switch {
		case isIndexType(mt):
			raw, err := u.readBlob(a, d, "index")
			if err != nil {
				return err
			}
			var idx ociIndex
			if err := json.Unmarshal(raw, &idx); err != nil {
				return fmt.Errorf("OCI index %s: %w", d.Digest, err)
			}
			if err := u.collectManifests(a, idx.Manifests, t, depth+1, out); err != nil {
				return err
			}
		case isManifestType(mt):
			*out = append(*out, manifestCandidate{desc: d, tags: t})
		default:
			report(u.opts, "manifest", fmt.Sprintf("skipping %s with media type %s", d.Digest, mt), true)
		}
	}
	return nil
}

// choosePlatform picks the manifest to scan: an exact platform match first,
// then a manifest without platform, then (only when the caller did not ask
// for a specific platform) the sole candidate. The bool reports a fallback.
func choosePlatform(candidates []manifestCandidate, want platformSpec, explicit bool) (manifestCandidate, bool, error) {
	for _, c := range candidates {
		if want.matches(c.desc.Platform) {
			return c, false, nil
		}
	}
	for _, c := range candidates {
		if c.desc.Platform == nil {
			return c, false, nil
		}
	}
	if !explicit && len(candidates) == 1 {
		return candidates[0], true, nil
	}
	available := make([]string, 0, len(candidates))
	for _, c := range candidates {
		available = append(available, c.desc.Platform.String())
	}
	if len(available) == 0 {
		return manifestCandidate{}, false, fmt.Errorf("no image manifest for platform %s (archive contains no image manifests)", want)
	}
	return manifestCandidate{}, false, fmt.Errorf("no image manifest for platform %s (available: %s)", want, strings.Join(available, ", "))
}

// readBlob returns a small metadata blob, verifying it against its digest.
func (u *unpacker) readBlob(a *outerArchive, d ociDescriptor, what string) ([]byte, error) {
	raw, err := a.bytes(digestPath(d.Digest))
	if err != nil {
		return nil, fmt.Errorf("OCI %s %s: %w", what, d.Digest, err)
	}
	sum := sha256.Sum256(raw)
	if actual := "sha256:" + hex.EncodeToString(sum[:]); actual != d.Digest {
		msg := fmt.Sprintf("OCI %s %s digest mismatch: actual %s", what, d.Digest, actual)
		if !u.opts.AllowDigestMismatch {
			return nil, errors.New(msg)
		}
		report(u.opts, "verify", "WARNING: "+msg+" (continuing: digest mismatches allowed)", false)
	}
	return raw, nil
}

func (u *unpacker) unpackOCIArchive(a *outerArchive) ([]File, *ImageMetadata, error) {
	report(u.opts, "archive", "OCI image layout detected", false)
	raw, err := a.bytes("index.json")
	var index ociIndex
	if err != nil || json.Unmarshal(raw, &index) != nil || len(index.Manifests) == 0 {
		return nil, nil, errors.New("invalid OCI index")
	}
	want, err := parsePlatform(u.opts.Platform)
	if err != nil {
		return nil, nil, err
	}
	var candidates []manifestCandidate
	if err := u.collectManifests(a, index.Manifests, nil, 0, &candidates); err != nil {
		return nil, nil, err
	}
	declaredMatch := false
	for _, c := range candidates {
		if want.matches(c.desc.Platform) {
			declaredMatch = true
			break
		}
	}
	if !declaredMatch {
		for i := range candidates {
			c := &candidates[i]
			if c.desc.Platform != nil {
				continue
			}
			raw, err := u.readBlob(a, c.desc, "manifest")
			if err != nil {
				return nil, nil, err
			}
			var m ociManifest
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, nil, fmt.Errorf("OCI manifest %s: %w", c.desc.Digest, err)
			}
			var cfg imageConfig
			if m.Config.Digest != "" {
				raw, err := u.readBlob(a, m.Config, "config")
				if err != nil {
					return nil, nil, err
				}
				if err := json.Unmarshal(raw, &cfg); err != nil {
					return nil, nil, fmt.Errorf("OCI config %s: %w", m.Config.Digest, err)
				}
			}
			c.desc.Platform = &ociPlatform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}
			if want.matches(c.desc.Platform) {
				break
			}
		}
	}
	chosen, fallback, err := choosePlatform(candidates, want, strings.TrimSpace(u.opts.Platform) != "")
	if err != nil {
		return nil, nil, err
	}
	if fallback {
		report(u.opts, "manifest", fmt.Sprintf("no manifest for platform %s; scanning the only image manifest (%s)", want, chosen.desc.Platform), false)
	}
	report(u.opts, "manifest", fmt.Sprintf("selected image manifest %s (%s)", chosen.desc.Digest, chosen.desc.Platform), false)
	manifestRaw, err := u.readBlob(a, chosen.desc, "manifest")
	if err != nil {
		return nil, nil, err
	}
	var manifest ociManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, nil, fmt.Errorf("OCI manifest %s: %w", chosen.desc.Digest, err)
	}
	image := &ImageMetadata{Digest: chosen.desc.Digest, Tags: chosen.tags}
	if p := chosen.desc.Platform; p != nil {
		image.OS, image.Architecture, image.Variant = p.OS, p.Architecture, p.Variant
	}
	var cfg imageConfig
	if manifest.Config.Digest != "" {
		cfgRaw, err := u.readBlob(a, manifest.Config, "config")
		if err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
			return nil, nil, fmt.Errorf("OCI config %s: %w", manifest.Config.Digest, err)
		}
		image.applyConfig(cfg, cfgRaw)
	}
	if len(manifest.Layers) > maxImageLayers {
		return nil, nil, fmt.Errorf("OCI manifest declares %d layers (limit %d)", len(manifest.Layers), maxImageLayers)
	}
	if n := len(cfg.RootFS.DiffIDs); n > 0 && n != len(manifest.Layers) {
		return nil, nil, fmt.Errorf("OCI config declares %d diff_ids but manifest lists %d layers", n, len(manifest.Layers))
	}
	names := make([]string, 0, len(manifest.Layers))
	for _, l := range manifest.Layers {
		names = append(names, digestPath(l.Digest))
	}
	if err := a.retain(names); err != nil {
		return nil, nil, err
	}
	var layers []File
	for i, l := range manifest.Layers {
		name := digestPath(l.Digest)
		e, ok := a.entries[name]
		if !ok {
			if isForeignLayer(l.MediaType) {
				report(u.opts, "layer", fmt.Sprintf("skipping non-distributable layer %s (not present in archive)", l.Digest), false)
				image.Layers = append(image.Layers, LayerInfo{Digest: l.Digest, Size: l.Size, MediaType: l.MediaType})
				continue
			}
			return nil, nil, fmt.Errorf("OCI layer %s missing", l.Digest)
		}
		want := layerCheck{name: l.Digest, digest: l.Digest, mediaType: l.MediaType, reopen: layerSource(a, name)}
		if i < len(cfg.RootFS.DiffIDs) {
			want.diffID = cfg.RootFS.DiffIDs[i]
		}
		rd, done, err := a.open(name)
		if err != nil {
			return nil, nil, err
		}
		report(u.opts, "layer", fmt.Sprintf("applying %s (%d bytes)", l.Digest, e.Size), false)
		info, err := u.applyLayer(rd, e.Size, want)
		done()
		if err != nil {
			return nil, nil, err
		}
		image.Layers = append(image.Layers, info)
		layers = append(layers, File{Path: l.Digest, Size: e.Size, SHA256: strings.TrimPrefix(info.Digest, "sha256:")})
		report(u.opts, "layer", fmt.Sprintf("applied %s (verified=%t); merged filesystem has %d files", l.Digest, info.Verified, len(u.fs)), false)
	}
	return layers, image, nil
}
