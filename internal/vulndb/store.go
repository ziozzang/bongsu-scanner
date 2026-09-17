package vulndb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	filehash "github.com/ziozzang/bongsu-scanner/internal/hash"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

type diskStore struct {
	dir    string
	meta   Meta
	mu     sync.Mutex
	loaded map[string]*ecosystemIndex
	files  map[string][2]*os.File
	closed bool
}
type ecosystemIndex struct {
	names   map[string][]int
	records []Record
}

func Open(dir string) (Store, error) { return OpenVerified(dir, nil) }

// OpenVerified pins the signer and opens a verified catalog with auto isolation.
func OpenVerified(dir string, pub ed25519.PublicKey) (Store, error) {
	return OpenVerifiedContext(context.Background(), dir, pub)
}

func OpenContext(ctx context.Context, dir string) (Store, error) {
	return OpenVerifiedContext(ctx, dir, nil)
}

// OpenVerifiedContext supports cancellation during verification and snapshot creation.
func OpenVerifiedContext(ctx context.Context, dir string, pub ed25519.PublicKey) (Store, error) {
	return OpenWithOptionsContext(ctx, dir, Options{PublicKey: pub})
}

// OpenWithOptionsContext opens a catalog with explicit reader options.
func OpenWithOptionsContext(ctx context.Context, dir string, opts Options) (Store, error) {
	return OpenWithKeyResolverContext(ctx, dir, opts, nil)
}

// OpenWithKeyResolverContext resolves signature trust after recovery while holding
// the same catalog lock used for verification. resolve receives the catalog path.
// A nil resolver uses opts.PublicKey.
func OpenWithKeyResolverContext(ctx context.Context, dir string, opts Options, resolve func(string) (ed25519.PublicKey, error)) (Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mode, err := opts.isolationMode()
	if err != nil {
		return nil, err
	}
	opts.Isolation, opts.SkipIsolation = mode, false
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return nil, err
	}
	unlock, err := acquireSharedDatabaseLock(dir + ".lock")
	if err != nil {
		return nil, err
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	// Recovery mutates directories and therefore needs the writer lock. Ordinary
	// opens use only a shared lock, permitting multiple in-place readers.
	if _, statErr := os.Lstat(dir); errors.Is(statErr, os.ErrNotExist) {
		unlock()
		unlock = nil
		writerUnlock, err := lockDatabase(dir)
		if err != nil {
			return nil, err
		}
		err = recoverDatabaseContext(ctx, dir)
		writerUnlock()
		if err != nil {
			return nil, err
		}
		unlock, err = acquireSharedDatabaseLock(dir + ".lock")
		if err != nil {
			return nil, err
		}
	} else if statErr != nil {
		return nil, statErr
	}
	if resolve != nil {
		opts.PublicKey, err = resolve(dir)
		if err != nil {
			return nil, err
		}
	}
	st, err := openVerifiedSnapshotOptionsContext(ctx, dir, opts)
	if err != nil {
		return nil, err
	}
	if sqlite, ok := st.(*sqliteStore); ok && mode == "auto" && sqlite.snapshot == "" {
		release, cleanup := unlock, sqlite.releaseSnapshot
		sqlite.releaseSnapshot = func() error { defer release(); return cleanup() }
		unlock = nil // Transfer ownership to Close, after the SQLite connection closes.
	}
	return st, nil
}

// openVerifiedSnapshot requires an existing lock for the entire store lifetime
// or an isolated staging path.
func openVerifiedSnapshot(dir string, pub ed25519.PublicKey) (Store, error) {
	return openVerifiedSnapshotContext(context.Background(), dir, pub)
}

func openVerifiedSnapshotContext(ctx context.Context, dir string, pub ed25519.PublicKey) (Store, error) {
	return openVerifiedSnapshotOptionsContext(ctx, dir, Options{PublicKey: pub})
}

func openVerifiedSnapshotOptionsContext(ctx context.Context, dir string, opts Options) (Store, error) {
	var source *catalogFile
	mode, err := opts.isolationMode()
	if err != nil {
		return nil, err
	}
	if mode == "auto" || mode == "none" {
		source, err = openCatalogFile(filepath.Join(dir, SQLiteFileName))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		defer func() {
			if source != nil {
				source.file.Close()
			}
		}()
	}
	digests, err := verifyWithDigestsContext(ctx, dir, opts.PublicKey, source)
	if source != nil {
		if changed := source.check("catalog changed during verification"); changed != nil {
			return nil, changed
		}
	}
	if err != nil {
		return nil, err
	}
	var m Meta
	if err = readVerifiedJSONContext(ctx, filepath.Join(dir, "meta.json"), digests["meta.json"], &m); err != nil {
		return nil, err
	}
	if m.SchemaVersion == SchemaVersion {
		digest := digests[SQLiteFileName]
		if digest == "" {
			return nil, errors.New("database integrity check failed: manifest does not cover advisories.sqlite")
		}
		st, err := openSQLiteSnapshotOptionsContext(ctx, dir, m, digest, opts, source)
		if err == nil && source != nil {
			if st.(*sqliteStore).source == nil {
				source.file.Close()
			}
			source = nil // The in-place store owns the descriptor until Close.
		}
		return st, err
	}
	if m.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported database schema %d; run bscan db update", m.SchemaVersion)
	}
	s := &diskStore{dir: dir, meta: m, loaded: map[string]*ecosystemIndex{}, files: map[string][2]*os.File{}}
	for _, e := range m.Ecosystems {
		if err := ctx.Err(); err != nil {
			s.Close()
			return nil, err
		}
		eco := BaseEcosystem(e)
		if _, ok := s.files[eco]; ok {
			continue
		}
		base := filepath.Join(dir, "index", safeName(eco))
		namesRel := filepath.ToSlash(filepath.Join("index", safeName(eco), "names.json"))
		names, err := verifiedLegacyCopy(ctx, filepath.Join(base, "names.json"), digests[namesRel])
		if err != nil {
			s.Close()
			return nil, err
		}
		recordsRel := filepath.ToSlash(filepath.Join("index", safeName(eco), "records.jsonl.gz"))
		records, err := verifiedLegacyCopy(ctx, filepath.Join(base, "records.jsonl.gz"), digests[recordsRel])
		if err != nil {
			closeLegacyCopy(names)
			s.Close()
			return nil, err
		}
		s.files[eco] = [2]*os.File{names, records}
	}
	return s, nil
}
func (s *diskStore) Meta() (Meta, error) {
	b, _ := json.Marshal(s.meta)
	var m Meta
	_ = json.Unmarshal(b, &m)
	return m, nil
}
func (s *diskStore) Ecosystems() ([]string, error) {
	return append([]string(nil), s.meta.Ecosystems...), nil
}
func (s *diskStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	for _, pair := range s.files {
		for _, f := range pair {
			errs = append(errs, closeLegacyCopy(f))
		}
	}
	s.loaded = nil
	return errors.Join(errs...)
}
func (s *diskStore) Lookup(ecosystem, name string) ([]Record, error) {
	return s.LookupContext(context.Background(), ecosystem, name)
}

func (s *diskStore) LookupContext(ctx context.Context, ecosystem, name string) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("database is closed")
	}
	eco := BaseEcosystem(ecosystem)
	found := false
	for _, e := range s.meta.Ecosystems {
		if BaseEcosystem(e) == eco {
			found = true
			break
		}
	}
	if !found {
		return nil, nil
	}
	idx := s.loaded[eco]
	if idx == nil {
		idx = &ecosystemIndex{}
		pair := s.files[eco]
		if err := readJSONReader(contextReader{ctx: ctx, r: io.NewSectionReader(pair[0], 0, 1<<63-1)}, &idx.names); err != nil {
			return nil, err
		}
		if err := readRecordsReader(contextReader{ctx: ctx, r: io.NewSectionReader(pair[1], 0, 1<<63-1)}, func(r *Record) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			idx.records = append(idx.records, *r)
			return nil
		}); err != nil {
			return nil, err
		}
		s.loaded[eco] = idx
	}
	var out []Record
	for _, n := range idx.names[NormalizeName(eco, name)] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if n < 0 || n >= len(idx.records) {
			return nil, errors.New("invalid database name index")
		}
		out = append(out, idx.records[n])
	}
	// Callers may annotate records; do not expose shared cached maps/slices.
	if len(out) > 0 {
		b, err := json.Marshal(out)
		if err != nil {
			return nil, err
		}
		var cloned []Record
		if err = json.Unmarshal(b, &cloned); err != nil {
			return nil, err
		}
		out = cloned
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
func readJSON(path string, v any) error {
	return readJSONContext(context.Background(), path, v)
}

func readJSONContext(ctx context.Context, path string, v any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := readJSONReader(contextReader{ctx: ctx, r: f}, v); err != nil {
		return err
	}
	return ctx.Err()
}
func readJSONReader(r io.Reader, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, (64<<20)+1))
	if err != nil {
		return err
	}
	if len(b) > 64<<20 {
		return errors.New("database JSON exceeds 64 MiB")
	}
	return json.Unmarshal(b, v)
}
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if len(b)+1 > 64<<20 {
		return errors.New("database JSON exceeds 64 MiB")
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func readRecords(path string, emit Emit) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return readRecordsReader(f, emit)
}
func readRecordsReader(reader io.Reader, emit Emit) error {
	return readRecordsBounded(reader, emit, 1<<30, 64<<20)
}

func readRecordsBounded(reader io.Reader, emit Emit, maxBytes int64, maxRecord int) error {
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: maxBytes + 1}
	scanner := bufio.NewScanner(limited)
	initial := 64 << 10
	if initial > maxRecord {
		initial = maxRecord
	}
	scanner.Buffer(make([]byte, initial), maxRecord)
	for scanner.Scan() {
		var r Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return err
		}
		if err := emit(&r); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if limited.N < 1 {
		return fmt.Errorf("expanded database index exceeds %d bytes", maxBytes)
	}
	return nil
}
func writeRecords(path string, records []*Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	var expanded int64
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			gz.Close()
			return err
		}
		if len(b)+1 >= 64<<20 || int64(len(b)+1) > (1<<30)-expanded {
			gz.Close()
			return errors.New("database record or expanded index exceeds size limit")
		}
		expanded += int64(len(b) + 1)
		if _, err = gz.Write(append(b, '\n')); err != nil {
			gz.Close()
			return err
		}
	}
	if err = gz.Close(); err != nil {
		return err
	}
	return f.Close()
}
func safeRelative(p string) bool {
	return p != "" && !strings.ContainsAny(p, "\\\r\n") && !filepath.IsAbs(p) && filepath.ToSlash(filepath.Clean(p)) == p && p != "." && p != ".." && !strings.HasPrefix(p, "../")
}

// Verify checks complete manifest coverage and optional Ed25519 pinning. A
// signature without a pinned key proves integrity, not publisher identity.
func Verify(dir string, pub ed25519.PublicKey) error {
	return VerifyContext(context.Background(), dir, pub)
}

// VerifyContext verifies the catalog while honoring cancellation between reads.
func VerifyContext(ctx context.Context, dir string, pub ed25519.PublicKey) error {
	_, err := verifyWithDigestsContext(ctx, dir, pub)
	return err
}

func verifyWithDigests(dir string, pub ed25519.PublicKey) (map[string]string, error) {
	return verifyWithDigestsContext(context.Background(), dir, pub)
}

func verifyWithDigestsContext(ctx context.Context, dir string, pub ed25519.PublicKey, sources ...*catalogFile) (map[string]string, error) {
	var source *catalogFile
	var pinned *os.File
	if len(sources) > 0 && sources[0] != nil {
		source = sources[0]
		pinned = source.file
	}
	digests, err := verifyCatalogContext(ctx, dir, pub, pinned, source)
	if err != nil {
		return nil, fmt.Errorf("database integrity check failed: %w", err)
	}
	return digests, ctx.Err()
}
func verify(dir string, pub ed25519.PublicKey) (map[string]string, error) {
	return verifyContext(context.Background(), dir, pub)
}

func verifyContext(ctx context.Context, dir string, pub ed25519.PublicKey, pinned ...*os.File) (map[string]string, error) {
	var f *os.File
	if len(pinned) > 0 {
		f = pinned[0]
	}
	// Explicit Verify and install/import validation always hash all entries.
	return verifyCatalogContext(ctx, dir, pub, f, nil)
}

func verifyCatalogContext(ctx context.Context, dir string, pub ed25519.PublicKey, pinned *os.File, source *catalogFile) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manifest := filepath.Join(dir, "manifest.sha256")
	manifestFile, err := os.Open(manifest)
	if err != nil {
		return nil, err
	}
	defer manifestFile.Close()
	h := sha256.New()
	limited := &io.LimitedReader{R: contextReader{ctx: ctx, r: manifestFile}, N: (64 << 20) + 1}
	entries, err := filehash.ReadFrom(io.TeeReader(limited, h))
	if err != nil {
		return nil, err
	}
	if limited.N < 1 {
		return nil, errors.New("database manifest exceeds 64 MiB")
	}
	manifestDigest := hex.EncodeToString(h.Sum(nil))
	covered := map[string]bool{}
	digests := map[string]string{}
	rawCovered := false
	for _, e := range entries {
		if !safeRelative(e.Path) || covered[e.Path] {
			return nil, fmt.Errorf("unsafe or duplicate manifest path %q", e.Path)
		}
		covered[e.Path] = true
		digests[e.Path] = e.Digest
		rawCovered = rawCovered || strings.HasPrefix(e.Path, "raw/")
	}
	if !covered["meta.json"] {
		return nil, errors.New("manifest does not cover meta.json")
	}
	// Schema-v1 manifests historically omitted raw feeds. Once a manifest
	// covers any raw feed, require complete raw-directory coverage as well.
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e != nil {
			return e
		}
		if p == dir {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in database: %s", rel)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("non-regular database file: %s", rel)
		}
		if localVerificationFile(rel) || rel == "manifest.sha256" || rel == "manifest.sha256.sig" || strings.HasPrefix(rel, "raw/") && !rawCovered {
			return nil
		}
		if !covered[rel] {
			return fmt.Errorf("file missing from manifest: %s", rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var marker verificationMarker
	cacheable, cached := false, false
	if source != nil && digests[SQLiteFileName] != "" {
		stat, ok, err := settledVerificationStat(ctx, source.info)
		if err != nil {
			return nil, err
		}
		cacheable = ok
		key := "unsigned"
		if pub != nil {
			fingerprint := sha256.Sum256(pub)
			key = hex.EncodeToString(fingerprint[:])
		}
		marker = verificationMarker{ManifestDigest: manifestDigest, SQLiteDigest: digests[SQLiteFileName],
			Stat: stat, SchemaVersion: SchemaVersion, SQLiteSchemaVersion: SQLiteSchemaVersion, PinnedKey: key}
		cached = cacheable && marker.matches(dir)
	}
	// Hash the entries parsed above, so the digest returned to the SQLite
	// snapshot creator is exactly the digest that was checked here.
	for _, entry := range entries {
		if entry.Path == SQLiteFileName && cached {
			continue
		}
		var got string
		var hashErr error
		if entry.Path == SQLiteFileName && pinned != nil {
			got, hashErr = hashReaderContext(ctx, pinned)
		} else {
			got, hashErr = hashFileContext(ctx, filepath.Join(dir, filepath.FromSlash(entry.Path)))
		}
		if hashErr != nil {
			return nil, fmt.Errorf("%s: %w", entry.Path, hashErr)
		}
		if got != entry.Digest {
			return nil, fmt.Errorf("%s: checksum mismatch", entry.Path)
		}
	}
	sigPath := manifest + ".sig"
	if _, err = os.Stat(sigPath); errors.Is(err, os.ErrNotExist) {
		if pub != nil {
			return nil, errors.New("pinned key requires signed database")
		}
	} else if err != nil {
		return nil, err
	} else {
		r, err := ReadSignatureContext(ctx, sigPath)
		if err != nil {
			return nil, err
		}
		if manifestDigest != r.DigestSHA256 {
			return nil, errors.New("manifest signature digest mismatch")
		}
		if err := r.Verify(pub); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cacheable && !cached {
		if err := source.check("catalog changed during verification"); err != nil {
			return nil, err
		}
		marker.write(dir)
	}
	return digests, ctx.Err()
}
func writeManifest(dir string, opts Options) error {
	return writeManifestContext(context.Background(), dir, opts)
}

func writeManifestContext(ctx context.Context, dir string, opts Options) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// A rebuilt manifest invalidates any receipt and must never cover local
	// reader state. Rename-based installs also invalidate old receipts by inode.
	if err := os.Remove(filepath.Join(dir, verificationMarkerName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var entries []filehash.Entry
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if localVerificationFile(rel) && d.Type().IsRegular() {
			return nil
		}
		sum, err := hashFileContext(ctx, p)
		if err != nil {
			return err
		}
		entries = append(entries, filehash.Entry{Path: rel, Digest: sum})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	path := filepath.Join(dir, "manifest.sha256")
	manifest, err := os.Create(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			manifest.Close()
			_ = os.Remove(path)
			return err
		}
		if strings.ContainsAny(entry.Path, "\r\n") {
			manifest.Close()
			_ = os.Remove(path)
			return fmt.Errorf("unsafe manifest path %q", entry.Path)
		}
		if _, err = fmt.Fprintf(manifest, "%s  %s\n", entry.Digest, entry.Path); err != nil {
			manifest.Close()
			_ = os.Remove(path)
			return err
		}
	}
	if err = errors.Join(manifest.Close(), ctx.Err()); err != nil {
		_ = os.Remove(path)
		return err
	}
	if len(opts.PrivateKey) > 0 {
		if len(opts.PrivateKey) != ed25519.PrivateKeySize {
			return errors.New("invalid signing private key")
		}
		sum, err := hashFileContext(ctx, path)
		if err != nil {
			return err
		}
		r, err := sign.Create(sum, "manifest.sha256", opts.Signer, opts.PrivateKey, time.Now())
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = sign.WriteRecord(path+".sig", r); err != nil {
			return err
		}
		return ctx.Err()
	}
	return ctx.Err()
}

// readVerifiedJSONContext parses only bytes whose hash matches the verified
// manifest, even if the source is replaced between verification and this read.
func readVerifiedJSONContext(ctx context.Context, path, expected string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, r: f}, (64<<20)+1))
	if err != nil {
		return err
	}
	if len(b) > 64<<20 {
		return errors.New("database JSON exceeds 64 MiB")
	}
	digest := sha256.Sum256(b)
	if expected == "" || hex.EncodeToString(digest[:]) != expected {
		return fmt.Errorf("database integrity check failed: %s changed after verification", filepath.Base(path))
	}
	return readJSONReader(bytes.NewReader(b), v)
}

func verifiedLegacyCopy(ctx context.Context, path, expected string) (*os.File, error) {
	if expected == "" {
		return nil, fmt.Errorf("database integrity check failed: manifest does not cover %s", path)
	}
	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	out, err := os.CreateTemp("", ".bscan-legacy-reader-*")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) { closeLegacyCopy(out); return nil, err }
	if _, err = io.Copy(out, contextReader{ctx: ctx, r: in}); err != nil {
		return fail(err)
	}
	if _, err = out.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	h := sha256.New()
	if _, err = io.Copy(h, contextReader{ctx: ctx, r: out}); err != nil {
		return fail(err)
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return fail(fmt.Errorf("database integrity check failed: %s changed after verification", filepath.Base(path)))
	}
	// Unlink immediately where supported; the descriptor retains the isolated
	// copy and the kernel reclaims it even when the reader process crashes.
	_ = os.Remove(out.Name())
	return out, nil
}

func closeLegacyCopy(f *os.File) error {
	err := f.Close()
	if removeErr := os.Remove(f.Name()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return errors.Join(err, removeErr)
	}
	return err
}

// ReadSignatureContext bounds detached database signatures, including the CLI's
// preliminary signer discovery, without changing the general signing package.
func ReadSignatureContext(ctx context.Context, path string) (sign.Record, error) {
	var record sign.Record
	f, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, r: f}, (64<<10)+1))
	if err != nil {
		return record, err
	}
	if len(b) > 64<<10 {
		return record, errors.New("database signature exceeds 64 KiB")
	}
	err = json.Unmarshal(b, &record)
	return record, err
}

// CPEStore extends advisory lookups with the optional CPE index.
type CPEStore interface {
	Store
	LookupCPE(vendor, product string) ([]Record, error)
}

func (s *diskStore) LookupCPE(vendor, product string) ([]Record, error) {
	return s.Lookup("CPE", vendor+":"+product)
}
