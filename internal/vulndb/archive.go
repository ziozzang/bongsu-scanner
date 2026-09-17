package vulndb

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Export writes a portable database archive after checking its integrity.
func Export(dir, archivePath string) error { return ExportVerified(dir, archivePath, nil) }

func ExportVerified(dir, archivePath string, pub ed25519.PublicKey) error {
	unlock, err := lockDatabase(dir)
	if err != nil {
		return err
	}
	defer unlock()
	if err = Verify(dir, pub); err != nil {
		return err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	dest, err := filepath.Abs(archivePath)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, dest)
	if err != nil {
		return err
	}
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("export archive must be outside the database")
	}
	archiveRoot, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = archiveRoot.Close() }() // Read-only directory handle.
	f, err := os.CreateTemp(filepath.Dir(archivePath), ".bscan-export-*")
	if err != nil {
		return err
	}
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.Remove(f.Name())
	}()
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("non-regular database file")
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		h := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0644, Size: info.Size(), Typeflag: tar.TypeReg}
		if err = tw.WriteHeader(h); err != nil {
			return err
		}
		in, err := openExportFile(archiveRoot, rel, info)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, in)
		closeErr := in.Close()
		return errors.Join(err, closeErr)
	})
	err = errors.Join(err, tw.Close(), gz.Close(), f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), archivePath)
}

// Keep a concurrent symlink replacement inside the catalog and reject replaced
// entries before copying their bytes to a distributable archive.
func openExportFile(root *os.Root, name string, expected os.FileInfo) (*os.File, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(expected, info) {
		_ = f.Close() // Read-only cleanup after a failed identity check.
		if err != nil {
			return nil, err
		}
		return nil, errors.New("database export entry changed")
	}
	return f, nil
}

// Import validates an archive in a sibling staging directory before replacing
// the database. Links, traversal paths, duplicate entries and special files
// are rejected. The expanded archive is limited to 8 GiB and 100,000 files.
func Import(archivePath, dir string, pub ed25519.PublicKey) (Meta, error) {
	return ImportContext(context.Background(), archivePath, dir, pub)
}

// ImportContext is Import with cancellation applied while reading and
// validating the archive. Cancellation leaves any installed database intact
// and removes the incomplete sibling staging directory.
func ImportContext(ctx context.Context, archivePath, dir string, pub ed25519.PublicKey) (Meta, error) {
	return importContextLimit(ctx, archivePath, dir, pub, 8<<30)
}

func importContextLimit(ctx context.Context, archivePath, dir string, pub ed25519.PublicKey, maxExpanded int64) (Meta, error) {
	var meta Meta
	if err := ctx.Err(); err != nil {
		return meta, err
	}
	unlock, err := lockDatabase(dir)
	if err != nil {
		return meta, err
	}
	defer unlock()
	if err = ctx.Err(); err != nil {
		return meta, err
	}
	if err = recoverDatabaseContext(ctx, dir); err != nil {
		return meta, err
	}
	if err = ctx.Err(); err != nil {
		return meta, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(dir), filepath.Base(dir)+".tmp-")
	if err != nil {
		return meta, err
	}
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.RemoveAll(stage)
	}()
	f, err := os.Open(archivePath) // #nosec G304 -- The caller selects the local import archive; every entry is validated before extraction.
	if err != nil {
		return meta, err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	gz, err := gzip.NewReader(contextReader{ctx: ctx, r: f})
	if err != nil {
		return meta, err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = gz.Close()
	}()
	expanded := &archiveExpansionReader{limited: io.LimitedReader{R: contextReader{ctx: ctx, r: gz}, N: maxExpanded + 1}, max: maxExpanded}
	tr := tar.NewReader(expanded)
	seen := map[string]bool{}
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return meta, err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return meta, err
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !safeRelative(name) || seen[name] {
			return meta, fmt.Errorf("unsafe or duplicate archive path %q", h.Name)
		}
		seen[name] = true
		if len(seen) > 100000 {
			return meta, errors.New("too many archive entries")
		}
		path := filepath.Join(stage, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(path, 0755); err != nil { // #nosec G301 -- Catalog and feed directories contain distributable vulnerability data, not credentials.
				return meta, err
			}
			continue
		case tar.TypeReg: // tar.Reader normalizes legacy NUL type flags to TypeReg.
		default:
			return meta, fmt.Errorf("unsupported archive entry %q", h.Name)
		}
		if h.Size < 0 || h.Size > maxExpanded-total {
			return meta, fmt.Errorf("expanded database archive exceeds %d bytes (including headers)", maxExpanded)
		}
		total += h.Size
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil { // #nosec G301 -- Catalog and feed directories contain distributable vulnerability data, not credentials.
			return meta, err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644) // #nosec G302 G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory. Distributable vulnerability catalog data is intentionally world-readable.
		if err != nil {
			return meta, err
		}
		_, copyErr := io.CopyN(out, tr, h.Size)
		if err = errors.Join(copyErr, out.Close()); err != nil {
			return meta, err
		}
	}
	// Consume the gzip trailer to check its checksum, bounding trailing bytes.
	if n, err := io.Copy(io.Discard, io.LimitReader(expanded, (1<<20)+1)); err != nil {
		return meta, err
	} else if n > 1<<20 {
		return meta, errors.New("excess trailing archive data")
	}
	if err = VerifyContext(ctx, stage, pub); err != nil {
		return meta, err
	}
	st, err := openVerifiedSnapshotContext(ctx, stage, pub)
	if err != nil {
		return meta, err
	}
	meta, err = st.Meta()
	err = errors.Join(err, st.Close())
	if err != nil {
		return meta, err
	}
	if err = ctx.Err(); err != nil {
		return meta, err
	}
	if err = installDatabaseContext(ctx, stage, dir); err != nil {
		return meta, err
	}
	return meta, nil
}

// tar.Reader consumes PAX and GNU extension records internally. Bound the gzip
// output below tar so those headers, padding and trailers all count as expansion.
type archiveExpansionReader struct {
	limited io.LimitedReader
	max     int64
}

func (r *archiveExpansionReader) Read(p []byte) (int, error) {
	n, err := r.limited.Read(p)
	if r.limited.N <= 0 {
		return n, fmt.Errorf("expanded database archive exceeds %d bytes (including headers)", r.max)
	}
	return n, err
}
