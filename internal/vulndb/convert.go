package vulndb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Convert packages an existing verified catalog as SQLite without networking.
// It preserves data freshness, source metadata and original advisory JSON.
// The output is unsigned unless opts.PrivateKey is supplied; opts.PublicKey
// pins the source signature. srcDir and destDir may be the same directory.
func Convert(ctx context.Context, srcDir, destDir string, opts Options) (_ Meta, resultErr error) {
	var meta Meta
	if err := ctx.Err(); err != nil {
		return meta, err
	}
	src, err := filepath.Abs(srcDir)
	if err != nil {
		return meta, err
	}
	dest, err := filepath.Abs(destDir)
	if err != nil {
		return meta, err
	}
	if src != dest && (strings.HasPrefix(dest, src+string(filepath.Separator)) || strings.HasPrefix(src, dest+string(filepath.Separator))) {
		return meta, errors.New("conversion source and destination must not contain each other")
	}
	locks := []string{src}
	if dest != src {
		locks = append(locks, dest)
	}
	sort.Strings(locks)
	var releases []func()
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()
	for _, dir := range locks {
		unlock, err := lockDatabase(dir)
		if err != nil {
			return meta, err
		}
		releases = append(releases, unlock)
		if err = recoverDatabaseContext(ctx, dir); err != nil {
			return meta, err
		}
	}
	st, err := openVerifiedSnapshotContext(ctx, src, opts.PublicKey)
	if err != nil {
		return meta, err
	}
	defer func() { resultErr = errors.Join(resultErr, st.Close()) }()
	meta, err = st.Meta()
	if err != nil {
		return meta, err
	}
	// Records stream from the source store into the new SQLite file; only
	// the set of seen IDs is retained (legacy per-ecosystem stores may list
	// one advisory under several ecosystems). Holding every decoded record
	// needed ~10 GiB for a default catalog.
	seen := map[string]struct{}{}
	streamRecords := func(emit Emit) error {
		clear(seen)
		return visitStoreRecords(ctx, st, func(r *Record) error {
			if _, dup := seen[r.ID]; dup {
				return nil
			}
			seen[r.ID] = struct{}{}
			return emit(r)
		})
	}
	stage, err := os.MkdirTemp(filepath.Dir(dest), filepath.Base(dest)+".tmp-")
	if err != nil {
		return meta, err
	}
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.RemoveAll(stage)
	}()
	for _, name := range []string{"cache", "raw"} {
		if name == "raw" && opts.NoKeepRaw {
			continue
		}
		base := filepath.Join(src, name)
		if _, err := os.Stat(base); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return meta, err
		}
		if err = filepath.WalkDir(base, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("non-regular conversion source: %q", path)
			}
			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			return copyFileContext(ctx, path, filepath.Join(stage, rel))
		}); err != nil {
			return meta, err
		}
	}
	if err = buildSQLiteStream(ctx, stage, streamRecords, &meta); err != nil {
		return meta, err
	}
	if err = writeJSON(filepath.Join(stage, "meta.json"), meta); err != nil {
		return meta, err
	}
	if err = writeManifestContext(ctx, stage, opts); err != nil {
		return meta, err
	}
	if err = VerifyContext(ctx, stage, nil); err != nil {
		return meta, err
	}
	if err = ctx.Err(); err != nil {
		return meta, err
	}
	if err = st.Close(); err != nil {
		return meta, err
	}
	if err = installDatabaseContext(ctx, stage, dest); err != nil {
		return meta, err
	}
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("converted %s records to %s", formatCount(meta.Records), SQLiteFileName))
	}
	return meta, nil
}

func visitStoreRecords(ctx context.Context, store Store, emit Emit) error {
	checked := func(r *Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return emit(r)
	}
	switch st := store.(type) {
	case *sqliteStore:
		rows, err := st.conn.QueryContext(ctx, "SELECT json FROM records ORDER BY id")
		if err != nil {
			return err
		}
		defer func() {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = rows.Close()
		}()
		for rows.Next() {
			var b []byte
			if err = rows.Scan(&b); err != nil {
				return err
			}
			if len(b) >= 64<<20 {
				return errors.New("SQLite advisory exceeds 64 MiB")
			}
			var r Record
			if err = decodeSQLiteRecord(b, &r); err != nil {
				return err
			}
			if err = checked(&r); err != nil {
				return err
			}
		}
		return rows.Err()
	case *diskStore:
		ecos := make([]string, 0, len(st.files))
		for eco := range st.files {
			ecos = append(ecos, eco)
		}
		sort.Strings(ecos)
		for _, eco := range ecos {
			pair := st.files[eco]
			if err := readRecordsReader(io.NewSectionReader(pair[1], 0, 1<<63-1), checked); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("unsupported catalog store for conversion")
	}
}
