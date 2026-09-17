package vulndb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// catalogFile is opened and statted under the shared catalog lock before hashing.
// Keep it alive so verification and SQLite refer to the same inode on Linux.
type catalogFile struct {
	file       *os.File
	info       os.FileInfo
	header     [100]byte
	headerSize int
}

const verificationMarkerName = ".verified"

// Injectable clock and timer keep ctime settlement tests independent of wall time.
var verificationNow = time.Now
var verificationTimer = time.NewTimer

// catalogStat excludes atime, which our own reads may change. Platforms without
// a trustworthy ctime and descriptor ownership check disable this cache.
type catalogStat struct {
	Dev       uint64 `json:"dev"`
	Inode     uint64 `json:"inode"`
	Size      int64  `json:"size"`
	MTimeSec  int64  `json:"mtime_sec"`
	MTimeNSec int64  `json:"mtime_nsec"`
	CTimeSec  int64  `json:"ctime_sec"`
	CTimeNSec int64  `json:"ctime_nsec"`
}

// Begin verification after the recorded ctime's whole second has elapsed.
// Otherwise a write in the same filesystem timestamp tick could leave the
// tuple unchanged and poison a receipt for later opens. Linux filesystems with
// second-or-better ctime resolution are required. A future clock timestamp
// disables caching instead of imposing an unbounded delay. The caller checks
// the original fstat again after hashing, including changes during this wait.
func settledVerificationStat(ctx context.Context, info os.FileInfo) (catalogStat, bool, error) {
	stat, ok := verificationStat(info)
	if !ok {
		return stat, false, nil
	}
	delay := time.Unix(stat.CTimeSec+1, 0).Sub(verificationNow())
	if delay > time.Second {
		return stat, false, nil
	}
	if delay > 0 {
		timer := verificationTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return stat, false, ctx.Err()
		case <-timer.C:
		}
	}
	return stat, true, ctx.Err()
}

// verificationMarker is a local receipt, never an alternative source of trust.
// A non-root writer cannot restore ctime after modifying the SQLite inode.
// The current UID and its private 0600 receipt must be trusted: code running as
// that UID can forge receipts, just as it can replace a user-owned binary.
// Root-level tampering (including forged stat tuples) is outside this model.
type verificationMarker struct {
	ManifestDigest      string      `json:"manifest_digest"`
	SQLiteDigest        string      `json:"sqlite_digest"`
	Stat                catalogStat `json:"stat"`
	SchemaVersion       int         `json:"schema_version"`
	SQLiteSchemaVersion int         `json:"sqlite_schema_version"`
	PinnedKey           string      `json:"pinned_key"`
}

func localVerificationFile(rel string) bool {
	return rel == verificationMarkerName || strings.HasPrefix(rel, ".verified-tmp-") && !strings.Contains(rel, "/")
}

func (m verificationMarker) matches(dir string) bool {
	f, err := openVerificationMarker(filepath.Join(dir, verificationMarkerName))
	if err != nil {
		return false
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	// Bound even an owner-created corrupt receipt, and require one JSON value.
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return false
	}
	var got verificationMarker
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&got) == nil && got == m && decoder.Decode(new(any)) == io.EOF
}

func (m verificationMarker) write(dir string) {
	// Best effort: read-only catalogs still receive full verification. Concurrent
	// shared-lock readers may publish equivalent receipts via separate temp files.
	f, err := os.CreateTemp(dir, ".verified-tmp-")
	if err != nil {
		return
	}
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.Remove(f.Name())
	}()
	err = f.Chmod(0600)
	if err == nil {
		err = json.NewEncoder(f).Encode(m)
	}
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err == nil {
		_ = os.Rename(f.Name(), filepath.Join(dir, verificationMarkerName))
	}
}

func openCatalogFile(path string) (*catalogFile, error) {
	f, err := os.Open(path) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
		return nil, err
	}
	source := &catalogFile{file: f, info: info}
	// Capture the SQLite header before verification, including the change
	// counter at offset 24. A committed write can preserve the stat tuple when
	// filesystem timestamps coalesce. ReadAt also preserves the hash offset.
	source.headerSize, err = f.ReadAt(source.header[:], 0)
	if err != nil && err != io.EOF {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
		return nil, err
	}
	// Short/invalid catalogs still go through the ordinary integrity checks.
	return source, nil
}

func (f *catalogFile) path() string {
	path := fmt.Sprintf("/proc/self/fd/%d", f.file.Fd())
	if info, err := os.Stat(path); err == nil && os.SameFile(f.info, info) {
		return path
	}
	return f.file.Name()
}

func (f *catalogFile) check(message string) error {
	info, err := f.file.Stat()
	if err != nil {
		return fmt.Errorf("%s: %w", message, err)
	}
	if !os.SameFile(f.info, info) || f.info.Size() != info.Size() ||
		!f.info.ModTime().Equal(info.ModTime()) || !reflect.DeepEqual(statCTime(f.info), statCTime(info)) {
		return errors.New(message)
	}
	// Bypass SQLite's immutable page cache: it deliberately disables change
	// detection, so PRAGMA data_version on that connection is insufficient.
	var header [100]byte
	n, err := f.file.ReadAt(header[:], 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("%s: %w", message, err)
	}
	if n != f.headerSize || header != f.header {
		return errors.New(message)
	}
	return nil
}

// Stat_t exposes ctime under different field names on Unix platforms. Ignore
// atime: hashing and SQLite reads may legitimately change it.
func statCTime(info os.FileInfo) any {
	v := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if v.IsValid() && v.Kind() == reflect.Struct {
		for _, name := range []string{"Ctim", "Ctimespec", "Ctime"} {
			if field := v.FieldByName(name); field.IsValid() {
				return field.Interface()
			}
		}
	}
	return nil
}
