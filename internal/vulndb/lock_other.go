//go:build !linux

package vulndb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Fail closed where Linux descriptor/ctime guarantees are unavailable.
func verificationStat(os.FileInfo) (catalogStat, bool) { return catalogStat{}, false }

func openVerificationMarker(string) (*os.File, error) {
	return nil, errors.New("verification cache unavailable on this platform")
}

// Non-Linux builds retain the directory-lock fallback. Unlike Linux flock,
// this fallback requires stale-lock cleanup after abnormal process exit.
func acquireDatabaseLock(path string) (func(), error) {
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, fmt.Errorf("database is locked or unavailable: %w", err)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = os.Remove(path) }) }, nil
}

func acquireReaderGuard(path string) (func(), error) { return acquireDatabaseLock(path) }

// Preserve owner-marked copies: portable locks cannot distinguish dead owners.
// Unmarked snapshots from older binaries are eligible only after 24 hours.
func removeStaleReaderSnapshots(parent string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		matched, _ := filepath.Match(".bscan-db-reader-*", entry.Name())
		if !entry.IsDir() || !matched {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		if _, err := os.Lstat(filepath.Join(path, "owner.lock")); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		info, err := entry.Info()
		if err == nil && time.Since(info.ModTime()) > 24*time.Hour {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
	}
	return nil
}

// The portable directory lock cannot share ownership. Keep an exclusive lock
// for in-place readers so writers still cannot replace their catalog.
func acquireSharedDatabaseLock(path string) (func(), error) { return acquireDatabaseLock(path) }
