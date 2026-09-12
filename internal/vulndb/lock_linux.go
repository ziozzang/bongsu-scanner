//go:build linux

package vulndb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func verificationStat(info os.FileInfo) (catalogStat, bool) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return catalogStat{}, false
	}
	return catalogStat{Dev: s.Dev, Inode: s.Ino, Size: s.Size,
		MTimeSec: int64(s.Mtim.Sec), MTimeNSec: int64(s.Mtim.Nsec),
		CTimeSec: int64(s.Ctim.Sec), CTimeNSec: int64(s.Ctim.Nsec)}, true
}

func trustedVerificationMarker(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode() == 0600 && s.Uid == uint32(os.Getuid())
}

func openVerificationMarker(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !trustedVerificationMarker(info) {
		f.Close()
		return nil, errors.New("untrusted verification marker")
	}
	return f, nil
}

// Keep the lock inode permanently: unlinking it after unlock lets a waiting
// process lock the old inode while a new process creates and locks another.
// flock is released by the kernel even on SIGKILL or unexpected process exit.
func acquireDatabaseLock(path string) (func(), error) {
	return acquireDatabaseFlock(path, syscall.LOCK_EX)
}

func acquireSharedDatabaseLock(path string) (func(), error) {
	return acquireDatabaseFlock(path, syscall.LOCK_SH)
}

func acquireDatabaseFlock(path string, mode int) (func(), error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("database lock unavailable: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if err := syscall.Flock(fd, mode|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("database is locked or unavailable: %w", err)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = f.Close() }) }, nil
}

// This short-lived lock covers only reader publication and garbage collection.
func acquireReaderGuard(path string) (func(), error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

func removeStaleReaderSnapshots(parent string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		matched, _ := filepath.Match(".bscan-db-reader-*", entry.Name())
		if !matched {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		// Older binaries had no owner lock. Preserve their recent snapshots;
		// only reclaim unmarked directories older than 24 hours.
		fd, err := syscall.Open(filepath.Join(path, "owner.lock"), syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
		if errors.Is(err, os.ErrNotExist) {
			info, statErr := entry.Info()
			if statErr == nil && time.Since(info.ModTime()) > 24*time.Hour {
				if err := os.RemoveAll(path); err != nil {
					return err
				}
			}
			continue
		}
		if err != nil {
			continue
		}
		f := os.NewFile(uintptr(fd), path)
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			err = os.RemoveAll(path)
		}
		_ = f.Close()
		if err != nil && !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
	}
	return nil
}
