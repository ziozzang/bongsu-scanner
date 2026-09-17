//go:build !windows

package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// deviceOf returns the st_dev of a file, or 0 when unavailable.
func deviceOf(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		return uint64(st.Dev)
	}
	return 0
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
		f, err = os.OpenFile(p, flags, 0) // #nosec G304 -- The caller selects the scan root; O_NOFOLLOW and post-open validation protect traversal.
	}
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err == nil && ((directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular())) {
		err = fmt.Errorf("%s: walk entry changed type", p)
	}
	if err != nil {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
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
