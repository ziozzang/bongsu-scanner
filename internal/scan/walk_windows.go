//go:build windows

package scan

import (
	"fmt"
	"io/fs"
	"os"
)

// deviceOf has no portable equivalent of st_dev on Windows; OneFileSystem
// therefore cannot distinguish volumes and every directory is treated as the
// root device.
func deviceOf(info fs.FileInfo) uint64 { return 0 }

// openWalkFile rejects a symlink or reparse point at the final component and
// opens the entry through the confined root when one is available.
func (w *walkState) openWalkFile(p string, directory bool) (*os.File, fs.FileInfo, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s: symlink replaced walk entry", p)
	}
	var f *os.File
	if w.safeRoot != nil {
		f, err = w.safeRoot.OpenFile(w.rel(p), os.O_RDONLY, 0)
	} else {
		f, err = os.OpenFile(p, os.O_RDONLY, 0)
	}
	if err != nil {
		return nil, nil, err
	}
	info, err = f.Stat()
	if err == nil && ((directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular())) {
		err = fmt.Errorf("%s: entry type changed during walk", p)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// fileModeSize returns the mode and size of a directory entry.
func (w *walkState) fileModeSize(p string, d fs.DirEntry) (fs.FileMode, int64, error) {
	info, err := d.Info()
	if err != nil {
		return 0, 0, err
	}
	return info.Mode(), info.Size(), nil
}
