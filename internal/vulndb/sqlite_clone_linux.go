//go:build linux

package vulndb

import (
	"os"

	"golang.org/x/sys/unix"
)

func cloneSQLiteFile(dst, src *os.File) error {
	return unix.IoctlFileClone(int(dst.Fd()), int(src.Fd()))
}
