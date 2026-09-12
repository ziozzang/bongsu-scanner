//go:build !linux

package vulndb

import (
	"errors"
	"os"
)

func cloneSQLiteFile(_, _ *os.File) error {
	return errors.New("copy-on-write file cloning is unavailable")
}
