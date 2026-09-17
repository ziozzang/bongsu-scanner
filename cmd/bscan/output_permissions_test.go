//go:build !windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Umask is process-wide: these tests and their subtests must stay serial.
func TestDeliverableOutputPermissions(t *testing.T) {
	for _, writer := range []struct {
		name  string
		write func(string, []byte) error
	}{
		{"findings", writeCommandOutput},
		{"report", func(path string, data []byte) error {
			return writeReportFile(path, func(w io.Writer) error {
				_, err := w.Write(data)
				return err
			})
		}},
	} {
		t.Run(writer.name, func(t *testing.T) {
			for _, tc := range []struct {
				name           string
				mask           int
				existing, want os.FileMode
			}{
				{"private umask", 0o077, 0, 0o600},
				{"standard umask", 0o022, 0, 0o644},
				{"preserve private target", 0o022, 0o600, 0o600},
				{"preserve readable target", 0o077, 0o640, 0o640},
			} {
				t.Run(tc.name, func(t *testing.T) {
					previous := syscall.Umask(tc.mask)
					t.Cleanup(func() { syscall.Umask(previous) })
					dir := t.TempDir()
					path := filepath.Join(dir, "out.json")
					if tc.existing != 0 {
						if err := os.WriteFile(path, []byte("old"), tc.existing); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(path, tc.existing); err != nil {
							t.Fatal(err)
						}
					}
					if err := writer.write(path, []byte("{}\n")); err != nil {
						t.Fatal(err)
					}
					info, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != tc.want {
						t.Errorf("mode=%#o, want %#o", info.Mode().Perm(), tc.want)
					}
					data, err := os.ReadFile(path)
					if err != nil || string(data) != "{}\n" {
						t.Fatalf("content=%q, err=%v", data, err)
					}
					entries, err := os.ReadDir(dir)
					if err != nil || len(entries) != 1 {
						t.Fatalf("temporary output left behind: %v, err=%v", entries, err)
					}
				})
			}
		})
	}
}
