package hash

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Entry struct {
	Digest string
	Path   string
}

func File(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
	if err != nil {
		return "", err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Write(path string, entries []Entry) error {
	f, err := os.Create(path) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	for _, e := range entries {
		if strings.ContainsAny(e.Path, "\r\n") {
			return fmt.Errorf("unsafe manifest path %q", e.Path)
		}
		if _, err := fmt.Fprintf(f, "%s  %s\n", e.Digest, e.Path); err != nil {
			return err
		}
	}
	return f.Close()
}

func Read(path string) ([]Entry, error) {
	f, err := os.Open(path) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
	if err != nil {
		return nil, err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	return ReadFrom(f)
}

// ReadFrom parses a SHA-256 manifest from an already opened stream. Callers
// that also authenticate the manifest can hash these exact bytes as they are
// parsed instead of reopening a path that may have changed.
func ReadFrom(r io.Reader) ([]Entry, error) {
	var out []Entry
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return nil, fmt.Errorf("invalid SHA256 manifest line")
		}
		if _, err := hex.DecodeString(line[:64]); err != nil {
			return nil, fmt.Errorf("invalid SHA256 digest")
		}
		out = append(out, Entry{Digest: line[:64], Path: line[66:]})
	}
	return out, s.Err()
}

func Verify(manifest string) error {
	entries, err := Read(manifest)
	if err != nil {
		return err
	}
	base := filepath.Dir(manifest)
	for _, e := range entries {
		p := e.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, filepath.FromSlash(p))
		}
		got, err := File(p)
		if err != nil {
			return fmt.Errorf("%s: %w", e.Path, err)
		}
		if got != e.Digest {
			return fmt.Errorf("%s: checksum mismatch", e.Path)
		}
	}
	return nil
}
