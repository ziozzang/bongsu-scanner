package hash

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type manifestErrorReader struct{ err error }

func (r manifestErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestSecurityManifestReadErrors(t *testing.T) {
	for name, input := range map[string]string{
		"short": "abc", "bad separator": strings.Repeat("a", 64) + " *file",
		"invalid digest": strings.Repeat("z", 64) + "  file", "empty path": strings.Repeat("a", 64) + "  ",
		"oversized line": strings.Repeat("a", 64) + "  " + strings.Repeat("x", 65536),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadFrom(strings.NewReader(input)); err == nil {
				t.Fatal("malformed manifest accepted")
			}
		})
	}
	want := errors.New("manifest read failed")
	if _, err := ReadFrom(manifestErrorReader{want}); !errors.Is(err, want) {
		t.Fatalf("reader error = %v", err)
	}
	if entries, err := ReadFrom(strings.NewReader("")); err != nil || len(entries) != 0 {
		t.Fatalf("empty manifest = %v, %v", entries, err)
	}
}

func TestSecurityManifestFilesystemEdges(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	for _, path := range []string{dir, missing} {
		if _, err := File(path); err == nil {
			t.Errorf("File(%q) accepted unreadable file", path)
		}
		if _, err := Read(path); err == nil {
			t.Errorf("Read(%q) accepted unreadable file", path)
		}
		if err := Verify(path); err == nil {
			t.Errorf("Verify(%q) accepted unreadable manifest", path)
		}
	}
	if err := Write(dir, nil); err == nil {
		t.Fatal("writing over directory succeeded")
	}
	manifest := filepath.Join(dir, "SHA256SUMS")
	for _, path := range []string{"file\ninjected", "file\rinjected"} {
		if err := Write(manifest, []Entry{{Digest: strings.Repeat("0", 64), Path: path}}); err == nil {
			t.Errorf("unsafe path %q accepted", path)
		}
	}
	file := filepath.Join(dir, "file with spaces")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	want := []Entry{{Digest: emptyDigest, Path: file}, {Digest: emptyDigest, Path: filepath.Base(file)}}
	if err := Write(manifest, want); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(manifest); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, %v", got, err)
	}
	if err := Verify(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := Verify(manifest); !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), file) {
		t.Fatalf("missing entry error = %v", err)
	}
	// ReadFrom must return a reader failure even after a valid entry.
	if _, err := ReadFrom(io.MultiReader(strings.NewReader(emptyDigest+"  file\n"), manifestErrorReader{io.ErrUnexpectedEOF})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("late reader error = %v", err)
	}
}
