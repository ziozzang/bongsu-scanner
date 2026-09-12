package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseSigningOrder(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make is unavailable")
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]string{{"-n"}, {"-n", "-j2"}, {"-j2"}, {"-j2", "existing"}} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			dir := t.TempDir()
			// Simulate the builds, and make the signer reject a missing checksum.
			fakeGo := `#!/bin/sh
set -eu
while [ "$1" != "-o" ]; do shift; done
shift
output="$1"
mkdir -p dist
case "$output" in
  dist/bscan)
    cat > "$output" <<'SIGNER'
#!/bin/sh
set -eu
test -s dist/SHA256SUMS
printf signed > dist/SHA256SUMS.sig
SIGNER
    chmod +x "$output"
    ;;
  *) sleep 0.1; printf binary > "$output" ;;
esac
`
			for name, data := range map[string][]byte{
				"Makefile": makefile, "go": []byte(fakeGo),
				"LICENSE": []byte("license"), "THIRD_PARTY_NOTICES.txt": []byte("notices"),
			} {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			existing := flags[len(flags)-1] == "existing"
			args := append(append([]string(nil), flags...), "release", "release-sign")
			if existing {
				if err := os.Mkdir(filepath.Join(dir, "dist"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "dist", "SHA256SUMS"), []byte("existing release\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				args = []string{"-j2", "release-sign"}
			}
			cmd := exec.Command(makePath, args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "MAKEFLAGS=", "MFLAGS=")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("make: %v\n%s", err, out)
			}
			checksum := strings.Index(string(out), "sha256sum ")
			signing := strings.Index(string(out), "./dist/bscan sign ")
			if !existing && (checksum < 0 || signing < checksum) {
				t.Fatalf("checksum must precede signing:\n%s", out)
			}
			if existing {
				data, err := os.ReadFile(filepath.Join(dir, "dist", "SHA256SUMS"))
				if err != nil || string(data) != "existing release\n" {
					t.Fatalf("signing changed the existing release: %q (%v)", data, err)
				}
			}
			if flags[0] != "-n" {
				if _, err := os.Stat(filepath.Join(dir, "dist", "SHA256SUMS.sig")); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
