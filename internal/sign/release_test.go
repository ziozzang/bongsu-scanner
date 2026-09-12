package sign

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise release recipes in isolation, with a fake compiler/signing command.
// This avoids rebuilding other packages or changing the developer's dist/.
func releaseFixture(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make unavailable")
	}
	dir := t.TempDir()
	for _, name := range []string{"Makefile", "LICENSE", "THIRD_PARTY_NOTICES.txt"} {
		data, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		writeReleaseFixture(t, filepath.Join(dir, name), string(data), 0o644)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeReleaseFixture(t, filepath.Join(dir, "fake-bscan"), `#!/bin/sh
set -eu
test "$#" -eq 4
test "$1" = sign
test "$2" = -o
test "$3" = dist/SHA256SUMS.sig
test "$4" = dist/SHA256SUMS
test -s "$4"
printf '%s\n' "$BONGSU_HOME" > signing-home
printf 'signature\n' > "$3"
`, 0o755)
	writeReleaseFixture(t, filepath.Join(bin, "go"), `#!/bin/sh
set -eu
printf '%s\n' "$*" >> go-calls
if [ "$1" = build ]; then
  while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then
      shift
      mkdir -p "$(dirname "$1")"
      cp fake-bscan "$1"
      exit 0
    fi
    shift
  done
  exit 1
fi
`, 0o755)
	writeReleaseFixture(t, filepath.Join(bin, "gofmt"), `#!/bin/sh
test "$*" = '-l .' || exit 2
printf '%s' "${FORMAT_OUTPUT-}"
exit "${FORMAT_STATUS-0}"
`, 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BONGSU_HOME", filepath.Join(dir, "publisher identity"))
	t.Setenv("FORMAT_OUTPUT", "")
	t.Setenv("FORMAT_STATUS", "0")
	return dir
}

func writeReleaseFixture(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func runMake(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("make", append([]string{"--no-print-directory"}, args...)...)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}

func TestReleaseSigningAndNotices(t *testing.T) {
	dir := releaseFixture(t)
	out, err := runMake(dir, "release", "VERSION=9.8.7")
	if err != nil {
		t.Fatalf("release: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "release-sign") {
		t.Error("unsigned release did not print a signing reminder")
	}
	for _, name := range []string{"LICENSE", "THIRD_PARTY_NOTICES.txt"} {
		want, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "dist", name))
		if err != nil || string(got) != string(want) {
			t.Errorf("release notice %s missing or changed: %v", name, err)
		}
	}
	sums, err := os.ReadFile(filepath.Join(dir, "dist", "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	out, err = runMake(dir, "release-sign", "VERSION=9.8.7")
	if err != nil {
		t.Fatalf("release-sign: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", "SHA256SUMS.sig")); err != nil {
		t.Fatal(err)
	}
	home, err := os.ReadFile(filepath.Join(dir, "signing-home"))
	if err != nil || strings.TrimSpace(string(home)) != os.Getenv("BONGSU_HOME") {
		t.Fatalf("signing identity directory was not inherited: %q, %v", home, err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "dist", "SHA256SUMS"))
	if err != nil || string(after) != string(sums) {
		t.Fatal("release-sign changed existing checksums")
	}
}

func TestCleanRemovesStaleSignature(t *testing.T) {
	dir := releaseFixture(t)
	if err := os.Mkdir(filepath.Join(dir, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dist", "SHA256SUMS.sig")
	writeReleaseFixture(t, path, "stale signature", 0o644)
	if out, err := runMake(dir, "clean"); err != nil {
		t.Fatalf("clean: %v\n%s", err, out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("clean left a stale signature: %v", err)
	}
}

func TestMakeTestChecksFormatAndDisablesCache(t *testing.T) {
	for _, tc := range []struct {
		name, output, status string
		wantFailure          bool
	}{
		{"formatted", "", "0", false},
		{"unformatted", "bad.go\n", "0", true},
		{"parse error", "", "2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := releaseFixture(t)
			t.Setenv("FORMAT_OUTPUT", tc.output)
			t.Setenv("FORMAT_STATUS", tc.status)
			out, err := runMake(dir, "test")
			if (err != nil) != tc.wantFailure {
				t.Fatalf("make test error = %v, wantFailure = %t\n%s", err, tc.wantFailure, out)
			}
			if !tc.wantFailure {
				calls, err := os.ReadFile(filepath.Join(dir, "go-calls"))
				if err != nil || !strings.Contains(string(calls), "test -race -count=1 ./...") || !strings.Contains(string(calls), "vet ./...") {
					t.Fatalf("missing uncached race test or vet: %q, %v", calls, err)
				}
			}
		})
	}
}

func TestMemoryMmapNotice(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "THIRD_PARTY_NOTICES.txt"))
	if err != nil {
		t.Fatal(err)
	}
	const start = "Copyright (c) 2011, Evan Shaw <edsrzf@gmail.com>"
	idx := strings.Index(string(data), start)
	if idx < 0 {
		t.Fatal("missing modernc.org/memory LICENSE-MMAP-GO")
	}
	// Hash of the complete LICENSE-MMAP-GO from modernc.org/memory v1.12.1.
	const want = "c2eba69f20d05414538c3a5df7694dde392e065ff70882e1625e90f5d6659fff"
	const noticeBytes = 1518
	if len(data)-idx < noticeBytes {
		t.Fatal("truncated mmap notice")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data[idx:idx+noticeBytes])); got != want {
		t.Fatalf("appended mmap notice differs from upstream: %s", got)
	}
}

func TestReadmeSignatureAndReleasePolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{
		"Version 1", "Version 2", "unauthenticated",
		"make release-sign", "BONGSU_HOME", "SHA256SUMS.sig",
		"a pinned release key requires", "even without `--require-signature`",
	} {
		if !strings.Contains(string(data), phrase) {
			t.Errorf("README missing signature/release guidance: %q", phrase)
		}
	}
	if strings.Contains(string(data), "the signature record was modified") {
		t.Error("README still claims all record changes fail verification")
	}
}
