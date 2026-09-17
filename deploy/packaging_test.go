package deploy

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func requireText(t *testing.T, path string, required ...string) {
	t.Helper()
	s := read(t, path)
	for _, want := range required {
		if !strings.Contains(s, want) {
			t.Errorf("%s: missing %q", path, want)
		}
	}
}

func TestDistribution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("distribution recipes run on a POSIX build host")
	}
	for _, name := range []string{"make", "tar", "sha256sum"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(name + " unavailable")
		}
	}
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("compiler-failure=", fail), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "deploy"), 0755); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				"Makefile": read(t, "../Makefile"), "deploy/dist.sh": read(t, "dist.sh"),
				"LICENSE": "license fixture", "THIRD_PARTY_NOTICES.txt": "notices fixture",
				"go": `#!/bin/sh
set -eu
test "$CGO_ENABLED" = 0
if [ "$PACKAGE_TEST_FAIL" = true ] && [ "$GOOS" = windows ]; then exit 19; fi
while [ "$1" != -o ]; do shift; done
shift
printf '%s/%s' "$GOOS" "$GOARCH" > "$1"
chmod 755 "$1"
`,
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(dir, "dist"), 0755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"SHA256SUMS", "SHA256SUMS.sig"} {
				if err := os.WriteFile(filepath.Join(dir, "dist", name), []byte("previous"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			legacy := "bscan_9.8.7_linux_x86_64"
			if err := os.WriteFile(filepath.Join(dir, "dist", legacy), []byte("legacy binary"), 0755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("make", "dist", "VERSION=9.8.7")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "PACKAGE_TEST_FAIL="+fmt.Sprint(fail), "MAKEFLAGS=", "MFLAGS=")
			out, err := cmd.CombinedOutput()
			if fail {
				if err == nil {
					t.Fatal("compiler failure was ignored")
				}
				for _, name := range []string{"SHA256SUMS", "SHA256SUMS.sig"} {
					if got := read(t, filepath.Join(dir, "dist", name)); got != "previous" {
						t.Fatalf("failed build changed %s: %s", name, got)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("make dist: %v\n%s", err, out)
				}
				sums := read(t, filepath.Join(dir, "dist", "SHA256SUMS"))
				if len(strings.Split(strings.TrimSpace(sums), "\n")) != 6 {
					t.Fatalf("expected five archive checksums plus legacy binary: %s", sums)
				}
				if !strings.Contains(sums, fmt.Sprintf("%x  %s", sha256.Sum256([]byte("legacy binary")), legacy)) {
					t.Fatal("legacy self-update binary lost its checksum")
				}
				for _, target := range []string{"linux_amd64", "linux_arm64", "darwin_arm64", "darwin_amd64", "windows_amd64"} {
					name := "bscan_9.8.7_" + target + ".tar.gz"
					path := filepath.Join(dir, "dist", name)
					data := read(t, path)
					if !strings.Contains(sums, fmt.Sprintf("%x  %s", sha256.Sum256([]byte(data)), name)) {
						t.Errorf("checksum missing or incorrect for %s", name)
					}
					binary := "bscan"
					if strings.HasPrefix(target, "windows_") {
						binary += ".exe"
					}
					gz, err := gzip.NewReader(strings.NewReader(data))
					if err != nil {
						t.Fatal(err)
					}
					tr := tar.NewReader(gz)
					want := map[string]string{binary: strings.ReplaceAll(target, "_", "/"), "LICENSE": files["LICENSE"], "THIRD_PARTY_NOTICES.txt": files["THIRD_PARTY_NOTICES.txt"]}
					for {
						h, err := tr.Next()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(tr)
						if err != nil {
							t.Fatal(err)
						}
						value, ok := want[h.Name]
						if !ok || string(body) != value || h.Typeflag != tar.TypeReg {
							t.Errorf("unexpected archive entry %s: %q", h.Name, body)
						}
						if h.Name == binary && h.Mode&0111 == 0 {
							t.Error("binary is not executable")
						}
						delete(want, h.Name)
					}
					gz.Close()
					if len(want) != 0 {
						t.Errorf("missing archive entries: %v", want)
					}
				}
				if _, err := os.Stat(filepath.Join(dir, "dist", "SHA256SUMS.sig")); !os.IsNotExist(err) {
					t.Fatal("stale checksum signature survived rebuild")
				}
			}
			staging, err := filepath.Glob(filepath.Join(dir, "dist", ".package-*"))
			if err != nil || len(staging) != 0 {
				t.Fatalf("staging directory leaked: %v, %v", staging, err)
			}
		})
	}
}

func TestSystemdSyntax(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd validation runs on Linux")
	}
	validator, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze unavailable")
	}
	standin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true unavailable")
	}
	dir := t.TempDir()
	args := []string{"verify", "--man=no"}
	for _, name := range []string{"bscan-scan.service", "bscan-scan.timer", "bscan-db-update.service", "bscan-db-update.timer"} {
		// verify requires an installed executable but never executes it.
		unit := strings.ReplaceAll(read(t, filepath.Join("systemd", name)), "/usr/local/bin/bscan", standin)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(unit), 0644); err != nil {
			t.Fatal(err)
		}
		args = append(args, path)
	}
	if out, err := exec.Command(validator, args...).CombinedOutput(); err != nil {
		t.Fatalf("invalid systemd units: %v\n%s", err, out)
	}
}

func TestDeploymentContracts(t *testing.T) {
	requireText(t, "../Dockerfile", "FROM --platform=$BUILDPLATFORM", "CGO_ENABLED=0", "GOOS=$TARGETOS", "GOARCH=$TARGETARCH", "FROM scratch", "ca-certificates.crt", "USER 65532:65532", `ENTRYPOINT ["/bscan"]`, "org.opencontainers.image.version", "org.opencontainers.image.source", "org.opencontainers.image.licenses", "BONGSU_HOME=/var/lib/bscan")
	requireText(t, "../.dockerignore", ".git", "dist", "*.key", ".bongsu", "scan-results")
	requireText(t, "../Makefile", "image:", "docker build", "--build-arg VERSION=", "dist:", "deploy/dist.sh")
	for _, unit := range []string{"bscan-scan", "bscan-db-update"} {
		requireText(t, "systemd/"+unit+".service", "User=bscan", "Group=bscan", "DynamicUser=no", "ProtectSystem=strict", "ReadOnlyPaths=/", "ReadWritePaths=/var/lib/bscan", "BONGSU_HOME=/var/lib/bscan", "NoNewPrivileges=yes", "PrivateTmp=yes")
		requireText(t, "systemd/"+unit+".timer", "Persistent=true", "WantedBy=timers.target")
	}
	requireText(t, "systemd/bscan-scan.service", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH", "AmbientCapabilities=CAP_DAC_READ_SEARCH", "--match --report html --output /var/lib/bscan/reports", "--exclude /var/lib/bscan", " host")
	requireText(t, "systemd/bscan-scan.timer", "OnCalendar=daily")
	requireText(t, "systemd/bscan-db-update.service", "/usr/local/bin/bscan db update")
	requireText(t, "systemd/bscan-db-update.timer", "OnCalendar=weekly")
	requireText(t, "cron/bscan", "BONGSU_HOME=/var/lib/bscan", "bscan db update", "bscan scan", "--match --report html")
	requireText(t, "README.md", "useradd", "docker.sock", "--one-file-system", "--exclude", "--workers", "--files=false", "read-only", "docker CLI", "CAP_DAC_READ_SEARCH")
	requireText(t, "../README.md", "## Install and deploy", "SHA256SUMS.sig", "sha256sum", "db export", "db import", "deploy/README.md")
	requireText(t, "../.github/workflows/ci.yml", "os: darwin", "os: windows", "os: freebsd", "GOOS: ${{ matrix.os }}", "go build ./...", "docker build", "deploy/container-smoke.sh")
	requireText(t, "../.github/workflows/release.yml", `make dist VERSION="${TAG#v}"`, "*.tar.gz", "linux/amd64,linux/arm64", "ghcr.io", "packages: write")
}

func TestContainerSmokeVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("container smoke tests run on a POSIX build host")
	}
	script := read(t, "container-smoke.sh")
	for _, version := range []string{"1.2.3", "bscan 1.2.3\nCommit: abc", "bscan 9.9.9"} {
		t.Run(version, func(t *testing.T) {
			dir := t.TempDir()
			fake := `#!/bin/sh
set -eu
for arg do
  case "$arg" in
    version) printf '%s\n' "$SMOKE_TEST_VERSION"; exit 0 ;;
    type=bind,src=*,dst=/reports) output=${arg#type=bind,src=}; output=${output%,dst=/reports} ;;
  esac
done
printf 'bscan-container-fixture' > "$output/input.cdx.json"
printf '{}' > "$output/input.spdx.json"
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fake), 0755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", script, "smoke", "bscan:test", "1.2.3")
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "TMPDIR="+dir, "SMOKE_TEST_VERSION="+version)
			out, err := cmd.CombinedOutput()
			badVersion := strings.Contains(version, "9.9.9")
			if (err != nil) != badVersion {
				t.Fatalf("smoke version validation: %v\n%s", err, out)
			}
			if !badVersion && !strings.Contains(string(out), "directory scan: OK") {
				t.Fatalf("scan was not validated: %s", out)
			}
			fixtures, err := filepath.Glob(filepath.Join(dir, "bscan-container-*"))
			if err != nil || len(fixtures) != 0 {
				t.Fatalf("smoke fixture leaked: %v, %v", fixtures, err)
			}
		})
	}
}
