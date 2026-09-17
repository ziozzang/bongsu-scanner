package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

func TestCIShortGatesBeforeFixtures(t *testing.T) {
	for file, names := range map[string][]string{
		"walk_parallel_test.go":                    {"TestWalkParallel50000Equality"},
		"../sbom/stream_test.go":                   {"TestStreamingByteIdentity", "TestRealResultByteIdentity"},
		"../match/match_test.go":                   {"TestExistingHostSBOMs", "TestHostFixtureOSParity"},
		"../match/performance_test.go":             {"TestRealInputProfile"},
		"../vulndb/sqlite_catalog_measure_test.go": {"TestSQLiteRealCatalogRebuild"},
		"../vulndb/update_perf_test.go":            {"TestPerformanceUpdate", "TestPerformanceLookups", "TestPerformanceConvert"},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			t.Run(name, func(t *testing.T) {
				for _, decl := range f.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Name.Name != name {
						continue
					}
					if len(fn.Body.List) == 0 {
						t.Fatal("empty test")
					}
					gate, ok := fn.Body.List[0].(*ast.IfStmt)
					if !ok {
						t.Fatal("short gate must precede fixture construction")
					}
					call, ok := gate.Cond.(*ast.CallExpr)
					if !ok {
						t.Fatal("missing testing.Short call")
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || selector.Sel.Name != "Short" {
						t.Fatal("missing testing.Short call")
					}
					pkg, ok := selector.X.(*ast.Ident)
					if !ok || pkg.Name != "testing" {
						t.Fatal("missing testing.Short call")
					}
					if len(gate.Body.List) != 1 {
						t.Fatal("short gate must only skip")
					}
					expr, ok := gate.Body.List[0].(*ast.ExprStmt)
					if !ok {
						t.Fatal("missing skip")
					}
					skip, ok := expr.X.(*ast.CallExpr)
					if !ok {
						t.Fatal("missing skip")
					}
					method, ok := skip.Fun.(*ast.SelectorExpr)
					if !ok || method.Sel.Name != "Skip" {
						t.Fatal("missing skip")
					}
					return
				}
				t.Fatal("test not found")
			})
		}
	}
}

func TestCIMakeTargets(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make unavailable")
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target string
		dirty  bool
	}{{"test-short", false}, {"ci", false}, {"test", false}, {"test-short", true}} {
		t.Run(tc.target+map[bool]string{true: "-dirty"}[tc.dirty], func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range map[string]string{
				"Makefile": string(makefile),
				"go":       "#!/bin/sh\nprintf '%s %s %s %s\\n' \"$*\" \"${CGO_ENABLED-}\" \"${GOOS-}\" \"${GOARCH-}\" >> \"$CI_TEST_LOG\"\n",
				"gofmt":    "#!/bin/sh\nif [ \"$CI_TEST_DIRTY\" = 1 ]; then echo unformatted.go; fi\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(makePath, "-j2", tc.target)
			cmd.Dir = dir
			log := filepath.Join(dir, "commands")
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "CI_TEST_LOG="+log, "CI_TEST_DIRTY="+map[bool]string{true: "1", false: "0"}[tc.dirty], "MAKEFLAGS=", "MFLAGS=")
			out, err := cmd.CombinedOutput()
			if tc.dirty {
				if err == nil || !strings.Contains(string(out), "unformatted.go") {
					t.Fatalf("formatting must fail: %v\n%s", err, out)
				}
				if _, err := os.Stat(log); !os.IsNotExist(err) {
					t.Fatal("ran Go after formatting failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("make: %v\n%s", err, out)
			}
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			commands := string(data)
			want := "test -short -race -count=1 ./..."
			if tc.target == "test" {
				want = "test -race -count=1 ./..."
			}
			if !strings.Contains(commands, want) || !strings.Contains(commands, "vet ./...") {
				t.Fatalf("missing checks: %s", commands)
			}
			if tc.target == "ci" {
				for _, arch := range []string{"amd64", "arm64"} {
					if !strings.Contains(commands, "0 linux "+arch) {
						t.Fatalf("missing static cross build: %s", commands)
					}
				}
				if strings.Index(commands, "build ") < strings.Index(commands, want) {
					t.Fatal("build ran before tests")
				}
			}
		})
	}
}

func TestCIWorkflowContracts(t *testing.T) {
	for file, required := range map[string][]string{
		"ci.yml":      {"push:", "branches: [main]", "pull_request:", "schedule:", "workflow_dispatch:", "go-version-file: go.mod", "cache: true", "gofmt -l .", "go vet ./...", "go test -short -race -count=1 ./...", "timeout-minutes: 20", "timeout-minutes: 45", "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'", "go test -race -count=1 ./...", "arch: [amd64, arm64]", "CGO_ENABLED: '0'", "go mod verify", "golang.org/x/vuln/cmd/govulncheck@latest", "govulncheck ./...", "actions/upload-artifact@"},
		"release.yml": {"tags: ['v*']", "bscan_${TAG#v}_linux_x86_64", "bscan_${TAG#v}_linux_arm64", "contents: write", "go-version-file: go.mod", "cache: true", "BONGSU_RELEASE_KEY: ${{ secrets.BONGSU_RELEASE_KEY }}", "TAG: ${{ github.ref_name }}", "-trimpath", "-s -w -X main.version=$TAG", "sha256sum", "signing.key", "signing.pub", "openssl pkey", "BONGSU_HOME", " sign -o dist/SHA256SUMS.sig dist/SHA256SUMS", "LICENSE THIRD_PARTY_NOTICES.txt", "gh release create", "--verify-tag", "dist/*", "trap ", "umask 077"},
	} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../.github/workflows", file))
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range required {
				if !strings.Contains(string(data), s) {
					t.Errorf("missing workflow contract %q", s)
				}
			}
		})
	}
}

// Execute the exact signing step with a stand-in CLI; the CLI signature format
// itself is covered by internal/sign and cmd/bscan.
func TestCIReleaseSigningStep(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl unavailable")
	}
	data, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, step, ok := strings.Cut(string(data), "      - name: Sign checksums when a release key is configured\n")
	if !ok {
		t.Fatal("signing step missing")
	}
	_, step, ok = strings.Cut(step, "        run: |\n")
	if !ok {
		t.Fatal("signing script missing")
	}
	step, _, _ = strings.Cut(step, "      - name:")
	var script strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(step, "\n"), "\n") {
		script.WriteString(strings.TrimPrefix(line, "          ") + "\n")
	}
	_, private, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key, err := sign.MarshalPrivate(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, key    string
		fail, signed bool
	}{
		{name: "unsigned"}, {name: "signed", key: string(key), signed: true}, {name: "invalid-key", key: "invalid", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dist := filepath.Join(dir, "dist")
			if err := os.Mkdir(dist, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dist, "SHA256SUMS"), []byte("checksums\n"), 0644); err != nil {
				t.Fatal(err)
			}
			fake := `#!/bin/sh
set -eu
test "$1" = sign && test "$2" = -o && test "$3" = dist/SHA256SUMS.sig && test "$4" = dist/SHA256SUMS
test -z "${BONGSU_RELEASE_KEY-}"
test -s "$BONGSU_HOME/signing.key" && test -s "$BONGSU_HOME/signing.pub"
openssl pkey -in "$BONGSU_HOME/signing.key" -pubout | cmp - "$BONGSU_HOME/signing.pub"
printf '%s' "$BONGSU_HOME" > identity-path
printf signed > "$3"
`
			if err := os.WriteFile(filepath.Join(dist, "bscan_0.0.0-test_linux_x86_64"), []byte(fake), 0755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", script.String())
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "TAG=v0.0.0-test", "BONGSU_RELEASE_KEY="+tc.key, "TMPDIR="+dir)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail {
				t.Fatalf("signing: %v\n%s", err, out)
			}
			_, err = os.Stat(filepath.Join(dist, "SHA256SUMS.sig"))
			if (err == nil) != tc.signed {
				t.Fatalf("signature presence: %v", err)
			}
			if tc.signed {
				identity, err := os.ReadFile(filepath.Join(dir, "identity-path"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(string(identity)); !os.IsNotExist(err) {
					t.Fatal("private identity was not removed")
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.IsDir() && entry.Name() != "dist" {
					t.Fatalf("temporary identity leaked: %s", entry.Name())
				}
			}
		})
	}
}
