package scan

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDeclaredReviewProjectPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, lock, installed string
		replace               bool
	}{
		{"unrelated", "apps/old/requirements.txt", "apps/new/.venv/lib/site-packages/requests-2.32.0.dist-info/METADATA", false},
		{"same project", "apps/old/requirements.txt", "apps/old/.venv/lib/site-packages/requests-2.32.0.dist-info/METADATA", true},
		{"prefix sibling", "apps/old/requirements.txt", "apps/older/site-packages/requests-2.32.0.dist-info/METADATA", false},
		{"case distinct projects", "apps/Old/requirements.txt", "apps/old/site-packages/requests-2.32.0.dist-info/METADATA", false},
		{"inside site", "lib/site-packages/service/requirements.txt", "lib/site-packages/requests-2.32.0.dist-info/METADATA", true},
		{"root project", "requirements.txt", "lib/site-packages/requests-2.32.0.dist-info/METADATA", true},
		{"unknown", "", "", false},
	} {
		for _, include := range []bool{false, true} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/include=%t/reverse=%t", tc.name, include, reverse), func(t *testing.T) {
					c := cataloger{includeDeclared: include}
					pkgs := []Package{
						{Name: "requests", Version: "2.19.0", Type: "pypi", Evidence: "lockfile", Source: tc.lock},
						{Name: "requests", Version: "2.32.0", Type: "pypi", Evidence: "installed", Source: tc.installed},
					}
					if reverse {
						pkgs[0], pkgs[1] = pkgs[1], pkgs[0]
					}
					c.addPackages(pkgs)
					got, _ := c.finish()
					wantSkipped := 0
					if tc.replace && !include {
						wantSkipped = 1
					}
					if len(got) != 2-wantSkipped || c.declaredSkipped != wantSkipped {
						t.Fatalf("packages=%+v skipped=%d, want skipped=%d", got, c.declaredSkipped, wantSkipped)
					}
					for _, p := range got {
						if p.Version == "2.19.0" && p.Evidence != "lockfile" {
							t.Fatalf("unbundled declaration evidence=%q", p.Evidence)
						}
					}
				})
			}
		}
	}
}

func TestDeclaredReviewMetadataConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, lock, metadata string
		skipped              bool
	}{
		{"python unconfirmed", "app/site-packages/service/requirements.txt", "", false},
		{"python confirmed", "app/site-packages/service/requirements.txt", "app/site-packages/service-1.0.dist-info/METADATA", true},
		{"python other package", "app/site-packages/service/requirements.txt", "app/site-packages/service_extra-1.0.dist-info/METADATA", false},
		{"python other site", "app/site-packages/service/requirements.txt", "other/site-packages/service-1.0.dist-info/METADATA", false},
		{"python normalized egg", "app/dist-packages/my_service/requirements.txt", "app/dist-packages/my-service.egg-info/PKG-INFO", true},
		{"python egg file", "app/site-packages/service/requirements.txt", "app/site-packages/service.egg-info", true},
		{"gem unconfirmed", "gems/service-2026/requirements.txt", "", false},
		{"gem confirmed", "gems/service-2026/requirements.txt", "specifications/service-2026.gemspec", true},
		{"gem other version", "gems/service-2026/requirements.txt", "specifications/service-2025.gemspec", false},
		{"npm unconfirmed", "app/node_modules/service/requirements.txt", "", false},
		{"npm confirmed", "app/node_modules/service/requirements.txt", "app/node_modules/service/package.json", true},
		{"npm scoped", "app/node_modules/@scope/service/requirements.txt", "app/node_modules/@scope/service/package.json", true},
		{"npm other package", "app/node_modules/service/requirements.txt", "app/node_modules/other/package.json", false},
		{"module cache", "home/dev/go/pkg/mod/example.org/service@v1.0.0/go.mod", "", true},
		{"module cache prefix sibling", "go/pkg/modules/service/go.mod", "", false},
		{"vendor bundle", "vendor/bundle/service/requirements.txt", "", true},
	} {
		for _, include := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/include=%t", tc.name, include), func(t *testing.T) {
				c := cataloger{includeDeclared: include}
				data := "requests==2.19.0\n"
				if strings.HasSuffix(tc.lock, "go.mod") {
					data = "module example.org/app\nrequire example.org/requests v2.19.0\n"
				}
				c.addFile(File{Path: tc.lock, Data: []byte(data)})
				// Metadata existence, even without a parsed package, confirms ownership.
				if tc.metadata != "" {
					c.addFile(File{Path: tc.metadata})
				}
				got, _ := c.finish()
				wantSkipped, evidence := 0, "lockfile"
				if tc.skipped {
					if include {
						evidence = "declared"
					} else {
						wantSkipped = 1
					}
				}
				if len(got) != 1-wantSkipped || c.declaredSkipped != wantSkipped {
					t.Fatalf("packages=%+v skipped=%d", got, c.declaredSkipped)
				}
				if len(got) == 1 && got[0].Evidence != evidence {
					t.Fatalf("evidence=%q want %q", got[0].Evidence, evidence)
				}
			})
		}
	}
}

func TestDeclaredReviewNestedNPMOwner(t *testing.T) {
	outer := "app/node_modules/outer"
	inner := outer + "/node_modules/@scope/workspace"
	for _, tc := range []struct {
		name, manifest string
		skip           bool
	}{
		{"nearest owner has install", inner + "/node_modules/child/package.json", false},
		{"outer install does not back nearest owner", outer + "/node_modules/child/package.json", true},
		{"empty install", inner + "/node_modules/package.json", true},
		{"nonmetadata file", inner + "/node_modules/child/index.js", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cataloger{hasDir: func(string) bool { return true }}
			c.addFile(File{Path: inner + "/requirements.txt", Data: []byte("requests==2.19.0\n")})
			for _, p := range []string{outer + "/package.json", inner + "/package.json", tc.manifest} {
				c.addFile(File{Path: p})
			}
			got, _ := c.finish()
			if (len(got) == 0) != tc.skip {
				t.Fatalf("packages=%+v skip=%t", got, tc.skip)
			}
		})
	}
}

func TestDeclaredReviewPerSourcePrecedence(t *testing.T) {
	c := cataloger{}
	for _, source := range []string{"apps/old/requirements.txt", "apps/new/requirements.txt"} {
		c.addFile(File{Path: source, Data: []byte("requests==2.19.0\n")})
	}
	c.addFile(File{Path: "apps/new/.venv/site-packages/requests-2.32.0.dist-info/METADATA", Data: []byte("Name: requests\nVersion: 2.32.0\n")})
	got, _ := c.finish()
	if len(got) != 2 || got[0].Source != "apps/old/requirements.txt" || c.declaredSkipped != 1 {
		t.Fatalf("packages=%+v skipped=%d", got, c.declaredSkipped)
	}
}

func TestDeclaredReviewAllInstallationSources(t *testing.T) {
	c := cataloger{}
	c.addFile(File{Path: "app/requirements.txt", Data: []byte("requests==2.19.0\n")})
	// The installation in app falls beyond the inventory's source display cap.
	for i := range maxPackageSources + 1 {
		c.addFile(File{Path: fmt.Sprintf("other/%d/site-packages/requests-2.32.0.dist-info/METADATA", i), Data: []byte("Name: requests\nVersion: 2.32.0\n")})
	}
	c.addFile(File{Path: "app/.venv/site-packages/requests-2.32.0.dist-info/METADATA", Data: []byte("Name: requests\nVersion: 2.32.0\n")})
	got, _ := c.finish()
	if len(got) != 1 || got[0].Version != "2.32.0" || c.declaredSkipped != 1 {
		t.Fatalf("packages=%+v skipped=%d", got, c.declaredSkipped)
	}
}

func TestDeclaredReviewMatchingVersionInOtherProject(t *testing.T) {
	c := cataloger{}
	c.addFile(File{Path: "app/requirements.txt", Data: []byte("requests==2.19.0\n")})
	c.addFile(File{Path: "app/.venv/site-packages/requests-2.32.0.dist-info/METADATA", Data: []byte("Name: requests\nVersion: 2.32.0\n")})
	c.addFile(File{Path: "other/site-packages/requests-2.19.0.dist-info/METADATA", Data: []byte("Name: requests\nVersion: 2.19.0\n")})
	got, _ := c.finish()
	if len(got) != 2 || c.declaredSkipped != 1 {
		t.Fatalf("packages=%+v skipped=%d", got, c.declaredSkipped)
	}
	for _, p := range got {
		if strings.Contains(p.Source, "requirements.txt") {
			t.Fatalf("superseded declaration merged into another project's installation: %+v", p)
		}
	}
}

func TestDeclaredReviewIncludePreservesMergeOrder(t *testing.T) {
	for _, installedFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(installedFirst), func(t *testing.T) {
			c := cataloger{includeDeclared: true}
			lock := Package{Type: "npm", Name: "dep", Version: "1", Evidence: "lockfile", Source: "app/package-lock.json", License: "MIT"}
			installed := Package{Type: "npm", Name: "dep", Version: "1", Evidence: "installed", Source: "app/node_modules/dep/package.json", License: "ISC"}
			first, second := lock, installed
			if installedFirst {
				first, second = second, first
			}
			c.addPackages([]Package{first, second})
			lock.Version = "2"
			c.addPackage(lock)
			got, _ := c.finish()
			if len(got) != 2 || c.declaredSkipped != 0 {
				t.Fatalf("packages=%+v skipped=%d", got, c.declaredSkipped)
			}
			if got[0].License != first.License || got[0].Source != first.Source+";"+second.Source || got[0].Evidence != "installed" {
				t.Fatalf("merge order changed: %+v", got[0])
			}
		})
	}
}

func TestDeclaredReviewDirectoryTarParity(t *testing.T) {
	setTestLimit(t, &maxJavaArchive, 1024)
	for _, include := range []bool{false, true} {
		for _, workers := range []int{1, 4} {
			for _, partial := range []bool{false, true} {
				t.Run(fmt.Sprintf("include=%t/workers=%d/partial=%t", include, workers, partial), func(t *testing.T) {
					files := map[string][]byte{
						"app/node_modules/service/package.json":        []byte(`{"name":"service","version":"1.0.0"}`),
						"app/node_modules/service/requirements.txt":    []byte("requests==2.19.0\n"),
						"gems/service-2026/Gemfile.lock":               []byte("GEM\n  specs:\n    rake (13.0.6)\n"),
						"app/site-packages/service/requirements.txt":   []byte("urllib3==1.0\n"),
						"go/pkg/mod/example.org/service@v1.0.0/go.mod": []byte("module example.org/service\nrequire example.org/dep v1.0.0\n"),
					}
					if partial {
						files["oversized/app.jar"] = bytes.Repeat([]byte("#"), int(maxJavaArchive)+1)
					}
					root := t.TempDir()
					var buf bytes.Buffer
					tw := tar.NewWriter(&buf)
					for name, data := range files {
						p := filepath.Join(root, filepath.FromSlash(name))
						if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(p, data, 0o644); err != nil {
							t.Fatal(err)
						}
						if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
							t.Fatal(err)
						}
						if _, err := tw.Write(data); err != nil {
							t.Fatal(err)
						}
					}
					empty := "app/node_modules/service/node_modules"
					if err := os.MkdirAll(filepath.Join(root, empty), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := tw.WriteHeader(&tar.Header{Name: empty + "/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
						t.Fatal(err)
					}
					if err := tw.Close(); err != nil {
						t.Fatal(err)
					}
					archive := writeTemp(t, "declared.tar", buf.Bytes())
					var logs [2][]string
					var results [2]Result
					for i := range results {
						opts := Options{Workers: workers, SkipBinaries: true, IncludeDeclared: include, Progress: func(p Progress) { logs[i] = append(logs[i], p.Message) }}
						var err error
						if i == 0 {
							results[i], err = Directory(root, "fixture", opts)
						} else {
							results[i], err = Archive(archive, opts)
						}
						if err != nil {
							t.Fatal(err)
						}
						wantSkipped := 2
						if include {
							wantSkipped = 0
						}
						m := results[i].Scan
						if m == nil {
							m = &ScanMetadata{}
						}
						if m.Partial != partial || m.DeclaredSkipped != wantSkipped {
							t.Fatalf("input=%d scan=%+v", i, m)
						}
						if !include {
							joined := strings.Join(logs[i], "\n")
							if !strings.Contains(joined, "skipped 2 declared dependencies by policy (use --include-declared to keep them)") {
								t.Fatalf("input=%d logs=%s", i, joined)
							}
							if partial && !strings.Contains(joined, "declared-skipped=2 (policy exclusions)") {
								t.Fatalf("partial reason missing policy count: %s", joined)
							}
						}
					}
					if !reflect.DeepEqual(results[0].Packages, results[1].Packages) {
						t.Fatalf("directory=%+v tar=%+v", results[0].Packages, results[1].Packages)
					}
				})
			}
		}
	}
}
