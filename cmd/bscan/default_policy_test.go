package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	matcher "github.com/ziozzang/bongsu-scanner/internal/match"
)

func TestDefaultPolicyCLI(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	db := distroPolicyDB(t, "unimportant")
	input := filepath.Join(t.TempDir(), "input.cdx.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"match", "scan", "batch"} {
		for _, tc := range []struct {
			name     string
			flags    []string
			severity string
			code     int
			notice   bool
		}{
			{"default", nil, "NEGLIGIBLE", 0, false},
			{"cvss", []string{"--severity-source", "cvss"}, "CRITICAL", 2, false},
			{"exclude", []string{"--exclude-unimportant"}, "", 0, false},
			{"exclude-cvss", []string{"--exclude-unimportant", "--severity-source", "cvss"}, "", 0, false},
			{"minimum", []string{"--min-severity", "LOW"}, "", 0, false},
			{"minimum-cvss", []string{"--min-severity", "LOW", "--severity-source", "cvss"}, "CRITICAL", 2, false},
			{"deprecated", []string{"--include-unimportant"}, "NEGLIGIBLE", 0, true},
			{"deprecated-false", []string{"--include-unimportant=false"}, "NEGLIGIBLE", 0, true},
			{"deprecated-repeated", []string{"--include-unimportant", "--include-unimportant=false"}, "NEGLIGIBLE", 0, true},
			{"both", []string{"--exclude-unimportant", "--include-unimportant"}, "", 0, true},
			{"both-reversed", []string{"--include-unimportant", "--exclude-unimportant"}, "", 0, true},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				out := t.TempDir()
				output := filepath.Join(out, "findings.json")
				args := []string{command, "--db", db, "--fail-on", "HIGH"}
				target := input
				if command == "match" {
					args = append(args, "--format", "json", "-o", output)
				} else {
					args = append(args, "--match", "--no-sign", "--output", out)
					target = scanMatchFixture(t)
					// Inventory an installed package without depending on lockfile policy.
					pkg := filepath.Join(target, "node_modules", "fixture")
					if err := os.MkdirAll(pkg, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"fixture","version":"1.0.0"}`), 0600); err != nil {
						t.Fatal(err)
					}
				}
				args = append(args, tc.flags...)
				args = append(args, target)
				_, stderr, err := captureCommandStreams(t, func() error { return run(context.Background(), args) })
				if exitCode(err) != tc.code {
					t.Fatalf("exit=%d want=%d: %v", exitCode(err), tc.code, err)
				}
				notices := strings.Count(stderr, "--include-unimportant is deprecated")
				if notices != map[bool]int{false: 0, true: 1}[tc.notice] {
					t.Fatalf("notice count=%d: %s", notices, stderr)
				}
				if command != "match" {
					paths, err := filepath.Glob(filepath.Join(out, "*.findings.json"))
					if err != nil || len(paths) != 1 {
						t.Fatalf("paths=%v: %v", paths, err)
					}
					output = paths[0]
				}
				data, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				var r matcher.Report
				if err := json.Unmarshal(data, &r); err != nil {
					t.Fatal(err)
				}
				if tc.severity == "" {
					if len(r.Findings) != 0 {
						t.Fatalf("filter: %+v", r)
					}
				} else if len(r.Findings) != 1 || r.Findings[0].Severity != tc.severity || r.Findings[0].DistroSeverity != "unimportant" {
					t.Fatalf("policy: %+v", r)
				}
			})
		}
	}
}

func TestDefaultPolicyCompletion(t *testing.T) {
	for _, command := range commandRegistry() {
		if command.Path != "match" && command.Path != "scan" && command.Path != "batch" {
			continue
		}
		flags := map[string]commandFlag{}
		for _, f := range command.Flags {
			flags[f.Name] = f
		}
		if flags["severity-source"].Default != "distro" || flags["exclude-unimportant"].Kind != "bool" || !strings.Contains(flags["include-unimportant"].Description, "deprecated") {
			t.Errorf("%s policy flags: %+v", command.Path, flags)
		}
	}
}
