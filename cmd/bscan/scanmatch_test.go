package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	matcher "github.com/ziozzang/bongsu-scanner/internal/match"
)

func scanMatchFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	data := `{"name":"app","lockfileVersion":3,"packages":{"node_modules/fixture":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestScanMatchReportsAndExitCode(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	if err := cmdInit([]string{"--signer", "scan-match-test"}); err != nil {
		t.Fatal(err)
	}
	db, target := cliTestDB(t), scanMatchFixture(t)
	for _, format := range []string{"both", "cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			out := t.TempDir()
			stdout, err := os.CreateTemp(t.TempDir(), "stdout")
			if err != nil {
				t.Fatal(err)
			}
			previous := os.Stdout
			os.Stdout = stdout
			defer func() { os.Stdout = previous; stdout.Close() }()
			log, err := captureBatchStderr(t, func() error {
				return run(context.Background(), []string{"scan", "--sign", "--format", format, "--output", out,
					"--match", "--db", db, "--report", "html,sarif,markdown,csv", "--fail-on", "high", target})
			})
			var found *findingsError
			if exitCode(err) != 2 || !errors.As(err, &found) || found.threshold != "HIGH" {
				t.Fatalf("expected findings exit 2, got %v", err)
			}
			if !strings.Contains(log, "[scan:match] ") || !strings.Contains(log, "subjects, 1 findings (critical=1 high=0)") {
				t.Fatalf("missing match summary: %s", log)
			}
			base := filepath.Join(out, safeName(filepath.Base(target)))
			printed, err := os.ReadFile(stdout.Name())
			if err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{".findings.json", ".report.html", ".report.sarif", ".report.md", ".report.csv"} {
				if !strings.Contains(string(printed), base+suffix+"\n") {
					t.Fatalf("output path not listed: %s%s", base, suffix)
				}
				data, err := os.ReadFile(base + suffix)
				if err != nil || !strings.Contains(string(data), "fixture") {
					t.Fatalf("%s: missing fixture: %s (%v)", suffix, data, err)
				}
				if (suffix == ".findings.json" || suffix == ".report.sarif") && !json.Valid(data) {
					t.Fatalf("invalid JSON: %s", data)
				}
				if _, err := os.Stat(base + suffix + ".sig"); !os.IsNotExist(err) {
					t.Fatalf("findings/report must not be signed: %v", err)
				}
			}
			sigs, err := filepath.Glob(base + ".*.json.sig")
			if err != nil || len(sigs) == 0 {
				t.Fatalf("SBOM signatures missing: %v (%v)", sigs, err)
			}
		})
	}
}

func TestScanMatchDefaultDBAndNoThreshold(t *testing.T) {
	db := cliTestDB(t)
	t.Setenv("BONGSU_HOME", filepath.Dir(db))
	out := t.TempDir()
	if err := run(context.Background(), []string{"scan", "--no-sign", "--match", "--output", out, scanMatchFixture(t)}); err != nil {
		t.Fatalf("findings without --fail-on must succeed: %v", err)
	}
	paths, err := filepath.Glob(filepath.Join(out, "*.findings.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("default DB findings: %v (%v)", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil || !bytes.Contains(data, []byte("CVE-2026-12345")) {
		t.Fatalf("default DB not matched: %s (%v)", data, err)
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 3 {
		t.Fatalf("match without --report outputs: %v (%v)", entries, err)
	}
}

func TestScanMatchHostContainersFinishAllReports(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	db := cliTestDB(t)
	fixture, err := os.ReadFile(filepath.Join(scanMatchFixture(t), "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "app/package-lock.json", Mode: 0644, Size: int64(len(fixture))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(fixture); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	export := filepath.Join(dir, "export.tar")
	if err := os.WriteFile(export, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCAN_MATCH_EXPORT", export)
	script := `#!/bin/sh
case "$1 $2" in
  "ps "*) printf 'first\tfirst\nsecond\tsecond\n' ;;
  "container inspect") printf 'abcdef0123456789|sha256:abc|/fixture|running\n' ;;
  "export "*) cp "$SCAN_MATCH_EXPORT" "$3" ;;
  "image inspect") printf '{"Id":"sha256:abc","Os":"linux","Architecture":"amd64"}\n' ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := t.TempDir()
	// Bound the real host walk; container exports still contain the fixture.
	err = run(context.Background(), []string{"scan", "--no-sign", "--output", out,
		"--containers", "--max-files", "1", "--workers", "1", "--skip-binaries", "--no-host-metadata",
		"--match", "--db", db, "--report", "html,sarif", "--fail-on", "HIGH", "host"})
	if exitCode(err) != 2 {
		t.Fatalf("host/container exit: %v", err)
	}
	for _, base := range []string{"host", "host.container-first", "host.container-second"} {
		for _, suffix := range []string{".findings.json", ".report.html", ".report.sarif"} {
			data, err := os.ReadFile(filepath.Join(out, base+suffix))
			if err != nil {
				t.Fatal(err)
			}
			if base != "host" && !bytes.Contains(data, []byte("fixture")) {
				t.Fatalf("container finding absent: %s%s", base, suffix)
			}
		}
	}
}

func TestScanMatchPrefersWrittenCycloneDX(t *testing.T) {
	for _, tc := range []struct {
		paths []string
		want  string
	}{
		{[]string{"root.spdx.json", "root.cdx.json.sig", "root.cdx.json", "root.sha256"}, "root.cdx.json"},
		{[]string{"root.spdx.json", "root.cdx.json.sig"}, "root.spdx.json"},
	} {
		path, base, err := scanMatchSBOM(tc.paths)
		if err != nil || path != tc.want || base != "root" {
			t.Fatalf("SBOM = %q, base = %q, err = %v", path, base, err)
		}
	}
}

func TestScanWithoutMatchWritesOnlySBOMs(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	out := t.TempDir()
	if err := run(context.Background(), []string{"scan", "--no-sign", "--output", out, scanMatchFixture(t)}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 2 {
		t.Fatalf("outputs: %v (%v)", entries, err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".cdx.json") && !strings.HasSuffix(entry.Name(), ".spdx.json") {
			t.Fatalf("unexpected output %s", entry.Name())
		}
	}
}

func TestScanMatchValidationBeforeScanning(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tc := range []struct {
		flags []string
		want  string
	}{
		{[]string{"--report", "html"}, "--report requires --match"},
		{[]string{"--match", "--db", missing}, "no vulnerability database at " + missing + "; run 'bscan db update'"},
		{[]string{"--match", "--db", t.TempDir()}, "no vulnerability database"},
		{[]string{"--match", "--report", "xml"}, "unsupported report format"},
		{[]string{"--match", "--min-severity", "typo"}, "invalid severity"},
		{[]string{"--match", "--fail-on", "typo"}, "invalid severity"},
	} {
		out := filepath.Join(t.TempDir(), "out")
		args := append([]string{"scan", "--no-sign", "--output", out}, tc.flags...)
		args = append(args, filepath.Join(t.TempDir(), "nonexistent-target"))
		log, err := captureBatchStderr(t, func() error { return run(context.Background(), args) })
		if exitCode(err) != 1 || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: want %q, got %v", tc.flags, tc.want, err)
		}
		if strings.Contains(log, "[scan:start]") {
			t.Fatalf("started scanning before validation: %s", log)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("created output before validation: %v", err)
		}
	}
}

func TestScanMatchFiltersAndBatch(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	db := cliTestDB(t)
	for _, version := range []string{"1.0.0", "2.0.0"} {
		t.Run(version, func(t *testing.T) {
			target := scanMatchFixture(t)
			path := filepath.Join(target, "package-lock.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(data), "1.0.0", version)), 0600); err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			err = run(context.Background(), []string{"batch", "--jobs", "2", "--no-sign", "--output", out,
				"--match", "--db", db, "--db-isolation", "copy", "--min-severity", "critical", "--only-fixed", "--include-unimportant",
				"--fail-on", "CRITICAL", target, scanMatchFixture(t)})
			if exitCode(err) != 2 {
				t.Fatalf("batch exit: %v", err)
			}
			paths, err := filepath.Glob(filepath.Join(out, "*.findings.json"))
			if err != nil || len(paths) != 2 {
				t.Fatalf("batch outputs: %v (%v)", paths, err)
			}
			total := 0
			for _, path := range paths {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var r matcher.Report
				if err := json.Unmarshal(data, &r); err != nil {
					t.Fatal(err)
				}
				total += len(r.Findings)
			}
			want := 2
			if version == "2.0.0" {
				want = 1
			}
			if total != want {
				t.Fatalf("findings = %d, want %d", total, want)
			}
		})
	}
}
