package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/config"
)

func TestScanConfigFlagPrecedence(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scan = config.ScanConfig{Excludes: []string{"configured", "another"}, OneFileSystem: true, Workers: 7, RedactIP: true, NoHostMetadata: true, SkipBinaries: true, IncludeDeclared: true, Containers: true, FailOnPartial: true, Output: "configured-output", Format: "spdx"}
	cfg.Match = config.MatchConfig{SeveritySource: "max", ExcludeUnimportant: true, MinSeverity: "HIGH", FailOn: "CRITICAL", OnlyFixed: true, DBIsolation: "copy", ReportFormats: []string{"html", "sarif"}}
	for _, explicit := range []bool{false, true} {
		fs := flag.NewFlagSet("scan", flag.ContinueOnError)
		f := addScanFlags(fs)
		args := []string{"--match"}
		if explicit {
			args = append(args, "--exclude=cli", "--exclude=second", "--one-file-system=false", "--workers=0", "--redact-ip=false", "--no-host-metadata=false", "--skip-binaries=false", "--include-declared=false", "--containers=false", "--fail-on-partial=false", "--output=.", "--format=both", "--severity-source=distro", "--exclude-unimportant=false", "--min-severity=", "--fail-on=", "--only-fixed=false", "--db-isolation=none", "--report=")
		}
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		before := fs.NFlag()
		if err := applyScanDefaults(fs, cfg); err != nil {
			t.Fatal(err)
		}
		if fs.NFlag() != before {
			t.Fatal("configuration marked as explicit CLI flag")
		}
		want := map[string]string{"one-file-system": "true", "workers": "7", "redact-ip": "true", "no-host-metadata": "true", "skip-binaries": "true", "include-declared": "true", "containers": "true", "fail-on-partial": "true", "output": "configured-output", "format": "spdx", "severity-source": "max", "exclude-unimportant": "true", "min-severity": "HIGH", "fail-on": "CRITICAL", "only-fixed": "true", "db-isolation": "copy", "report": "html,sarif"}
		excludes := cfg.Scan.Excludes
		if explicit {
			for name := range want {
				want[name] = fs.Lookup(name).DefValue
			}
			want["db-isolation"] = "none"
			excludes = []string{"cli", "second"}
		}
		for name, value := range want {
			if got := fs.Lookup(name).Value.String(); got != value {
				t.Errorf("explicit=%t %s=%q want %q", explicit, name, got, value)
			}
		}
		if !reflect.DeepEqual(f.exclude, excludes) {
			t.Fatalf("excludes=%v want %v", f.exclude, excludes)
		}
	}
	// Configured reports must not opt ordinary scans into database matching.
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	f := addScanFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := applyScanDefaults(fs, cfg); err != nil {
		t.Fatal(err)
	}
	if f.match || f.reports != "" {
		t.Fatalf("unexpected matching: %+v", f.scanMatchFlags)
	}
}

func TestDBConfigFlagPrecedence(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "1")
	cfg := config.Defaults()
	cfg.DB = config.DBConfig{Sources: []string{"osv", "nvd"}, Ecosystems: []string{"Go", "PyPI"}, AlpineReleases: []string{"v3.20"}, NVDYears: "2020-2022", MaxFeedBytes: 123, MaxFeedUncompressed: 456, KeepRaw: false, Mirror: "https://mirror.example"}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		fs := flag.NewFlagSet("db update", flag.ContinueOnError)
		args := []string{}
		want := map[string]string{"source": "osv,nvd", "ecosystem": "Go,PyPI", "alpine-release": "v3.20", "nvd-years": "2020-2022", "mirror": "https://mirror.example", "max-feed-bytes": "123", "max-feed-uncompressed": "456", "no-keep-raw": "true"}
		if explicit {
			want = map[string]string{"source": "", "ecosystem": "", "alpine-release": "", "nvd-years": "", "mirror": "", "max-feed-bytes": "1073741824", "max-feed-uncompressed": "34359738368", "no-keep-raw": "false"}
			for name, value := range want {
				args = append(args, "--"+name+"="+value)
			}
		}
		db := t.TempDir()
		err := cmdDBUpdate(context.Background(), fs, &db, args)
		if err == nil || !strings.Contains(err.Error(), "offline mode") {
			t.Fatalf("err=%v", err)
		}
		for name, value := range want {
			if got := fs.Lookup(name).Value.String(); got != value {
				t.Errorf("explicit=%t %s=%q want %q", explicit, name, got, value)
			}
		}
	}
}

func TestDBConvertConfigKeepRaw(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BONGSU_HOME", home)
	t.Setenv("BONGSU_OFFLINE", "1")
	db := cliTestDB(t)
	writeCommandConfig(t, home, "db:\n  keep_raw: false\n")
	for _, explicit := range []bool{false, true} {
		dest := filepath.Join(t.TempDir(), "converted")
		args := []string{"convert", "--db", db}
		if explicit {
			args = append(args, "--no-keep-raw=false")
		}
		args = append(args, dest)
		if err := cmdDB(context.Background(), args); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(filepath.Join(dest, "raw", "osv", "npm-all.zip"))
		if explicit && err != nil {
			t.Fatalf("CLI did not retain raw feed: %v", err)
		}
		if !explicit && !os.IsNotExist(err) {
			t.Fatalf("config did not omit raw feed: %v", err)
		}
	}
}

func writeCommandConfig(t *testing.T, home, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, "scaner.yaml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigShowAndInitCommands(t *testing.T) {
	home := t.TempDir()
	stdout, stderr, code := polishCLI(t, home, "config", "show")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "  format: \"both\"") || !strings.Contains(stdout, "  keep_raw: true") {
		t.Fatalf("show: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("show created files: %v", entries)
	}
	writeCommandConfig(t, home, "scan:\n  workers: 3\n  typo: true\nmatch:\n  severity_source: max\ndb:\n  keep_raw: false\n")
	stdout, stderr, code = polishCLI(t, home, "config", "show")
	for _, want := range []string{"workers: 3", "severity_source: \"max\"", "keep_raw: false", "format: \"both\"", "max_feed_bytes: 1073741824"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("show lacks %q: %s", want, stdout)
		}
	}
	if code != 0 || !strings.Contains(stderr, "scan.typo") || strings.Contains(stdout, "typo") {
		t.Fatalf("show: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	fresh := t.TempDir()
	stdout, stderr, code = polishCLI(t, fresh, "config", "init")
	if code != 0 || stderr != "" || strings.TrimSpace(stdout) != filepath.Join(fresh, "scaner.yaml") {
		t.Fatalf("init: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	data, err := os.ReadFile(filepath.Join(fresh, "scaner.yaml"))
	if err != nil || !strings.Contains(string(data), "# Defaults for scan") {
		t.Fatalf("template=%s err=%v", data, err)
	}
	if entries, _ := os.ReadDir(fresh); len(entries) != 1 {
		t.Fatalf("init generated signing keys: %v", entries)
	}
	_, _, code = polishCLI(t, fresh, "config", "init")
	if code == 0 {
		t.Fatal("init replaced existing file")
	}
	for _, args := range [][]string{{"config"}, {"config", "invalid"}, {"config", "show", "extra"}} {
		if _, _, code := polishCLI(t, fresh, args...); code == 0 {
			t.Errorf("accepted %v", args)
		}
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		stdout, stderr, code = polishCLI(t, fresh, "completion", shell)
		if code != 0 || stderr != "" || !strings.Contains(stdout, "config/show") || !strings.Contains(stdout, "config/init") {
			t.Fatalf("completion %s: code=%d stderr=%s", shell, code, stderr)
		}
	}
}

func TestConfiguredCommandDefaultsIntegration(t *testing.T) {
	home := t.TempDir()
	target := t.TempDir()
	configuredOutput := t.TempDir()
	cliOutput := t.TempDir()
	writeCommandConfig(t, home, "scan:\n  output: "+configuredOutput+"\n  format: spdx\nmatch:\n  report_formats: [html]\n")
	stdout, stderr, code := polishCLI(t, home, "scan", "--no-sign", target)
	if code != 0 || !strings.Contains(stdout, configuredOutput) || !strings.Contains(stdout, ".spdx.json") || strings.Contains(stdout, ".cdx.json") {
		t.Fatalf("configured scan: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	stdout, stderr, code = polishCLI(t, home, "batch", "--no-sign", "--output", cliOutput, "--format=cyclonedx", target)
	if code != 0 || !strings.Contains(stdout, cliOutput) || !strings.Contains(stdout, ".cdx.json") || strings.Contains(stdout, ".spdx.json") {
		t.Fatalf("CLI batch: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	writeCommandConfig(t, home, "match:\n  severity_source: invalid-policy\n")
	_, stderr, code = polishCLI(t, home, "match", "missing-sbom.json")
	if code != 1 || !strings.Contains(stderr, "invalid-policy") {
		t.Fatalf("configured match: code=%d stderr=%s", code, stderr)
	}
	_, stderr, code = polishCLI(t, home, "match", "--severity-source=distro", "missing-sbom.json")
	if code != 1 || strings.Contains(stderr, "invalid-policy") {
		t.Fatalf("CLI match: code=%d stderr=%s", code, stderr)
	}
	writeCommandConfig(t, home, "db:\n  max_feed_bytes: 0\n")
	_, stderr, code = polishCLI(t, home, "db", "update")
	if code != 1 || !strings.Contains(stderr, "--max-feed-bytes") {
		t.Fatalf("configured db: code=%d stderr=%s", code, stderr)
	}
	_, stderr, code = polishCLI(t, home, "db", "update", "--max-feed-bytes=123")
	if code != 1 || !strings.Contains(stderr, "offline mode") {
		t.Fatalf("CLI db: code=%d stderr=%s", code, stderr)
	}
}
