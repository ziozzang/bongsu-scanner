package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const commandDefaultsYAML = `scan:
  excludes: ["a,b", "path # literal", 'it''s', "[literal]", ""]
  one_file_system: true
  workers: 3
  redact_ip: true
  no_host_metadata: true
  skip_binaries: true
  include_declared: true
  containers: true
  fail_on_partial: true
  output: "/var/lib/bscan output"
  format: cyclonedx
match:
  severity_source: max
  exclude_unimportant: true
  min_severity: HIGH
  fail_on: CRITICAL
  only_fixed: true
  db_isolation: copy
  report_formats: [html, sarif]
db:
  sources: [osv, nvd]
  ecosystems: [Go, PyPI]
  alpine_releases: [v3.20, v3.21]
  nvd_years: 2023-2025
  max_feed_bytes: 123456789
  max_feed_uncompressed: 9876543210
  keep_raw: false
  mirror: "https://mirror.example/osv"
`

func TestCommandDefaultsParseAndRoundTrip(t *testing.T) {
	got, warnings, err := parse("test.yaml", []byte(commandDefaultsYAML))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("warnings=%v err=%v", warnings, err)
	}
	want := Defaults()
	want.Scan = ScanConfig{Excludes: []string{"a,b", "path # literal", "it's", "[literal]", ""}, OneFileSystem: true, Workers: 3, RedactIP: true, NoHostMetadata: true, SkipBinaries: true, IncludeDeclared: true, Containers: true, FailOnPartial: true, Output: "/var/lib/bscan output", Format: "cyclonedx"}
	want.Match = MatchConfig{SeveritySource: "max", ExcludeUnimportant: true, MinSeverity: "HIGH", FailOn: "CRITICAL", OnlyFixed: true, DBIsolation: "copy", ReportFormats: []string{"html", "sarif"}}
	want.DB = DBConfig{Sources: []string{"osv", "nvd"}, Ecosystems: []string{"Go", "PyPI"}, AlpineReleases: []string{"v3.20", "v3.21"}, NVDYears: "2023-2025", MaxFeedBytes: 123456789, MaxFeedUncompressed: 9876543210, Mirror: "https://mirror.example/osv"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
	t.Setenv("BONGSU_HOME", t.TempDir())
	if err := Save(got); err != nil {
		t.Fatal(err)
	}
	again, _, warnings, err := LoadWithWarnings()
	if err != nil || len(warnings) != 0 || !reflect.DeepEqual(again, want) {
		t.Fatalf("round trip=%+v warnings=%v err=%v", again, warnings, err)
	}
}

func TestCommandDefaultsListsAndWarnings(t *testing.T) {
	input := "scan:\n  excludes:\n    - 'a,b'\n    - cache # comment\n  typo:\n    workers: 999\n    arbitrary text\n  workers: 4\n  workers: 5\nmatch:\n  typo: true\n  report_formats:\n    - html\ndb:\n  typo: false\n  sources:\n    - nvd\n  ecosystems:\n    - Go\n  alpine_releases:\n    - v3.20\n"
	cfg, warnings, err := parse("test.yaml", []byte(input))
	if err != nil || len(warnings) != 4 {
		t.Fatalf("warnings=%v err=%v", warnings, err)
	}
	for i, key := range []string{"scan.typo", "scan.workers", "match.typo", "db.typo"} {
		if !strings.Contains(warnings[i], key) || !strings.HasPrefix(warnings[i], "test.yaml:") {
			t.Error(warnings[i])
		}
	}
	if cfg.Scan.Workers != 5 || !reflect.DeepEqual(cfg.Scan.Excludes, []string{"a,b", "cache"}) || !reflect.DeepEqual(cfg.Match.ReportFormats, []string{"html"}) || !reflect.DeepEqual(cfg.DB.Sources, []string{"nvd"}) || !reflect.DeepEqual(cfg.DB.Ecosystems, []string{"Go"}) || !reflect.DeepEqual(cfg.DB.AlpineReleases, []string{"v3.20"}) {
		t.Fatalf("cfg=%+v", cfg)
	}
	again, warnings, err := parse("test.yaml", render(cfg))
	if err != nil || len(warnings) != 0 || !reflect.DeepEqual(cfg, again) {
		t.Fatalf("round trip=%+v warnings=%v err=%v", again, warnings, err)
	}
}

func TestCommandDefaultsBadTypes(t *testing.T) {
	cfg := Defaults()
	for _, block := range []string{"scan", "match", "db"} {
		for _, field := range optionFields(&cfg, block) {
			var bad []string
			switch field.value.(type) {
			case *bool:
				bad = []string{"maybe", "", "2", "[]", "{}"}
			case *int, *int64:
				bad = []string{"oops", "", "1.5", "999999999999999999999999999", "[]", "{}"}
			case *[]string:
				bad = []string{"value", "true", "{}", "[unterminated", "[\"unterminated]", "[a,,b]"}
			case *string:
				bad = []string{"[]", "{}"}
			}
			for _, value := range bad {
				t.Run(block+"."+field.name+"/"+value, func(t *testing.T) {
					_, _, err := parse("bad.yaml", []byte(block+":\n  "+field.name+": "+value+"\n"))
					if err == nil || !strings.Contains(err.Error(), "bad.yaml:2:") || !strings.Contains(err.Error(), block+"."+field.name) {
						t.Fatalf("err=%v", err)
					}
				})
			}
		}
		for _, value := range []string{"true", "[]", "{}"} {
			if _, _, err := parse("bad.yaml", []byte(block+": "+value)); err == nil {
				t.Fatalf("accepted %s: %s", block, value)
			}
		}
	}
}

func TestCommandDefaultsDuplicateBlock(t *testing.T) {
	got, warnings, err := parse("test.yaml", []byte("scan:\n  workers: 5\n  format: spdx\nscan:\n  workers: 2\n"))
	if err != nil || len(warnings) != 1 || got.Scan.Workers != 2 || got.Scan.Format != "both" {
		t.Fatalf("cfg=%+v warnings=%v err=%v", got, warnings, err)
	}
}

func TestInitTemplatePreservesExistingFileAndHasNoKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BONGSU_HOME", filepath.Join(dir, "new"))
	path, err := InitTemplate()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "# Defaults for scan") {
		t.Fatalf("template=%s err=%v", data, err)
	}
	got, warnings, err := parse(path, data)
	if err != nil || len(warnings) != 0 || !reflect.DeepEqual(got, Defaults()) {
		t.Fatalf("cfg=%+v warnings=%v err=%v", got, warnings, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("info=%v err=%v", info, err)
	}
	if _, err := InitTemplate(); !os.IsExist(err) {
		t.Fatalf("overwrite err=%v", err)
	}
	again, _ := os.ReadFile(path)
	if string(again) != string(data) {
		t.Fatal("existing template changed")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("unexpected identity files: %v", entries)
	}
}

// Feed limits at their built-in default are rendered commented out so that
// a raised default in a later release reaches installations initialized
// with an older template; explicit values are kept.
func TestRenderLeavesDefaultFeedLimitsUnpinned(t *testing.T) {
	out := string(render(Defaults()))
	for _, key := range []string{"max_feed_bytes", "max_feed_uncompressed"} {
		if !strings.Contains(out, "  # "+key+": ") {
			t.Fatalf("%s pinned in template: %s", key, out)
		}
	}
	cfg := Defaults()
	cfg.DB.MaxFeedUncompressed = 123
	out = string(render(cfg))
	if !strings.Contains(out, "  max_feed_uncompressed: 123\n") || !strings.Contains(out, "  # max_feed_bytes: ") {
		t.Fatalf("explicit limit lost: %s", out)
	}
	loaded, _, err := parse("scaner.yaml", []byte(out))
	if err != nil || loaded.DB.MaxFeedUncompressed != 123 || loaded.DB.MaxFeedBytes != Defaults().DB.MaxFeedBytes {
		t.Fatalf("round trip: %+v %v", loaded.DB, err)
	}
}
