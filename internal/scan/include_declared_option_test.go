package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// A Gemfile.lock bundled inside an installed gem declares dependencies that
// are not installed: skipped by default (and counted), kept with
// Options.IncludeDeclared.
func TestIncludeDeclaredOption(t *testing.T) {
	root := t.TempDir()
	gems := filepath.Join(root, "usr", "local", "lib", "ruby", "gems", "3.3.0")
	spec := filepath.Join(gems, "specifications")
	inner := filepath.Join(gems, "gems", "rbs-3.4.0")
	for _, d := range []string{spec, inner} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(spec, "rbs-3.4.0.gemspec"), []byte("Gem::Specification.new do |s|\n  s.name = \"rbs\"\n  s.version = \"3.4.0\"\nend\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := "GEM\n  remote: https://rubygems.org/\n  specs:\n    rexml (3.2.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rexml\n"
	if err := os.WriteFile(filepath.Join(inner, "Gemfile.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	names := func(r Result) map[string]string {
		m := map[string]string{}
		for _, p := range r.Packages {
			m[p.Name] = p.Evidence
		}
		return m
	}
	def, err := Directory(root, "fixture", Options{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	got := names(def)
	if _, ok := got["rexml"]; ok {
		t.Fatalf("declared-only rexml must be skipped by default: %v", got)
	}
	if got["rbs"] == "" || def.Scan == nil || def.Scan.DeclaredSkipped != 1 {
		t.Fatalf("installed gem or DeclaredSkipped counter missing: %v scan=%+v", got, def.Scan)
	}
	kept, err := Directory(root, "fixture", Options{Workers: 1, IncludeDeclared: true})
	if err != nil {
		t.Fatal(err)
	}
	if ev := names(kept)["rexml"]; ev != "declared" {
		t.Fatalf("IncludeDeclared must keep rexml with evidence 'declared', got %q (%v)", ev, names(kept))
	}
}
