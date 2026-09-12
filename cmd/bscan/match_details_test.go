package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchDetailsFlag(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	db := cliTestDB(t)
	input := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","bom-ref":"fixture-ref","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, details := range []bool{false, true} {
		out := filepath.Join(t.TempDir(), "out.json")
		args := []string{"--db", db, "--format", "json", "-o", out}
		if details {
			args = append(args, "--details")
		}
		args = append(args, input)
		if err := cmdMatch(context.Background(), args); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var report struct {
			Findings []struct{ Record map[string]any }
		}
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		if len(report.Findings) != 1 {
			t.Fatalf("findings=%d", len(report.Findings))
		}
		rec := report.Findings[0].Record
		if _, ok := rec["affected"]; ok {
			t.Fatal("full advisory embedded")
		}
		if details && rec["details"] != "This vulnerability occurs only on Windows. Linux installations are not affected." {
			t.Fatalf("full details missing: %v", rec)
		}
		if !details && strings.Contains(string(data), `"details"`) {
			t.Fatal("default output includes details")
		}
	}
}
