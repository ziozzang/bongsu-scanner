package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestCPECLIOptIn(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "1")
	db := cliTestDB(t)
	input := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"python","version":"3.12.4","cpe":"cpe:2.3:a:python:python:3.12.4"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdMatch(context.Background(), []string{"--cpe", "--db", db, "--format", "json", "-o", filepath.Join(t.TempDir(), "result.json"), input}); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var f scanMatchFlags
	addScanMatchFlags(fs, &f)
	if f.cpe {
		t.Fatal("CPE enabled by default")
	}
	if err := fs.Parse([]string{"--match", "--cpe", "--db", db}); err != nil {
		t.Fatal(err)
	}
	m, err := prepareScanMatch(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	defer m.store.Close()
	if !m.options.CPE {
		t.Fatal("scan did not forward --cpe")
	}
}
