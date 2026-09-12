package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestDBStatusIdentifiesSourceFeeds(t *testing.T) {
	original := os.Stdout
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	os.Stdout = f
	defer func() { os.Stdout = original }()
	meta := vulndb.Meta{Sources: []vulndb.SourceMeta{
		{Name: "osv", Ecosystems: []string{"npm"}, Records: 228915},
		{Name: "osv", Ecosystems: []string{"PyPI"}},
		{Name: "alpine-secdb", URL: "https://secdb.alpinelinux.org/v3.20/main.json"},
	}}
	if err := printDBMeta(meta); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"osv [npm]: 228,915 records", "osv [PyPI]:", "alpine-secdb [https://secdb.alpinelinux.org/v3.20/main.json]:"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
}

func TestDBIsolationCLIFlags(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	db := cliTestDB(t)
	input := filepath.Join(t.TempDir(), "input.cdx.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"auto", "copy", "none", "invalid"} {
		for _, command := range []string{"status", "lookup", "verify", "match"} {
			t.Run(command+"/"+mode, func(t *testing.T) {
				args := []string{command, "--db", db, "--db-isolation", mode}
				if command == "lookup" {
					args = append(args, "npm", "fixture")
				}
				if command == "match" {
					args = append(args, "-o", filepath.Join(t.TempDir(), "out"), input)
				}
				if command != "match" {
					args = append([]string{"db"}, args...)
				}
				err := run(context.Background(), args)
				if mode == "invalid" {
					if err == nil || !strings.Contains(err.Error(), "isolation") {
						t.Fatalf("invalid mode: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
