package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestDBUpdateNVDFlags(t *testing.T) {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	var out bytes.Buffer
	fs.SetOutput(&out)
	dir := t.TempDir()
	err := cmdDBUpdate(context.Background(), fs, &dir, []string{"--help"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help = %v", err)
	}
	if !strings.Contains(out.String(), "-nvd-years") || !strings.Contains(out.String(), "nvd (opt-in)") {
		t.Fatalf("NVD flags missing: %s", out.String())
	}
	if err := fs.Parse([]string{"--source", "nvd", "--nvd-years", "2024-2026"}); err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("nvd-years").Value.String() != "2024-2026" {
		t.Fatal("NVD year flag not parsed")
	}
}
