package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

func TestRegistryScanFlag(t *testing.T) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := addScanFlags(fs)
	if err := fs.Parse([]string{"--insecure-registry"}); err != nil {
		t.Fatal(err)
	}
	if !f.options().InsecureRegistry {
		t.Fatal("flag was not forwarded to scanner")
	}
}

func TestRegistryHelp(t *testing.T) {
	stdout, _, err := captureCommandStreams(t, func() error { usage(); return nil })
	if err != nil || !strings.Contains(stdout, "registry://IMAGE") {
		t.Fatalf("registry target missing from help: %v\n%s", err, stdout)
	}
}
