package main

import (
	"strings"
	"testing"
)

func TestFindingsExitCodeOption(t *testing.T) {
	opts, rest, err := parseGlobalFlags([]string{"--findings-exit-code", "7", "match", "x"})
	if err != nil || opts.findingsExit != 7 || len(rest) != 2 {
		t.Fatalf("parse: %v %+v %v", err, opts, rest)
	}
	restore, err := applyGlobalFlags(opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := exitCode(&findingsError{threshold: "HIGH"}); got != 7 {
		t.Fatalf("findings exit code = %d, want 7", got)
	}
	restore()
	if got := exitCode(&findingsError{threshold: "HIGH"}); got != 2 {
		t.Fatalf("default findings exit code = %d, want 2", got)
	}
	for _, bad := range []string{"0", "130", "200", "-1"} {
		if _, _, err := parseGlobalFlags([]string{"--findings-exit-code", bad, "version"}); err == nil || !strings.Contains(err.Error(), "findings-exit-code") {
			t.Fatalf("%s accepted: %v", bad, err)
		}
	}
}

func TestParseByteSize(t *testing.T) {
	for in, want := range map[string]int64{"512": 512, "512MiB": 512 << 20, "1GiB": 1 << 30, "1 GB": 1 << 30, "64m": 64 << 20, "2k": 2048, "3TB": 3 << 40} {
		got, err := parseByteSize(in)
		if err != nil || got != want {
			t.Fatalf("%q → %d, %v (want %d)", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "-5", "0", "1.5G"} {
		if _, err := parseByteSize(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, _, err := parseGlobalFlags([]string{"--memory-limit", "nonsense", "version"}); err == nil || !strings.Contains(err.Error(), "memory-limit") {
		t.Fatalf("bad memory limit accepted: %v", err)
	}
}
