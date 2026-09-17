package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every global flag accepted by the parser must be discoverable in the
// hand-written root help (acceptance defect D10).
func TestRootHelpListsEveryGlobalFlag(t *testing.T) {
	var options globalFlags
	fs := globalFlagSet(&options)
	help := captureStdout(t, usage)
	fs.VisitAll(func(f *flag.Flag) {
		dash := "--"
		if len(f.Name) == 1 {
			dash = "-"
		}
		if !strings.Contains(help, dash+f.Name) {
			t.Errorf("root help does not mention %s%s", dash, f.Name)
		}
	})
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	os.Stdout = old
	_ = w.Close()
	return <-done
}

// run restores --findings-exit-code before returning; the status chosen
// while the flag applied must survive into main's exit (acceptance defect D9).
func TestRunPinsFindingsExitStatus(t *testing.T) {
	err := run(context.Background(), []string{"-q", "--findings-exit-code", "7", "match", "--fail-on", "HIGH", "--db", t.TempDir(), "missing.cdx.json"})
	if err == nil {
		t.Fatal("expected an error for a missing SBOM")
	}
	if got := processExitCode(err); got != 1 {
		t.Fatalf("usage error exit = %d, want 1: %v", got, err)
	}
	if got := processExitCode(&exitStatusError{code: 7, err: &findingsError{threshold: "HIGH"}}); got != 7 {
		t.Fatalf("pinned status = %d, want 7", got)
	}
	if got := processExitCode(&findingsError{threshold: "HIGH"}); got != 2 {
		t.Fatalf("default status = %d, want 2", got)
	}
	var found *findingsError
	wrapped := &exitStatusError{code: 7, err: &findingsError{threshold: "HIGH"}}
	if !errors.As(wrapped, &found) || wrapped.Error() != found.Error() {
		t.Fatal("pinned error must unwrap to the findings error")
	}
}

// The status must reach the operating system: the acceptance test observed
// exit 2 from a real process despite --findings-exit-code 7.
func TestFindingsExitCodeReachesProcessExit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BONGSU_HOME", home)
	if err := cmdInit([]string{"--signer", "findings-exit-test"}); err != nil {
		t.Fatal(err)
	}
	db, target := cliTestDB(t), scanMatchFixture(t)
	err := run(context.Background(), []string{"-q", "--findings-exit-code", "7", "scan", "--no-sign", "--output", t.TempDir(),
		"--match", "--db", db, "--fail-on", "high", target})
	var found *findingsError
	if !errors.As(err, &found) {
		t.Fatalf("expected findings error, got %v", err)
	}
	if got := processExitCode(err); got != 7 {
		t.Fatalf("in-process status = %d, want 7", got)
	}
	_, stderr, code := polishCLI(t, home, "-q", "--findings-exit-code", "7", "scan", "--no-sign", "--output", t.TempDir(),
		"--match", "--db", db, "--fail-on", "high", target)
	if code != 7 {
		t.Fatalf("process exit = %d, want 7: %s", code, stderr)
	}
}

// Coverage-gap warnings must survive --quiet: a silent exit 0 with nothing
// matched would read as "no vulnerabilities".
func TestQuietKeepsCoverageWarnings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BONGSU_HOME", home)
	if err := cmdInit([]string{"--signer", "quiet-warning-test"}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "input.cdx.json")
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"missing","version":"1","purl":"pkg:pypi/missing@1"}]}`
	if err := os.WriteFile(input, []byte(sbom), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := polishCLI(t, home, "-q", "match", "--db", cliTestDB(t), input)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "WARNING: coverage gap: PyPI") {
		t.Fatalf("coverage warning suppressed by -q: %q", stderr)
	}
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if !strings.Contains(line, "WARNING") {
			t.Fatalf("progress leaked under -q: %q", line)
		}
	}
}
