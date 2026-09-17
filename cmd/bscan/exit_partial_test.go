package main

import (
	"context"
	"errors"
	"testing"
)

// --fail-on-partial maps to exit code 3, distinct from hard errors (1),
// findings above --fail-on (2), and interruption (130).
func TestExitCodePartialScan(t *testing.T) {
	if got := exitCode(&partialScanError{target: "host", denied: 3}); got != 3 {
		t.Fatalf("partial scan exit code = %d, want 3", got)
	}
	wrapped := errors.Join(errors.New("other"), &partialScanError{target: "dir"})
	if got := exitCode(wrapped); got != 3 {
		t.Fatalf("wrapped partial scan exit code = %d, want 3", got)
	}
	if got := exitCode(context.Canceled); got != 130 {
		t.Fatalf("cancel exit code = %d, want 130", got)
	}
	if got := exitCode(errors.New("boom")); got != 1 {
		t.Fatalf("generic exit code = %d, want 1", got)
	}
}
