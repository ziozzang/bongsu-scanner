package main

import (
	"context"
	"strings"
	"testing"
)

func TestUbuntuPriorityExclusionHelp(t *testing.T) {
	for _, command := range []string{"match", "scan", "batch"} {
		stdout, stderr, err := captureCommandStreams(t, func() error { return run(context.Background(), []string{command, "-h"}) })
		if err != nil || !strings.Contains(stdout+stderr, "exclude advisories the distribution rates unimportant or negligible") {
			t.Fatalf("%s help: %s%s; %v", command, stdout, stderr, err)
		}
	}
}
