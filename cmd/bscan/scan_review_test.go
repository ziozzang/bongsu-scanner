package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReviewScanCancellationBeforeOutputs(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	dir, output := t.TempDir(), t.TempDir()
	marker := filepath.Join(dir, "started")
	t.Setenv("B1_DOCKER_STARTED", marker)
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\ntouch \"$B1_DOCKER_STARTED\"\nexec sleep 30\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := scanOne(ctx, "host", scanFlags{format: "both", output: output, sign: true, maxFiles: 1, containers: true, skipBinaries: true, noHostMetadata: true})
		done <- err
	}()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	waiting := true
	for waiting {
		select {
		case err := <-done:
			t.Fatalf("scan ended before docker enumeration: %v", err)
		case <-deadline.C:
			cancel()
			<-done
			t.Fatal("docker enumeration did not start")
		case <-tick.C:
			if _, err := os.Stat(marker); err == nil {
				waiting = false
			}
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("scan error=%v", err)
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cancelled scan wrote/signed output: %v", entries)
	}
}

func TestReviewScanContainerEnumerationError(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\necho unavailable >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, err := scanOne(context.Background(), "host", scanFlags{format: "cyclonedx", output: t.TempDir(), noSign: true, maxFiles: 1, containers: true, skipBinaries: true, noHostMetadata: true})
	if err == nil {
		t.Fatal("explicit container enumeration failure succeeded")
	}
}
