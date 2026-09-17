package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigShowMasksMirrorCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BONGSU_HOME", home)
	raw := "db:\n  mirror: https://private-user:private-pass@example.com/feed?token=private-token&key=private-key&sig=private-sig&signature=private-signature&password=private-password&region=kr\n"
	writeCommandConfig(t, home, raw)
	stdout, stderr, err := captureCommandStreams(t, func() error { return cmdConfig([]string{"show"}) })
	if err != nil || stderr != "" {
		t.Fatalf("err=%v stderr=%s", err, stderr)
	}
	if strings.Contains(stdout, "private-") {
		t.Fatalf("credentials exposed: %s", stdout)
	}
	if !strings.Contains(stdout, "example.com/feed") || !strings.Contains(stdout, "region=kr") {
		t.Fatalf("mirror context missing: %s", stdout)
	}
	data, err := os.ReadFile(filepath.Join(home, "scaner.yaml"))
	if err != nil || string(data) != raw {
		t.Fatalf("saved config changed: %s %v", data, err)
	}
}
