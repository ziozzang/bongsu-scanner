package config

import (
	"os"
	"strings"
	"testing"
)

func TestR17ExplicitDefaultPin(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	path, err := InitTemplate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"max_feed_bytes", "max_feed_uncompressed"} {
		if !strings.Contains(string(b), "  # "+key+":") {
			t.Fatalf("template missing commented %s", key)
		}
	}
	b = []byte(strings.ReplaceAll(string(b), "  # max_feed", "  max_feed"))
	// Strip template prose when explicitly pinning the two values.
	b = []byte(strings.ReplaceAll(string(b), "  (built-in default; uncomment to override)", ""))
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{saved, Marshal(cfg)} {
		for _, key := range []string{"max_feed_bytes", "max_feed_uncompressed"} {
			if !strings.Contains(string(data), "\n  "+key+":") {
				t.Errorf("explicit %s lost", key)
			}
		}
	}
}
