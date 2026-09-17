package config

import (
	"strings"
	"testing"
)

func TestMarshalDisplayMirrorCredentials(t *testing.T) {
	for _, raw := range []string{
		"https://private-user:private-pass@example.com/feed?token=private-token&key=private-key&sig=private-sig&signature=private-signature&password=private-password&region=kr",
		"https://private-user@example.com/feed?ToKeN=private-one&ToKeN=private-two&%6bey=private-key&region=kr",
		"https://example.com/feed?password=private%2Dpassword&region=kr",
		"https://private-user:private-pass@example.com/%zz",
		"https://example.com/feed?token=private-token%zz",
		"https://example.com/feed?token=private-token;key=private-key",
		"https:private-user:private-pass@example.com/feed",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("BONGSU_HOME", t.TempDir())
			cfg := Defaults()
			cfg.DB.Mirror = raw
			display := string(MarshalDisplay(cfg))
			// private_key is an unrelated field name; inspect the mirror line.
			for _, line := range strings.Split(display, "\n") {
				if strings.Contains(line, "mirror:") && strings.Contains(line, "private") {
					t.Fatalf("credential leak: %s", line)
				}
			}
			if strings.Contains(raw, "region=kr") && (!strings.Contains(display, "example.com/feed") || !strings.Contains(display, "region=kr")) {
				t.Fatal("lost non-secret URL context")
			}
			if cfg.DB.Mirror != raw || !strings.Contains(string(Marshal(cfg)), raw) {
				t.Fatal("display changed persistence serialization")
			}
			if err := Save(cfg); err != nil {
				t.Fatal(err)
			}
			loaded, _, err := Load()
			if err != nil || loaded.DB.Mirror != raw {
				t.Fatalf("saved mirror=%q err=%v", loaded.DB.Mirror, err)
			}
		})
	}
}

func TestMarshalDisplayPreservesPublicMirror(t *testing.T) {
	cfg := Defaults()
	cfg.DB.Mirror = "https://example.com/feed?z=last&a=first%20value"
	if string(MarshalDisplay(cfg)) != string(Marshal(cfg)) {
		t.Fatal("public configuration changed")
	}
}
