package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSecurityExpandPaths(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("HOME-based platform")
	}
	home, configDir := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BONGSU_HOME", "  "+configDir+"  ")
	for _, tc := range []struct{ input, want string }{
		{"", filepath.Join(configDir, "signing.key")},
		{" key.pem ", filepath.Join(configDir, "key.pem")},
		{"~", home}, {"~/keys/private", filepath.Join(home, "keys/private")},
		{filepath.Join(home, "absolute"), filepath.Join(home, "absolute")},
	} {
		if got, err := Expand(tc.input); err != nil || got != tc.want {
			t.Errorf("Expand(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	t.Setenv("BONGSU_HOME", "\t ")
	if got, err := Dir(); err != nil || got != filepath.Join(home, ".bongsu") {
		t.Fatalf("default directory = %q, %v", got, err)
	}
	t.Setenv("HOME", "")
	if _, err := Dir(); err == nil {
		t.Fatal("missing home accepted")
	}
	if _, err := Expand("key"); err == nil {
		t.Fatal("expansion with missing home succeeded")
	}
	if _, _, _, err := LoadWithWarnings(); err == nil {
		t.Fatal("load with missing home succeeded")
	}
	if err := Save(Defaults()); err == nil {
		t.Fatal("save with missing home succeeded")
	}
	if _, err := InitTemplate(); err == nil {
		t.Fatal("init with missing home succeeded")
	}
	t.Setenv("BONGSU_HOME", configDir)
	if _, err := Expand("~/key"); err == nil {
		t.Fatal("tilde expansion with missing home succeeded")
	}
}

func TestSecurityConfigFilesystemErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "regular")
	if err := os.WriteFile(file, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BONGSU_HOME", filepath.Join(file, "child"))
	if err := Save(Defaults()); err == nil {
		t.Fatal("save through regular file succeeded")
	}
	if _, err := InitTemplate(); err == nil {
		t.Fatal("init through regular file succeeded")
	}
	t.Setenv("BONGSU_HOME", dir)
	if err := os.Mkdir(filepath.Join(dir, "scaner.yaml"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadWithWarnings(); err == nil {
		t.Fatal("directory accepted as configuration")
	}
	if err := Save(Defaults()); err == nil {
		t.Fatal("save over directory succeeded")
	}
	if raw, err := os.ReadFile(file); err != nil || string(raw) != "preserve" {
		t.Fatalf("unrelated file changed: %q, %v", raw, err)
	}
}
