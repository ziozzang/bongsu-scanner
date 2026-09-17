package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestR27ConfigOverride(t *testing.T) {
	home, custom := t.TempDir(), t.TempDir()
	t.Setenv("BONGSU_HOME", home)
	t.Chdir(custom)
	for _, path := range []string{"nested/custom.yaml", filepath.Join(custom, "absolute.yaml")} {
		t.Run(path, func(t *testing.T) {
			t.Setenv("BONGSU_CONFIG", path)
			want, err := filepath.Abs(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Path()
			if err != nil || got != want {
				t.Fatalf("Path()=%q, %v; want %q", got, err, want)
			}
			if _, err := InitTemplate(); err != nil {
				t.Fatal(err)
			}
			cfg := Defaults()
			cfg.Signer = "custom"
			if err := Save(cfg); err != nil {
				t.Fatal(err)
			}
			loaded, resolved, err := Load()
			if err != nil || resolved != want || loaded.Signer != "custom" {
				t.Fatalf("load=%+v %q %v", loaded, resolved, err)
			}
			key, err := Expand("signing.key")
			if err != nil || key != filepath.Join(home, "signing.key") {
				t.Fatalf("key moved: %q %v", key, err)
			}
			dir, err := Dir()
			if err != nil || dir != home {
				t.Fatalf("home moved: %q %v", dir, err)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(home, "scaner.yaml")); !os.IsNotExist(err) {
		t.Fatalf("default config written: %v", err)
	}
}
