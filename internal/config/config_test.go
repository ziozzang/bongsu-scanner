package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	want := Defaults()
	want.Signer = "ziozzang@gmail.com"
	want.PrivateKey = "private key.pem"
	want.TrustedKeys["release"] = "abcdef"
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got, path, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Signer != want.Signer || got.PrivateKey != want.PrivateKey || got.TrustedKeys["release"] != "abcdef" {
		t.Fatalf("round trip = %#v", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions: %v %#o", err, info.Mode().Perm())
	}
	if filepath.Base(path) != "scaner.yaml" {
		t.Fatalf("path = %s", path)
	}
}
