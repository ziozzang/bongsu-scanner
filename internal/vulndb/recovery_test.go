package vulndb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func interruptedDatabase(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "db")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), Meta{SchemaVersion: SchemaVersion}); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+".prev"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestUpdateAndImportRecoverInterruptedInstall(t *testing.T) {
	for _, command := range []string{"update", "import"} {
		t.Run(command, func(t *testing.T) {
			dir := interruptedDatabase(t)
			var err error
			if command == "update" {
				_, err = Update(context.Background(), dir, Options{Sources: []string{"not-a-source"}})
			} else {
				_, err = Import(filepath.Join(t.TempDir(), "missing.tar.gz"), dir, nil)
			}
			if err == nil {
				t.Fatal("expected subsequent command failure")
			}
			if err := Verify(dir, nil); err != nil {
				t.Fatalf("last valid database not recovered: %v", err)
			}
			if _, err := os.Stat(dir + ".prev"); !os.IsNotExist(err) {
				t.Fatalf("previous generation not restored: %v", err)
			}
		})
	}
}

func TestRecoveryPreservesCorruptPreviousGeneration(t *testing.T) {
	dir := interruptedDatabase(t)
	if err := os.WriteFile(filepath.Join(dir+".prev", "meta.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(context.Background(), dir, Options{Sources: []string{"not-a-source"}}); err == nil {
		t.Fatal("corrupt backup accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("corrupt backup installed: %v", err)
	}
	if _, err := os.Stat(dir + ".prev"); err != nil {
		t.Fatalf("corrupt backup deleted: %v", err)
	}
}
