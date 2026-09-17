package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

func TestSecondReviewDBVerifyRecoveredTrust(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		name := "untrusted"
		if trusted {
			name = "trusted"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("BONGSU_HOME", t.TempDir())
			dir := privateCLITestDB(t)
			pub, priv, err := sign.Generate()
			if err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(dir, "manifest.sha256")
			digest, err := sign.FileDigest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			record, err := sign.Create(digest, "manifest.sha256", "fixture", priv, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := sign.WriteRecord(manifest+".sig", record); err != nil {
				t.Fatal(err)
			}
			if trusted {
				pem, err := sign.MarshalPublic(pub)
				if err != nil {
					t.Fatal(err)
				}
				keyPath := filepath.Join(t.TempDir(), "key.pub")
				if err := os.WriteFile(keyPath, pem, 0600); err != nil {
					t.Fatal(err)
				}
				cfg := config.Defaults()
				cfg.PublicKey = keyPath
				if err := config.Save(cfg); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(dir, dir+".prev"); err != nil {
				t.Fatal(err)
			}
			err = cmdDB(context.Background(), []string{"verify", "--db", dir})
			if trusted && err != nil {
				t.Fatal(err)
			}
			if !trusted && err == nil {
				t.Fatal("recovered untrusted signature accepted as unsigned")
			}
			if _, err := os.Stat(manifest); err != nil {
				t.Fatal("catalog was not recovered", err)
			}
		})
	}
}
