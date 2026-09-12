package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	hashutil "github.com/ziozzang/bongsu-scanner/internal/hash"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

// signature_min_version: 2 must make verify reject legacy v1 records whose
// signer/target labels are not authenticated.
func TestVerifyRejectsV1WhenMinVersionIs2(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BONGSU_HOME", home)
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.SignatureMinVersion = 2
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "artifact")
	if err := os.WriteFile(target, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := hashutil.File(target)
	if err != nil {
		t.Fatal(err)
	}
	record, err := sign.Create(digest, "artifact", "fixture-signer", priv, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	v2Path := target + ".v2.sig"
	if err := sign.WriteRecord(v2Path, record); err != nil {
		t.Fatal(err)
	}
	record.Version = 1
	message := "bongsu-signature-v1\nsha256:" + digest + "\nsigned-at:" +
		record.SignedAt.UTC().Format(time.RFC3339Nano) + "\nsalt:" + record.Salt + "\n"
	record.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(message)))
	v1Path := target + ".sig"
	if err := sign.WriteRecord(v1Path, record); err != nil {
		t.Fatal(err)
	}
	// v2 record verifies; the v2 .sig names target "artifact", so run from dir.
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(pub)
	err = run(context.Background(), []string{"verify", "--pubkey", key, v1Path})
	if err == nil || !strings.Contains(err.Error(), "signature_min_version") {
		t.Fatalf("v1 record must be rejected under signature_min_version=2, got %v", err)
	}
	if err := run(context.Background(), []string{"verify", "--pubkey", key, v2Path}); err != nil {
		t.Fatalf("v2 record must verify: %v", err)
	}
}
