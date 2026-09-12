package main

import (
	"archive/tar"
	"bytes"
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

func TestScanCLIPrintsConfigWarnings(t *testing.T) {
	for _, command := range []string{"scan", "batch"} {
		t.Run(command, func(t *testing.T) {
			t.Setenv("BONGSU_HOME", t.TempDir())
			path, err := config.Path()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("unknown_cli_setting: true\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			log, err := captureBatchStderr(t, func() error {
				return run(context.Background(), []string{command, "--output", t.TempDir(), t.TempDir()})
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(log, "warning:") || !strings.Contains(log, `unknown configuration key "unknown_cli_setting"`) {
				t.Fatalf("missing CLI configuration warning: %s", log)
			}
		})
	}
}

func TestDirectoryProducesOnlySignedSBOMs(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	source := t.TempDir()
	output := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "go.mod"), []byte("module test\nrequire example.com/a v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := scanOne(context.Background(), source, scanFlags{format: "both", output: output, sign: true, files: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("outputs = %#v", files)
	}
	for _, file := range files {
		if strings.HasSuffix(file, ".sha256") || strings.HasSuffix(file, ".layers.sha256") {
			t.Fatalf("directory scan created SHA manifest: %s", file)
		}
	}
	for _, suffix := range []string{".spdx.json", ".cdx.json"} {
		sbomPath := findSuffix(t, files, suffix)
		sigPath := findSuffix(t, files, suffix+".sig")
		record, err := sign.ReadRecord(sigPath)
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := hashutil.File(sbomPath)
		if record.DigestSHA256 != digest {
			t.Fatalf("%s signature does not cover SBOM", suffix)
		}
	}
	pubKey := filepath.Join(os.Getenv("BONGSU_HOME"), "signing.pub")
	signatures := []string{
		findSuffix(t, files, ".spdx.json.sig"),
		findSuffix(t, files, ".cdx.json.sig"),
	}
	verifyArgs := append([]string{"--pubkey", pubKey}, signatures...)
	if err := cmdCheck(context.Background(), verifyArgs, true); err != nil {
		t.Fatalf("multi-signature verify: %v", err)
	}
	t.Setenv("BONGSU_HOME", t.TempDir())
	if err := cmdCheck(context.Background(), signatures, true); err == nil {
		t.Fatal("verify accepted an untrusted embedded key")
	}
	if err := cmdCheck(context.Background(), verifyArgs, true); err != nil {
		t.Fatalf("explicit pinned verification failed: %v", err)
	}
	if err := os.WriteFile(findSuffix(t, files, ".spdx.json"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdCheck(context.Background(), verifyArgs, true); err == nil {
		t.Fatal("verify accepted a modified SBOM")
	}
}

func TestConfiguredIdentityAutoSignsAndNoSignOverrides(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	if err := cmdInit([]string{"--signer", "scanner@example.com"}); err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "go.mod"), []byte("module auto.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	autoOutput := t.TempDir()
	files, err := scanOne(context.Background(), source, scanFlags{format: "both", output: autoOutput, files: true})
	if err != nil {
		t.Fatal(err)
	}
	if countSuffix(files, ".json.sig") != 2 {
		t.Fatalf("configured identity did not auto-sign: %#v", files)
	}

	unsignedOutput := t.TempDir()
	files, err = scanOne(context.Background(), source, scanFlags{format: "both", output: unsignedOutput, files: true, noSign: true})
	if err != nil {
		t.Fatal(err)
	}
	if countSuffix(files, ".sig") != 0 {
		t.Fatalf("--no-sign produced signatures: %#v", files)
	}
}

func TestConflictingSignFlagsRejected(t *testing.T) {
	_, err := scanOne(context.Background(), t.TempDir(), scanFlags{
		format: "both", output: t.TempDir(), files: true, sign: true, noSign: true,
	})
	if err == nil {
		t.Fatal("--sign with --no-sign was accepted")
	}
}

func TestArchiveProducesAndSignsSHAManifest(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	source := filepath.Join(t.TempDir(), "rootfs.tar")
	output := t.TempDir()
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	data := []byte("ID=test\nVERSION_ID=1\n")
	if err := tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := scanOne(context.Background(), source, scanFlags{format: "both", output: output, sign: true, files: true})
	if err != nil {
		t.Fatal(err)
	}
	manifest := findSuffix(t, files, ".sha256")
	findSuffix(t, files, ".sha256.sig")
	if err := hashutil.Verify(manifest); err != nil {
		t.Fatal(err)
	}
	entries, err := hashutil.Read(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("manifest entries = %#v", entries)
	}
}

func findSuffix(t *testing.T, files []string, suffix string) string {
	t.Helper()
	for _, file := range files {
		if strings.HasSuffix(file, suffix) {
			return file
		}
	}
	t.Fatalf("output suffix %q missing from %#v", suffix, files)
	return ""
}

func countSuffix(files []string, suffix string) int {
	count := 0
	for _, file := range files {
		if strings.HasSuffix(file, suffix) {
			count++
		}
	}
	return count
}

func TestVerifyLabelsLegacySignerUnauthenticated(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
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
			if version == 1 {
				record.Version = 1
				message := "bongsu-signature-v1\nsha256:" + digest + "\nsigned-at:" +
					record.SignedAt.UTC().Format(time.RFC3339Nano) + "\nsalt:" + record.Salt + "\n"
				record.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(message)))
				// A legacy record can carry a changed label without invalidating its signature.
				record.Signer = "changed-signer"
			}
			path := target + ".sig"
			if err := sign.WriteRecord(path, record); err != nil {
				t.Fatal(err)
			}
			out, err := os.CreateTemp(dir, "stdout")
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			old := os.Stdout
			os.Stdout = out
			defer func() { os.Stdout = old }()
			if err := run(context.Background(), []string{"verify", "--pubkey", hex.EncodeToString(pub), path}); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(out.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), "signer="+record.Signer) {
				t.Fatalf("signer missing: %s", b)
			}
			warning := "(unauthenticated: v1 record)"
			if strings.Contains(string(b), warning) != (version == 1) {
				t.Fatalf("version %d: unexpected signer authentication label: %s", version, b)
			}
		})
	}
}
