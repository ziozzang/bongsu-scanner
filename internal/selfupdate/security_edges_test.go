package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestSecurityUpdaterMissingClient(t *testing.T) {
	u := &Updater{}
	ctx := context.Background()
	if _, err := u.Latest(ctx); err == nil {
		t.Fatal("Latest without client succeeded")
	}
	if _, err := u.Checksums(ctx, &Release{}); err == nil {
		t.Fatal("Checksums without client succeeded")
	}
	if _, err := u.Download(ctx, Asset{}, "", t.TempDir()); err == nil {
		t.Fatal("Download without client succeeded")
	}
	if _, err := VerifyChecksums(nil, nil, nil); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("unpinned verification: %v", err)
	}
}

func TestSecurityChecksumsDownloadFailures(t *testing.T) {
	rs, _, _, pub, _ := fixture(t)
	u, _ := rs.updater(pub)
	for name, assets := range map[string][]Asset{
		"missing sums":        nil,
		"sums transport":      {{Name: checksumsAsset, URL: "http://invalid.example"}},
		"empty sums":          {{Name: checksumsAsset, URL: rs.srv.URL + "/dl/empty"}},
		"signature transport": {{Name: checksumsAsset, URL: rs.srv.URL + "/dl/" + checksumsAsset}, {Name: signatureAsset, URL: "http://invalid.example"}},
		"signature cap":       {{Name: checksumsAsset, URL: rs.srv.URL + "/dl/" + checksumsAsset}, {Name: signatureAsset, Size: MaxSignatureBytes + 1}},
	} {
		t.Run(name, func(t *testing.T) {
			rs.assets["empty"] = nil
			got, err := u.Checksums(context.Background(), &Release{Assets: assets})
			if err == nil || got != nil {
				t.Fatalf("checksums = %#v, %v", got, err)
			}
			if strings.Contains(name, "transport") && !errors.Is(err, httpx.ErrInsecureURL) {
				t.Fatalf("transport error = %v", err)
			}
			if name == "signature cap" && !errors.Is(err, httpx.ErrTooLarge) {
				t.Fatalf("size error = %v", err)
			}
		})
	}
}

func TestSecurityDownloadMetadataAndTemporaryFiles(t *testing.T) {
	rs, name, binary, pub, _ := fixture(t)
	u, _ := rs.updater(pub)
	digest := sha256.Sum256(binary)
	want := strings.ToUpper(hex.EncodeToString(digest[:]))
	asset := Asset{Name: name, URL: rs.srv.URL + "/dl/" + name}
	dir := t.TempDir()
	if _, err := u.Download(context.Background(), asset, "short", dir); err == nil {
		t.Fatal("short checksum accepted")
	}
	if _, err := u.Download(context.Background(), asset, want, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing temporary directory accepted")
	}
	asset.Size = int64(len(binary) + 1)
	if _, err := u.Download(context.Background(), asset, want, dir); err == nil || !strings.Contains(err.Error(), "release metadata says") {
		t.Fatalf("metadata mismatch = %v", err)
	}
	if left := leftovers(t, dir); len(left) != 0 {
		t.Fatalf("failed download left %v", left)
	}
	asset.Size = 0
	tmp, err := u.Download(context.Background(), asset, want, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(tmp); err != nil || string(got) != string(binary) {
		t.Fatalf("download = %q, %v", got, err)
	}
}

func TestSecurityReplaceFailurePreservesTarget(t *testing.T) {
	real, link := fakeInstall(t)
	for _, source := range []string{filepath.Join(filepath.Dir(real), "missing"), t.TempDir()} {
		if _, err := Replace(source, link); err == nil {
			t.Fatal("invalid source replaced executable")
		}
		if got, err := os.ReadFile(real); err != nil || string(got) != "old" {
			t.Fatalf("target changed: %q, %v", got, err)
		}
		if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("link changed: %v, %v", info, err)
		}
	}
}

func TestSecurityPrereleaseOrdering(t *testing.T) {
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.2", "1.0.0-alpha.10", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"}
	for i, a := range ordered {
		for j, b := range ordered {
			got := Compare(a, b)
			if (i < j && got >= 0) || (i == j && got != 0) || (i > j && got <= 0) {
				t.Errorf("Compare(%q, %q) = %d", a, b, got)
			}
		}
	}
}
