package selfupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

func TestCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0}, {"v1.2.4", "1.2.3", 1}, {"1.2.2", "1.2.3", -1}, {"1.10", "1.9.9", 1},
		{"1.2.3-rc1", "1.2.3", -1}, {"1.2.3", "1.2.3-rc1", 1}, {"1.2.3-rc1", "1.2.3-rc2", -1},
		{"1.2.3-rc.2", "1.2.3-rc.10", -1}, {"1.2.3-alpha", "1.2.3-beta", -1}, {"1.2.3-rc1", "1.2.3-rc1", 0},
		{"1.2.3+build5", "1.2.3", 0}, {"1.2.4-rc1", "1.2.3", 1}, {"1.2", "1.2.0", 0},
	} {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareNeverPanics(t *testing.T) {
	weird := []string{"", "v", "-", "+", "dev", "1.2.3-rc1", "v-", "..", "1..2", "v+", "-rc1", "a.b.c", " v1 ", "\x1b[31m1", "99999999999999999999999"}
	for _, a := range weird {
		for _, b := range weird {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Compare(%q,%q) panicked: %v", a, b, r)
					}
				}()
				Compare(a, b)
				fields(a)
				IsVersion(a)
				IsDevBuild(a)
			}()
		}
	}
	for _, v := range []string{"", "v", "-", "+", "..", "a.b"} {
		if got := fields(v); len(got) == 0 {
			t.Errorf("fields(%q) empty", v)
		}
	}
}

func TestIsVersionAndDevBuild(t *testing.T) {
	for v, want := range map[string]bool{
		"1.2.3": true, "v1.2.3": true, "1.2.3-rc1": true, "1.2.3-rc1+b5": true, "0": true, "v10.0": true,
		"": false, "v": false, "-": false, "dev": false, "1.2.3-rc1\n": false, "1.2.3;rm": false, "../1": false, "1.2.3\x1b[31m": false,
	} {
		if got := IsVersion(v); got != want {
			t.Errorf("IsVersion(%q)=%t", v, got)
		}
	}
	for v, want := range map[string]bool{
		"": true, "dev": true, "v": true, "1.2.3-dev": true, "1.2.3-dev.5": true, "nightly": true,
		"1.2.3": false, "v1.2.3": false, "1.2.3-rc1": false,
	} {
		if got := IsDevBuild(v); got != want {
			t.Errorf("IsDevBuild(%q)=%t", v, got)
		}
	}
}

func TestLinuxAssetNameUsesBscan(t *testing.T) {
	name, err := AssetName("0.2.0")
	if err == nil && name != "bscan_0.2.0_linux_x86_64" && name != "bscan_0.2.0_linux_arm64" {
		t.Fatalf("asset name = %q", name)
	}
}

func TestParseChecksums(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	got := parseChecksums([]byte(sum + "  bscan_1_linux_x86_64\n" + strings.ToUpper(sum) + " *starred\nbad line\n" +
		sum + "  ../evil\n" + "zz" + sum[2:] + "  nothex\n" + sum + "  a b\n"))
	if len(got) != 2 || got["bscan_1_linux_x86_64"] != sum || got["starred"] != sum {
		t.Fatalf("parseChecksums = %#v", got)
	}
}

// releaseServer is a fake GitHub releases API + asset host.
type releaseServer struct {
	t      *testing.T
	srv    *httptest.Server
	tag    string
	assets map[string][]byte
	sizes  map[string]int64 // override reported size (0 = actual)
	noSig  bool
	// observed
	apiAuth   string
	assetAuth []string
}

func newReleaseServer(t *testing.T, tag string) *releaseServer {
	t.Helper()
	rs := &releaseServer{t: t, tag: tag, assets: map[string][]byte{}, sizes: map[string]int64{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		rs.apiAuth = r.Header.Get("Authorization")
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		var assets []Asset
		for name, b := range rs.assets {
			if rs.noSig && name == signatureAsset {
				continue
			}
			size := int64(len(b))
			if s := rs.sizes[name]; s != 0 {
				size = s
			}
			assets = append(assets, Asset{Name: name, URL: rs.srv.URL + "/dl/" + name, Size: size})
		}
		json.NewEncoder(w).Encode(Release{TagName: rs.tag, Assets: assets})
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		rs.assetAuth = append(rs.assetAuth, r.Header.Get("Authorization"))
		b, ok := rs.assets[strings.TrimPrefix(r.URL.Path, "/dl/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	})
	rs.srv = httptest.NewTLSServer(mux)
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *releaseServer) updater(key ed25519.PublicKey) (*Updater, *bytes.Buffer) {
	c := NewClient(5 * time.Second)
	c.AllowedHosts = nil
	c.HTTP.Transport = rs.srv.Client().Transport
	warn := &bytes.Buffer{}
	return &Updater{Client: c, APIBase: rs.srv.URL, Repo: "o/r", Token: "tok", ReleaseKey: key, Warn: warn}, warn
}

func signSums(t *testing.T, sums []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	d := sha256.Sum256(sums)
	rec, err := sign.Create(hex.EncodeToString(d[:]), checksumsAsset, "release-bot", priv, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rec)
	return b
}

// fixture builds a signed release for the current platform.
func fixture(t *testing.T) (rs *releaseServer, name string, binary []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	name, err := AssetName("9.9.9")
	if err != nil {
		t.Skip(err)
	}
	pub, priv, err = sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	binary = []byte("#!/bin/sh\necho new-binary-" + strings.Repeat("x", 3000) + "\n")
	d := sha256.Sum256(binary)
	sums := []byte(hex.EncodeToString(d[:]) + "  " + name + "\n")
	rs = newReleaseServer(t, "v9.9.9")
	rs.assets[name] = binary
	rs.assets[checksumsAsset] = sums
	rs.assets[signatureAsset] = signSums(t, sums, priv)
	return rs, name, binary, pub, priv
}

// fakeInstall creates dir/real (mode 0750) and dir/link -> real.
func fakeInstall(t *testing.T) (real, link string) {
	t.Helper()
	dir := t.TempDir()
	real = filepath.Join(dir, "bscan-real")
	if err := os.WriteFile(real, []byte("old"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o750); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(dir, "bscan")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	return real, link
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, ".bscan-update-*"))
	return m
}

func TestUpdateFlowSigned(t *testing.T) {
	rs, name, binary, pub, _ := fixture(t)
	u, warn := rs.updater(pub)
	ctx := context.Background()

	rel, err := u.Latest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version() != "9.9.9" || rs.apiAuth != "Bearer tok" {
		t.Fatalf("release = %#v auth=%q", rel, rs.apiAuth)
	}
	if Compare(rel.Version(), "0.1.0") <= 0 {
		t.Fatal("expected newer")
	}
	sums, err := u.Checksums(ctx, rel)
	if err != nil {
		t.Fatal(err)
	}
	if !sums.Verified || sums.Signer != "release-bot" || sums.Entries[name] == "" {
		t.Fatalf("checksums = %#v", sums)
	}
	asset, ok := rel.Find(name)
	if !ok {
		t.Fatal("asset missing")
	}
	real, link := fakeInstall(t)
	tmp, err := u.Download(ctx, asset, sums.Entries[name], filepath.Dir(real))
	if err != nil {
		t.Fatal(err)
	}
	dest, err := Replace(tmp, link)
	if err != nil {
		t.Fatal(err)
	}
	wantReal, _ := filepath.EvalSymlinks(real)
	if dest != wantReal {
		t.Fatalf("dest = %s want %s", dest, wantReal)
	}
	got, err := os.ReadFile(real)
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("installed content mismatch: %v", err)
	}
	if info, _ := os.Stat(real); info.Mode().Perm() != 0o750 {
		t.Fatalf("mode = %o, want 0750", info.Mode().Perm())
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v %v", info, err)
	}
	if n := leftovers(t, filepath.Dir(real)); len(n) != 0 {
		t.Fatalf("leftover temp files: %v", n)
	}
	for _, a := range rs.assetAuth {
		if a != "" {
			t.Fatalf("token leaked to asset host: %q", a)
		}
	}
	if warn.Len() != 0 {
		t.Fatalf("unexpected warnings: %s", warn)
	}
}

func TestChecksumMismatchCleansUp(t *testing.T) {
	rs, name, _, pub, _ := fixture(t)
	rs.assets[name] = append(rs.assets[name], "tampered"...)
	u, _ := rs.updater(pub)
	ctx := context.Background()
	rel, err := u.Latest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sums, err := u.Checksums(ctx, rel)
	if err != nil {
		t.Fatal(err)
	}
	asset, _ := rel.Find(name)
	dir := t.TempDir()
	tmp, err := u.Download(ctx, asset, sums.Entries[name], dir)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v tmp=%q", err, tmp)
	}
	if n := leftovers(t, dir); len(n) != 0 {
		t.Fatalf("leftover temp files: %v", n)
	}
}

func TestSignatureFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("wrong key", func(t *testing.T) {
		rs, _, _, _, _ := fixture(t)
		otherPub, _, _ := sign.Generate()
		u, _ := rs.updater(otherPub)
		rel, err := u.Latest(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := u.Checksums(ctx, rel); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("sums altered after signing", func(t *testing.T) {
		rs, name, _, pub, _ := fixture(t)
		rs.assets[checksumsAsset] = []byte(strings.Repeat("00", 32) + "  " + name + "\n")
		u, _ := rs.updater(pub)
		rel, _ := u.Latest(ctx)
		if _, err := u.Checksums(ctx, rel); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("garbage signature", func(t *testing.T) {
		rs, _, _, pub, _ := fixture(t)
		rs.assets[signatureAsset] = []byte("not json")
		u, _ := rs.updater(pub)
		rel, _ := u.Latest(ctx)
		if _, err := u.Checksums(ctx, rel); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no key warns", func(t *testing.T) {
		rs, _, _, _, _ := fixture(t)
		u, warn := rs.updater(nil)
		rel, _ := u.Latest(ctx)
		sums, err := u.Checksums(ctx, rel)
		if err != nil || sums.Verified || !strings.Contains(warn.String(), "no trusted 'release' key") {
			t.Fatalf("err=%v verified=%t warn=%q", err, sums.Verified, warn)
		}
	})
	t.Run("no key required", func(t *testing.T) {
		rs, _, _, _, _ := fixture(t)
		u, _ := rs.updater(nil)
		u.RequireSignature = true
		rel, _ := u.Latest(ctx)
		if _, err := u.Checksums(ctx, rel); !errors.Is(err, ErrSignatureRequired) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("pinned key requires signature", func(t *testing.T) {
		rs, _, _, pub, _ := fixture(t)
		rs.noSig = true
		u, warn := rs.updater(pub)
		rel, _ := u.Latest(ctx)
		sums, err := u.Checksums(ctx, rel)
		if !errors.Is(err, ErrSignatureRequired) || !strings.Contains(err.Error(), "SHA256SUMS.sig") || sums != nil || warn.Len() != 0 {
			t.Fatalf("err=%v sums=%v warn=%q", err, sums, warn)
		}
		u.RequireSignature = true
		if _, err := u.Checksums(ctx, rel); !errors.Is(err, ErrSignatureRequired) {
			t.Fatalf("required err = %v", err)
		}
	})
}

func TestRejectsInsecureURLs(t *testing.T) {
	rs, name, _, pub, _ := fixture(t)
	u, _ := rs.updater(pub)
	ctx := context.Background()
	u.APIBase = strings.Replace(rs.srv.URL, "https://", "http://", 1)
	if _, err := u.Latest(ctx); !errors.Is(err, httpx.ErrInsecureURL) {
		t.Fatalf("http API err = %v", err)
	}
	u.APIBase = rs.srv.URL
	rel, err := u.Latest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	asset, _ := rel.Find(name)
	asset.URL = strings.Replace(asset.URL, "https://", "http://", 1)
	dir := t.TempDir()
	if _, err := u.Download(ctx, asset, strings.Repeat("0", 64), dir); !errors.Is(err, httpx.ErrInsecureURL) {
		t.Fatalf("http asset err = %v", err)
	}
	if n := leftovers(t, dir); len(n) != 0 {
		t.Fatalf("leftover temp files: %v", n)
	}
	// Host allow-list applies to asset URLs too.
	u.Client.AllowedHosts = []string{"github.com"}
	if _, err := u.Download(ctx, Asset{Name: name, URL: "https://evil.example/x"}, strings.Repeat("0", 64), dir); !errors.Is(err, httpx.ErrHostNotAllowed) {
		t.Fatalf("allow-list err = %v", err)
	}
	if _, err := u.Latest(ctx); !errors.Is(err, httpx.ErrHostNotAllowed) {
		t.Fatalf("allow-list API err = %v", err)
	}
	u.Repo = "../../evil"
	u.Client.AllowedHosts = nil
	if _, err := u.Latest(ctx); err == nil || !strings.Contains(err.Error(), "invalid repository") {
		t.Fatalf("repo validation err = %v", err)
	}
}

func TestRejectsOversizedAssets(t *testing.T) {
	rs, name, _, pub, _ := fixture(t)
	u, _ := rs.updater(pub)
	ctx := context.Background()
	rel, err := u.Latest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sums, err := u.Checksums(ctx, rel)
	if err != nil {
		t.Fatal(err)
	}
	asset, _ := rel.Find(name)
	dir := t.TempDir()
	// Metadata claims fewer bytes than the server sends: capped at Size.
	asset.Size = 100
	if _, err := u.Download(ctx, asset, sums.Entries[name], dir); !errors.Is(err, httpx.ErrTooLarge) {
		t.Fatalf("size cap err = %v", err)
	}
	// Metadata claims an absurd size: rejected before any request.
	asset.Size = DefaultMaxAssetBytes + 1
	if _, err := u.Download(ctx, asset, sums.Entries[name], dir); !errors.Is(err, httpx.ErrTooLarge) {
		t.Fatalf("absurd size err = %v", err)
	}
	if n := leftovers(t, dir); len(n) != 0 {
		t.Fatalf("leftover temp files: %v", n)
	}
	// Oversized SHA256SUMS metadata is rejected as well.
	big := *rel
	big.Assets = append([]Asset(nil), rel.Assets...)
	for i := range big.Assets {
		if big.Assets[i].Name == checksumsAsset {
			big.Assets[i].Size = MaxChecksumsBytes + 1
		}
	}
	if _, err := u.Checksums(ctx, &big); !errors.Is(err, httpx.ErrTooLarge) {
		t.Fatalf("sums size err = %v", err)
	}
}

func TestLatestRejectsBadTags(t *testing.T) {
	for _, tag := range []string{"", "v", "-", "nightly", "1.2.3\x1b[31m"} {
		rs := newReleaseServer(t, tag)
		u, _ := rs.updater(nil)
		_, err := u.Latest(context.Background())
		if err == nil {
			t.Errorf("tag %q accepted", tag)
			continue
		}
		if strings.ContainsRune(err.Error(), 0x1b) {
			t.Errorf("error not sanitized: %q", err)
		}
	}
}

func TestLatestAPIErrorIsSanitized(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "\x1b[2Jrate limit exceeded\n")
	}))
	defer srv.Close()
	c := NewClient(time.Second)
	c.AllowedHosts = nil
	c.HTTP.Transport = srv.Client().Transport
	u := &Updater{Client: c, APIBase: srv.URL, Repo: "o/r"}
	_, err := u.Latest(context.Background())
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.StatusCode != 403 || strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Fatalf("err = %v", err)
	}
}

func TestReplace(t *testing.T) {
	real, link := fakeInstall(t)
	dir := filepath.Dir(real)
	src := filepath.Join(dir, ".bscan-update-src")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest, err := Replace(src, link)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(real); dest != want {
		t.Fatalf("dest = %s want %s", dest, want)
	}
	if b, _ := os.ReadFile(link); string(b) != "new" {
		t.Fatalf("content via link = %q", b)
	}
	if info, _ := os.Stat(real); info.Mode().Perm() != 0o750 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a file")
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("src still exists: %v", err)
	}
	// Non-regular / missing targets are refused and src is left in place.
	if err := os.WriteFile(src, []byte("again"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Replace(src, dir); err == nil {
		t.Fatal("replacing a directory succeeded")
	}
	if _, err := Replace(src, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("replacing a missing file succeeded")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("src removed on failure: %v", err)
	}
}

func TestExecutableResolvesSymlinks(t *testing.T) {
	p, err := Executable()
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(p); err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("Executable() = %s (%v), want resolved regular file", p, err)
	}
}

func legacySumsRecord(t *testing.T, sums []byte, priv ed25519.PrivateKey) sign.Record {
	t.Helper()
	digest := sha256.Sum256(sums)
	rec := sign.Record{
		Version: 1, Algorithm: "ed25519", Signer: "release-bot", Target: "SHA256SUMS",
		PublicKey:    hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
		DigestSHA256: hex.EncodeToString(digest[:]), SignedAt: time.Unix(1700000000, 0).UTC(),
		Salt: base64.RawStdEncoding.EncodeToString(make([]byte, 16)),
	}
	payload := "bongsu-signature-v1\nsha256:" + rec.DigestSHA256 + "\nsigned-at:" + rec.SignedAt.Format(time.RFC3339Nano) + "\nsalt:" + rec.Salt + "\n"
	rec.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload)))
	return rec
}

func TestChecksumsSignerAuthenticationAndMinVersion(t *testing.T) {
	for _, minimum := range []int{0, 1, 2} {
		for _, version := range []int{1, 2} {
			t.Run(fmt.Sprintf("minimum%d/v%d", minimum, version), func(t *testing.T) {
				rs, _, _, pub, priv := fixture(t)
				if version == 1 {
					rec := legacySumsRecord(t, rs.assets[checksumsAsset], priv)
					rec.Signer = "forged-publisher"
					if err := rec.Verify(pub); err != nil {
						t.Fatalf("legacy fixture must still verify after signer forgery: %v", err)
					}
					raw, err := json.Marshal(rec)
					if err != nil {
						t.Fatal(err)
					}
					rs.assets[signatureAsset] = raw
				}
				u, _ := rs.updater(pub)
				u.SignatureMinVersion = minimum
				rel, err := u.Latest(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				sums, err := u.Checksums(context.Background(), rel)
				if version < minimum {
					if !errors.Is(err, ErrSignatureInvalid) || sums != nil || !strings.Contains(err.Error(), "signature_min_version 2") {
						t.Fatalf("legacy record accepted: sums=%#v err=%v", sums, err)
					}
					return
				}
				if err != nil || !sums.Verified || sums.Authenticated != (version == 2) {
					t.Fatalf("sums=%#v err=%v", sums, err)
				}
				if version == 1 && sums.Signer != "forged-publisher" {
					t.Fatalf("lost legacy signer: %#v", sums)
				}
			})
		}
	}
}
