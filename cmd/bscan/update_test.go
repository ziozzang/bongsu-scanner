package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/selfupdate"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

type updatePolicyTransport struct{}

func (updatePolicyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: -1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(strings.Repeat("ab", 32) + "  bscan\n")),
		Request:       r,
	}, nil
}

func TestUpdateSignaturePolicy(t *testing.T) {
	pub, _, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                                                           string
		pinned, configRequired, flagRequired, dbRequired, wantRequired bool
	}{
		{name: "no key warns"},
		{name: "pinned key requires signature", pinned: true, wantRequired: true},
		{name: "flag requires key", flagRequired: true, wantRequired: true},
		{name: "config requires key", configRequired: true, wantRequired: true},
		{name: "pinned key and flag", pinned: true, flagRequired: true, wantRequired: true},
		{name: "pinned key and config", pinned: true, configRequired: true, wantRequired: true},
		{name: "database policy is independent", dbRequired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BONGSU_HOME", t.TempDir())
			cfg := config.Defaults()
			cfg.UpdateRequireSignature = tc.configRequired
			cfg.DBRequireSignature = tc.dbRequired
			if tc.pinned {
				cfg.TrustedKeys["release"] = hex.EncodeToString(pub)
			}
			u, source, err := newReleaseUpdater(cfg, "o/r", tc.flagRequired)
			if err != nil {
				t.Fatal(err)
			}
			if u.RequireSignature != tc.wantRequired {
				t.Fatalf("RequireSignature=%t", u.RequireSignature)
			}
			if tc.pinned && (source != "trusted:release" || !u.ReleaseKey.Equal(pub)) {
				t.Fatalf("pinned key lost: %s", source)
			}
			u.Client.HTTP.Transport = updatePolicyTransport{}
			var warnings bytes.Buffer
			u.Warn = &warnings
			rel := &selfupdate.Release{Assets: []selfupdate.Asset{{Name: "SHA256SUMS", URL: "https://github.com/o/r/SHA256SUMS"}}}
			sums, err := u.Checksums(context.Background(), rel)
			if tc.wantRequired {
				if !errors.Is(err, selfupdate.ErrSignatureRequired) || sums != nil || warnings.Len() != 0 {
					t.Fatalf("sums=%v err=%v warnings=%s", sums, err, &warnings)
				}
				if tc.pinned && !strings.Contains(err.Error(), "SHA256SUMS.sig") {
					t.Fatalf("missing signature diagnostic: %v", err)
				}
			} else if err != nil || sums == nil || sums.Verified || !strings.Contains(warnings.String(), "no trusted 'release' key") {
				t.Fatalf("sums=%v err=%v warnings=%s", sums, err, &warnings)
			}
		})
	}
}

func withVersion(t *testing.T, v string) {
	t.Helper()
	old := version
	version = v
	t.Cleanup(func() { version = old })
}

func TestUpdateCachePath(t *testing.T) {
	t.Setenv("BONGSU_HOME", "/opt/bongsu")
	if got := updateCachePath(); got != filepath.Join("/opt/bongsu", "cache", "update-check.json") {
		t.Fatalf("BONGSU_HOME path = %s", got)
	}
	t.Setenv("BONGSU_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "/xdg")
	if got := updateCachePath(); got != filepath.Join("/xdg", "bscan", "update-check.json") {
		t.Fatalf("XDG path = %s", got)
	}
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "")
	if got := updateCachePath(); got != "" {
		t.Fatalf("no HOME should disable the cache, got %s", got)
	}
}

func TestReadUpdateCacheRejectsBadValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-check.json")
	now := time.Now().UTC().Format(time.RFC3339)
	for name, tc := range map[string]struct {
		body       string
		wantOK     bool
		wantLatest string
	}{
		"missing":          {"", false, ""},
		"corrupt":          {"{not json", false, ""},
		"empty object":     {"{}", false, ""},
		"no timestamp":     {`{"latest":"v1.2.3"}`, false, ""},
		"valid":            {`{"checked_at":"` + now + `","latest":"v1.2.3"}`, true, "v1.2.3"},
		"bare v":           {`{"checked_at":"` + now + `","latest":"v"}`, true, ""},
		"dash":             {`{"checked_at":"` + now + `","latest":"-"}`, true, ""},
		"escape":           {`{"checked_at":"` + now + `","latest":"\u001b[31m1.0"}`, true, ""},
		"raw control":      {"{\"checked_at\":\"" + now + "\",\"latest\":\"\x1b1.0\"}", false, ""},
		"newline":          {`{"checked_at":"` + now + `","latest":"1.0\n"}`, true, ""},
		"shell":            {`{"checked_at":"` + now + `","latest":"1.0;rm -rf"}`, true, ""},
		"cached failure":   {`{"checked_at":"` + now + `","error":"dial tcp: timeout"}`, true, ""},
		"wrong type":       {`{"checked_at":"` + now + `","latest":123}`, false, ""},
		"prerelease":       {`{"checked_at":"` + now + `","latest":"1.2.3-rc1"}`, true, "1.2.3-rc1"},
		"checked_at wrong": {`{"checked_at":"yesterday","latest":"1.0"}`, false, ""},
	} {
		os.Remove(path)
		if tc.body != "" {
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		c, ok := readUpdateCache(path)
		if ok != tc.wantOK || c.Latest != tc.wantLatest {
			t.Errorf("%s: ok=%t latest=%q, want ok=%t latest=%q", name, ok, c.Latest, tc.wantOK, tc.wantLatest)
		}
	}
}

func TestWriteUpdateCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "cache", "update-check.json")
	want := updateCache{Checked: time.Now().Truncate(time.Second), Latest: "v2.0.0"}
	if err := writeUpdateCache(path, want); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir perms: %v %v", err, info.Mode())
	}
	got, ok := readUpdateCache(path)
	if !ok || got.Latest != want.Latest || !got.Checked.Equal(want.Checked) {
		t.Fatalf("round trip = %#v ok=%t", got, ok)
	}
	if updateCacheStale(got, time.Now()) {
		t.Fatal("fresh cache reported stale")
	}
	if !updateCacheStale(got, time.Now().Add(25*time.Hour)) {
		t.Fatal("old cache reported fresh")
	}
	if !updateCacheStale(updateCache{Checked: time.Now().Add(48 * time.Hour)}, time.Now()) {
		t.Fatal("future cache reported fresh")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".update-*")); len(leftovers) != 0 {
		t.Fatalf("temp files left: %v", leftovers)
	}
}

func TestUpdateCheckSkipped(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "")
	t.Setenv("BONGSU_OFFLINE", "")
	withVersion(t, "1.0.0")

	for _, args := range [][]string{
		{}, {"update"}, {"self-update"}, {"version"}, {"-v"}, {"--version"}, {"help"}, {"-h"}, {"--help"}, {"about"},
	} {
		if !updateCheckSkipped(args) {
			t.Errorf("args %v should skip the update check", args)
		}
	}
	for _, args := range [][]string{{"scan", "."}, {"verify", "x.sig"}, {"batch", "a"}} {
		if updateCheckSkipped(args) {
			t.Errorf("args %v should not skip the update check", args)
		}
	}

	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	if !updateCheckSkipped([]string{"scan", "."}) {
		t.Error("BONGSU_NO_UPDATE_CHECK ignored")
	}
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "0")
	if updateCheckSkipped([]string{"scan", "."}) {
		t.Error("BONGSU_NO_UPDATE_CHECK=0 should not disable")
	}
	t.Setenv("BONGSU_OFFLINE", "yes")
	if !updateCheckSkipped([]string{"scan", "."}) {
		t.Error("BONGSU_OFFLINE ignored")
	}
	t.Setenv("BONGSU_OFFLINE", "")

	withVersion(t, "dev")
	if !updateCheckSkipped([]string{"scan", "."}) {
		t.Error("dev build should skip the update check")
	}
	withVersion(t, "1.0.0")

	cfg := config.Defaults()
	cfg.Offline = true
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if !updateCheckSkipped([]string{"scan", "."}) {
		t.Error("offline: true in config ignored")
	}
	if !offlineMode(cfg) {
		t.Error("offlineMode(cfg.Offline=true) = false")
	}
}

func TestUpdateCheckSkipsUnreadablePolicy(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "")
	t.Setenv("BONGSU_OFFLINE", "")
	withVersion(t, "1.0.0")
	path, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	for _, contents := range []string{"offline: true\ninvalid line\n", "invalid line\noffline: true\n"} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if !updateCheckSkipped([]string{"scan", "."}) {
			t.Fatal("background network check allowed with invalid offline configuration")
		}
	}
}

func TestReleaseKeyResolution(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	cfg := config.Defaults()
	pub, source, err := releaseKey(cfg)
	if err != nil || pub != nil || source != "" {
		t.Fatalf("no key: %v %v %q", pub, err, source)
	}
	want, _, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cfg.TrustedKeys["release"] = hex.EncodeToString(want)
	pub, source, err = releaseKey(cfg)
	if err != nil || !pub.Equal(want) || source != "trusted:release" {
		t.Fatalf("hex key: %v %v %q", pub, err, source)
	}
	pem, _ := sign.MarshalPublic(want)
	keyPath := filepath.Join(t.TempDir(), "release.pub")
	if err := os.WriteFile(keyPath, pem, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.TrustedKeys["release"] = keyPath
	pub, _, err = releaseKey(cfg)
	if err != nil || !pub.Equal(want) {
		t.Fatalf("file key: %v %v", pub, err)
	}
	cfg.TrustedKeys["release"] = "not a key"
	if _, _, err := releaseKey(cfg); err == nil {
		t.Fatal("invalid trusted key accepted")
	}
}

func TestEnvTrue(t *testing.T) {
	for value, want := range map[string]bool{"": false, "0": false, "false": false, "No": false, "off": false, "1": true, "true": true, "yes": true, "anything": true} {
		t.Setenv("BSCAN_TEST_FLAG", value)
		if got := envTrue("BSCAN_TEST_FLAG"); got != want {
			t.Errorf("envTrue(%q) = %t", value, got)
		}
	}
}

func TestUpdatePrintsForgedLegacySignerAsUnauthenticated(t *testing.T) {
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sums := []byte(strings.Repeat("ab", 32) + "  bscan\n")
	digest := sha256.Sum256(sums)
	rec := sign.Record{
		Version: 1, Algorithm: "ed25519", Signer: "release-bot", Target: "SHA256SUMS",
		PublicKey: hex.EncodeToString(pub), DigestSHA256: hex.EncodeToString(digest[:]),
		SignedAt: time.Unix(1700000000, 0).UTC(), Salt: base64.RawStdEncoding.EncodeToString(make([]byte, 16)),
	}
	payload := "bongsu-signature-v1\nsha256:" + rec.DigestSHA256 + "\nsigned-at:" + rec.SignedAt.Format(time.RFC3339Nano) + "\nsalt:" + rec.Salt + "\n"
	rec.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload)))
	rec.Signer = "forged-publisher"
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BONGSU_HOME", t.TempDir())
	cfg := config.Defaults()
	cfg.TrustedKeys["release"] = hex.EncodeToString(pub)
	u, source, err := newReleaseUpdater(cfg, "o/r", false)
	if err != nil {
		t.Fatal(err)
	}
	u.Client.HTTP.Transport = updateSignatureTransport{checksums: sums, signature: raw}
	rel := &selfupdate.Release{Assets: []selfupdate.Asset{
		{Name: "SHA256SUMS", URL: "https://github.com/o/r/SHA256SUMS"},
		{Name: "SHA256SUMS.sig", URL: "https://github.com/o/r/SHA256SUMS.sig"},
	}}
	verified, err := u.Checksums(context.Background(), rel)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	printUpdateSignature(&output, source, verified)
	if !strings.Contains(output.String(), "signer=forged-publisher (unauthenticated: v1 record)") {
		t.Fatalf("legacy signer displayed as authenticated: %s", &output)
	}
}

type updateSignatureTransport struct {
	checksums, signature []byte
}

func (tr updateSignatureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := tr.checksums
	if strings.HasSuffix(r.URL.Path, ".sig") {
		body = tr.signature
	}
	return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(body)), Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
}

func TestUpdateMinimumSignatureVersionFromConfig(t *testing.T) {
	for _, minimum := range []int{1, 2} {
		t.Setenv("BONGSU_HOME", t.TempDir())
		cfg := config.Defaults()
		cfg.SignatureMinVersion = minimum
		if err := config.Save(cfg); err != nil {
			t.Fatal(err)
		}
		cfg, _, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		u, _, err := newReleaseUpdater(cfg, "o/r", false)
		if err != nil || u.SignatureMinVersion != minimum {
			t.Fatalf("updater=%#v err=%v", u, err)
		}
	}
}

func TestUpdateSignatureOutputV2AndUnverified(t *testing.T) {
	for _, verified := range []bool{false, true} {
		var output bytes.Buffer
		printUpdateSignature(&output, "trusted:release", &selfupdate.Checksums{Verified: verified, Authenticated: verified, Signer: "publisher"})
		want := ""
		if verified {
			want = "[update] SHA256SUMS signature verified (key=trusted:release signer=publisher)\n"
		}
		if output.String() != want {
			t.Fatalf("output=%q, want %q", output.String(), want)
		}
	}
}

func TestREADMEConfigUpdateExitCodeGuidance(t *testing.T) {
	body, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, guidance := range []string{
		"UTF-8", "BOM", "CRLF", "signature_min_version", "update_require_signature", "db_require_signature",
		"(unauthenticated: v1 record)",
		"exit code 2 takes precedence over an LLM enrichment error (exit code 1)",
	} {
		if !strings.Contains(string(body), guidance) {
			t.Errorf("README missing configuration/update/exit-code guidance: %q", guidance)
		}
	}
}
