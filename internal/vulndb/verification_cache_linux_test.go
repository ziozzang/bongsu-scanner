//go:build linux

package vulndb

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

func cacheOpen(t *testing.T, dir string, opts Options, wantHashes int, wantErr string) {
	t.Helper()
	ctx := &hashCountingContext{Context: context.Background()}
	st, err := OpenWithOptionsContext(ctx, dir, opts)
	if st != nil {
		defer st.Close()
	}
	if wantErr == "" && err != nil || wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)) {
		t.Fatalf("open error=%v, want %q", err, wantErr)
	}
	if ctx.readerCalls != wantHashes {
		t.Fatalf("completed hashes=%d want=%d", ctx.readerCalls, wantHashes)
	}
	if st != nil {
		got, err := st.Lookup("npm", "example")
		if err != nil || len(got) != 1 || got[0].ID != "CVE-2025-1234" {
			t.Fatalf("lookup=%v error=%v", got, err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func readMarker(t *testing.T, dir string) verificationMarker {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, verificationMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	var m verificationMarker
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestVerificationCacheFirstAndSecondOpen(t *testing.T) {
	for _, mode := range []string{"auto", "none"} {
		t.Run(mode, func(t *testing.T) {
			dir := readerCatalog(t)
			opts := Options{Isolation: mode}
			cacheOpen(t, dir, opts, 2, "")
			m := readMarker(t, dir)
			if m.Stat.CTimeSec >= verificationNow().Unix() {
				t.Fatal("verification did not wait out the inode's ctime tick")
			}
			info, err := os.Stat(filepath.Join(dir, verificationMarkerName))
			if err != nil {
				t.Fatal(err)
			}
			if !trustedVerificationMarker(info) {
				t.Fatalf("untrusted receipt: %v", info)
			}
			dbInfo, err := os.Stat(filepath.Join(dir, SQLiteFileName))
			if err != nil {
				t.Fatal(err)
			}
			stat, _ := verificationStat(dbInfo)
			manifest, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(manifest)
			if m.Stat != stat || m.ManifestDigest != hex.EncodeToString(digest[:]) || m.PinnedKey != "unsigned" || m.SchemaVersion != SchemaVersion || m.SQLiteSchemaVersion != SQLiteSchemaVersion {
				t.Fatalf("bad receipt: %+v", m)
			}
			cacheOpen(t, dir, opts, 1, "")
			if got := readMarker(t, dir); got != m {
				t.Fatal("cache hit rewrote receipt contents")
			}
			ctx := &hashCountingContext{Context: context.Background()}
			if err := VerifyContext(ctx, dir, nil); err != nil {
				t.Fatal(err)
			}
			if ctx.readerCalls != 2 {
				t.Fatalf("explicit Verify used cache: %d", ctx.readerCalls)
			}
		})
	}
}

func TestVerificationCacheRejectsChangedSQLite(t *testing.T) {
	for _, restoreMtime := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-times", true: "restored-mtime"}[restoreMtime], func(t *testing.T) {
			dir := readerCatalog(t)
			cacheOpen(t, dir, Options{}, 2, "")
			// Explicitly change ctime even when mtime is restored below; clock
			// settlement is covered separately without waiting for a real tick.
			old := readMarker(t, dir)
			path := filepath.Join(dir, SQLiteFileName)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.WriteAt([]byte("tampered"), 100)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if restoreMtime {
				stamp := time.Unix(old.Stat.MTimeSec, old.Stat.MTimeNSec)
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					t.Fatal(err)
				}
				changeCatalogCTime(t, path, before)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			current, _ := verificationStat(info)
			if current == old.Stat {
				t.Fatal("mutation failed to alter stat tuple")
			}
			cacheOpen(t, dir, Options{}, 1, "checksum mismatch")
			if readMarker(t, dir) != old {
				t.Fatal("failed verification published receipt")
			}
		})
	}
}

func TestVerificationCacheIgnoresInvalidMarker(t *testing.T) {
	cases := []string{"mode", "malformed", "oversized", "trailing-json", "manifest", "sqlite", "key", "schema", "sqlite-schema", "dev", "inode", "size", "mtime", "ctime"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			dir := readerCatalog(t)
			cacheOpen(t, dir, Options{}, 2, "")
			m := readMarker(t, dir)
			path := filepath.Join(dir, verificationMarkerName)
			var b []byte
			switch name {
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				b = []byte("{")
			case "oversized":
				b = bytes.Repeat([]byte(" "), 4097)
			case "trailing-json":
				b = []byte("{}{}")
			default:
				switch name {
				case "manifest":
					m.ManifestDigest = strings.Repeat("0", 64)
				case "sqlite":
					m.SQLiteDigest = strings.Repeat("0", 64)
				case "key":
					m.PinnedKey = "another-key"
				case "schema":
					m.SchemaVersion++
				case "sqlite-schema":
					m.SQLiteSchemaVersion++
				case "dev":
					m.Stat.Dev++
				case "inode":
					m.Stat.Inode++
				case "size":
					m.Stat.Size++
				case "mtime":
					m.Stat.MTimeNSec++
				case "ctime":
					m.Stat.CTimeNSec++
				}
				b, _ = json.Marshal(m)
			}
			if b != nil {
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cacheOpen(t, dir, Options{}, 2, "")
			cacheOpen(t, dir, Options{}, 1, "")
		})
	}
}

// The privilege-independent owner branch uses a real fstat with only UID
// changed; exercise the actual descriptor check too wherever chown is allowed.
type markerOwnerInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i markerOwnerInfo) Sys() any { return &i.stat }
func TestVerificationCacheMarkerOwner(t *testing.T) {
	dir := readerCatalog(t)
	cacheOpen(t, dir, Options{}, 2, "")
	path := filepath.Join(dir, verificationMarkerName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := *info.Sys().(*syscall.Stat_t)
	changed.Uid++
	if trustedVerificationMarker(markerOwnerInfo{info, changed}) {
		t.Fatal("accepted other UID")
	}
	t.Run("filesystem", func(t *testing.T) {
		if err := os.Chown(path, int(changed.Uid), -1); err != nil {
			t.Skipf("chown requires privilege: %v", err)
		}
		cacheOpen(t, dir, Options{}, 2, "")
	})
}

func TestVerificationCacheCopyAlwaysHashes(t *testing.T) {
	dir := readerCatalog(t)
	cacheOpen(t, dir, Options{}, 2, "")
	cacheOpen(t, dir, Options{Isolation: "copy"}, 3, "")
	cacheOpen(t, dir, Options{Isolation: "copy"}, 3, "")
}

func signCacheManifest(t *testing.T, dir string, key ed25519.PrivateKey) {
	t.Helper()
	path := filepath.Join(dir, "manifest.sha256")
	digest, err := sign.FileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sign.Create(digest, "manifest.sha256", "test", key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.WriteRecord(path+".sig", rec); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationCachePinnedKeyAndSignature(t *testing.T) {
	dir := readerCatalog(t)
	cacheOpen(t, dir, Options{}, 2, "")
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signCacheManifest(t, dir, priv)
	cacheOpen(t, dir, Options{PublicKey: pub}, 2, "") // unsigned receipt cannot satisfy pin
	cacheOpen(t, dir, Options{PublicKey: pub}, 1, "")
	old := readMarker(t, dir)
	other, private, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cacheOpen(t, dir, Options{PublicKey: other}, 2, "signature")
	if readMarker(t, dir) != old {
		t.Fatal("bad signature wrote marker")
	}
	signCacheManifest(t, dir, private)
	cacheOpen(t, dir, Options{PublicKey: other}, 2, "")
	cacheOpen(t, dir, Options{PublicKey: other}, 1, "")
	if err := os.Remove(filepath.Join(dir, "manifest.sha256.sig")); err != nil {
		t.Fatal(err)
	}
	cacheOpen(t, dir, Options{PublicKey: other}, 1, "requires signed")
	cacheOpen(t, dir, Options{}, 2, "") // removing pin is another trust decision
}

func TestVerificationCacheManifestContentChange(t *testing.T) {
	dir := readerCatalog(t)
	cacheOpen(t, dir, Options{}, 2, "")
	path := filepath.Join(dir, "manifest.sha256")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	if err := os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	cacheOpen(t, dir, Options{}, 2, "")
	cacheOpen(t, dir, Options{}, 1, "")
}

func TestVerificationCacheRenameInstallInvalidates(t *testing.T) {
	dir := readerCatalog(t)
	cacheOpen(t, dir, Options{}, 2, "")
	old := readMarker(t, dir)
	stage := readerCatalog(t)
	// Make all contents byte-identical, including an old receipt accidentally
	// copied during install/import. The newly allocated inode must still miss.
	for _, name := range []string{SQLiteFileName, "meta.json", "manifest.sha256", verificationMarkerName} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Unix(old.Stat.MTimeSec, old.Stat.MTimeNSec)
	if err := os.Chtimes(filepath.Join(stage, SQLiteFileName), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = installDatabase(stage, dir)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, SQLiteFileName))
	if err != nil {
		t.Fatal(err)
	}
	stat, _ := verificationStat(info)
	if stat.Inode == old.Stat.Inode {
		t.Fatal("rename install reused old inode")
	}
	cacheOpen(t, dir, Options{}, 2, "")
	cacheOpen(t, dir, Options{}, 1, "")
}

func TestVerificationCacheConcurrentPublication(t *testing.T) {
	dir := readerCatalog(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := Open(dir)
			if err != nil {
				t.Error(err)
				return
			}
			if err := st.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	cacheOpen(t, dir, Options{}, 1, "")
	paths, err := filepath.Glob(filepath.Join(dir, ".verified-tmp-*"))
	if err != nil || len(paths) > 0 {
		t.Fatalf("temporary receipts: %v %v", paths, err)
	}
}

func TestVerificationCacheKeepsSymlinkChecks(t *testing.T) {
	dir := readerCatalog(t)
	cacheOpen(t, dir, Options{}, 2, "")
	path := filepath.Join(dir, verificationMarkerName)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("meta.json", path); err != nil {
		t.Fatal(err)
	}
	cacheOpen(t, dir, Options{}, 0, "symlink")
}

// Opt in with BSCAN_VERIFY_BENCH_DB pointing to a private real-catalog copy.
// These benchmarks also provide the exact Go hash cost instead of substituting
// a different SHA-256 implementation from a shell utility.
func BenchmarkVerificationRealCatalog(b *testing.B) {
	dir := os.Getenv("BSCAN_VERIFY_BENCH_DB")
	if dir == "" {
		b.Skip("set BSCAN_VERIFY_BENCH_DB")
	}
	for _, mode := range []string{"full", "cached"} {
		b.Run(mode, func(b *testing.B) {
			st, err := Open(dir)
			if err != nil {
				b.Fatal(err)
			}
			if err := st.Close(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if mode == "full" {
					b.StopTimer()
					if err := os.Remove(filepath.Join(dir, verificationMarkerName)); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
				}
				st, err := Open(dir)
				if err != nil {
					b.Fatal(err)
				}
				if err := st.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	b.Run("sqlite-hash", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := hashFileContext(context.Background(), filepath.Join(dir, SQLiteFileName)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestVerificationCacheFreshStatCancellationAndFutureClock(t *testing.T) {
	dir := readerCatalog(t)
	info, err := os.Stat(filepath.Join(dir, SQLiteFileName))
	if err != nil {
		t.Fatal(err)
	}
	stat := *info.Sys().(*syscall.Stat_t)
	stat.Ctim.Sec = verificationNow().Unix()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok, err := settledVerificationStat(ctx, markerOwnerInfo{info, stat}); ok || err != context.Canceled {
		t.Fatalf("cancelled wait: %v %v", ok, err)
	}
	stat.Ctim.Sec = verificationNow().Add(time.Hour).Unix()
	if _, ok, err := settledVerificationStat(context.Background(), markerOwnerInfo{info, stat}); ok || err != nil {
		t.Fatalf("future timestamp must disable cache: %v %v", ok, err)
	}
}

func TestVerificationCacheWriteFailureFallsBack(t *testing.T) {
	dir := readerCatalog(t)
	// An empty directory blocks atomic receipt publication on all privilege levels.
	if err := os.Mkdir(filepath.Join(dir, verificationMarkerName), 0700); err != nil {
		t.Fatal(err)
	}
	cacheOpen(t, dir, Options{}, 2, "")
	cacheOpen(t, dir, Options{}, 2, "")
}

func TestVerificationCacheManifestRebuildRemovesReceipt(t *testing.T) {
	dir := readerCatalog(t)
	cacheOpen(t, dir, Options{}, 2, "")
	if err := os.Remove(filepath.Join(dir, "manifest.sha256")); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, verificationMarkerName)); !os.IsNotExist(err) {
		t.Fatalf("receipt retained: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(verificationMarkerName)) {
		t.Fatal("manifest covers local receipt")
	}
	cacheOpen(t, dir, Options{}, 2, "")
}

func TestVerificationCacheCorruptSignatureOnHit(t *testing.T) {
	dir := readerCatalog(t)
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signCacheManifest(t, dir, priv)
	cacheOpen(t, dir, Options{PublicKey: pub}, 2, "")
	old := readMarker(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "manifest.sha256.sig"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	cacheOpen(t, dir, Options{PublicKey: pub}, 1, "signature")
	if readMarker(t, dir) != old {
		t.Fatal("bad signature changed receipt")
	}
}

func TestVerificationSettlementInjectedClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 250_000_000)
	for _, tc := range []struct {
		name      string
		offset    int64
		cancelled bool
		wantOK    bool
		wantDelay time.Duration
	}{
		{"settled", -1, false, true, 0},
		{"fresh", 0, false, true, 750 * time.Millisecond},
		{"future", 1, false, false, 0},
		{"cancelled-wait", 0, true, false, 750 * time.Millisecond},
		{"cancelled-settled", -1, true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testLimit(t, &verificationNow, func() time.Time { return now })
			var delays []time.Duration
			testLimit(t, &verificationTimer, func(delay time.Duration) *time.Timer {
				delays = append(delays, delay)
				if tc.cancelled {
					return time.NewTimer(time.Hour)
				}
				return time.NewTimer(0)
			})
			stat := *info.Sys().(*syscall.Stat_t)
			stat.Ctim.Sec = now.Unix() + tc.offset
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			fakeInfo := markerOwnerInfo{info, stat}
			wantStat, _ := verificationStat(fakeInfo)
			got, ok, err := settledVerificationStat(ctx, fakeInfo)
			if got != wantStat || ok != tc.wantOK || tc.cancelled && !errors.Is(err, context.Canceled) || !tc.cancelled && err != nil {
				t.Fatalf("stat=%+v ok=%v err=%v", got, ok, err)
			}
			if tc.wantDelay == 0 {
				if len(delays) != 0 {
					t.Fatalf("unnecessary wait: %v", delays)
				}
			} else if len(delays) != 1 || delays[0] != tc.wantDelay {
				t.Fatalf("waits=%v want [%s]", delays, tc.wantDelay)
			}
		})
	}
}

func TestVerificationCacheCTimeOnlyChange(t *testing.T) {
	dir := readerCatalog(t)
	cacheOpen(t, dir, Options{}, 2, "")
	old := readMarker(t, dir)
	path := filepath.Join(dir, SQLiteFileName)
	f, err := openCatalogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.file.Close()
	changeCatalogCTime(t, path, f.info)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := verificationStat(info)
	if current == old.Stat {
		t.Fatal("chmod did not change stat tuple")
	}
	current.CTimeSec, current.CTimeNSec = old.Stat.CTimeSec, old.Stat.CTimeNSec
	if current != old.Stat {
		t.Fatal("chmod changed fields other than ctime")
	}
	if err := f.check("ctime changed"); err == nil || err.Error() != "ctime changed" {
		t.Fatalf("descriptor missed ctime-only change: %v", err)
	}
	cacheOpen(t, dir, Options{}, 2, "")
	cacheOpen(t, dir, Options{}, 1, "")
}

func TestHeavyVerificationSettlementRealClock(t *testing.T) {
	heavyTest(t)
	testLimit(t, &verificationNow, time.Now)
	path := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := verificationStat(info)
	got, ok, err := settledVerificationStat(context.Background(), info)
	if err != nil || !ok || got != want || got.CTimeSec >= time.Now().Unix() {
		t.Fatalf("real clock did not settle ctime: stat=%+v ok=%v err=%v", got, ok, err)
	}
}
