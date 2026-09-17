package vulndb

import (
	"os"
	"reflect"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Ordinary catalog tests exercise stat comparisons without waiting for every
	// new inode's ctime second to elapse. Settlement itself has deterministic
	// clock/timer tests. Install this before any test goroutines are started.
	original := verificationNow
	verificationNow = func() time.Time { return time.Now().Add(2 * time.Second) }
	code := m.Run()
	verificationNow = original
	os.Exit(code)
}

// Call only from serial tests, before starting workers; Cleanup runs after
// their deferred shutdown. In particular, do not combine this with t.Parallel.
func testLimit[T any](t *testing.T, target *T, value T) {
	t.Helper()
	original := *target
	*target = value
	t.Cleanup(func() { *target = original })
}

func heavyTest(t *testing.T) {
	t.Helper()
	if os.Getenv("BSCAN_HEAVY_TESTS") != "1" {
		t.Skip("set BSCAN_HEAVY_TESTS=1 for production-size limits")
	}
}

// chmod changes ctime without changing size or mtime. Repeat metadata updates
// if the filesystem coalesces adjacent timestamps, without a wall-clock sleep.
func changeCatalogCTime(t *testing.T, path string, before os.FileInfo) {
	t.Helper()
	for range 10000 {
		for _, mode := range []os.FileMode{before.Mode().Perm() ^ 0100, before.Mode().Perm()} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(statCTime(before), statCTime(after)) {
			return
		}
	}
	t.Fatal("metadata updates did not change ctime")
}
