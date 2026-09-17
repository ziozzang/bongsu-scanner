package scan

import (
	"bytes"
	"context"
	"testing"
)

func testBinaryImageRemainingBudget(t *testing.T) {
	u := newUnpacker(context.Background(), Options{})
	defer u.Close()
	// Seed the already-spent portion instead of parsing 20,000 binaries.
	u.binaryBudget.count.Store(maxClassifiedBinaries - 2)
	data := []byte("\x7fELF\x00curl_easy_init curl 8.9.1\x00")
	for i, name := range []string{"a/curl", "b/curl", "c/curl"} {
		layer := buildTar(t, []tarEntry{{name: name, data: data, mode: 0755}})
		if err := u.applyTar(bytes.NewReader(layer), "fixture"); err != nil {
			t.Fatal(err)
		}
		var result Result
		u.applyBinaryMetadata(&result)
		if i < 2 {
			if result.Scan != nil || len(u.binaries) != i+1 {
				t.Fatalf("budget marked exhausted before overflow: scan=%+v binaries=%v", result.Scan, u.binaries)
			}
		} else if result.Scan == nil || !result.Scan.Partial || result.Scan.LimitReached != "max-binaries" || len(u.binaries) != 2 {
			t.Fatalf("missing exhaustion metadata or extra probe: scan=%+v binaries=%v", result.Scan, u.binaries)
		}
		if u.binaryBudget.count.Load() != int64(maxClassifiedBinaries-1+i) {
			t.Fatal("binary reservations did not advance exactly once per entry")
		}
	}
	if len(u.fs) != 3 {
		t.Fatal("probe limit discarded filesystem entries")
	}
}
