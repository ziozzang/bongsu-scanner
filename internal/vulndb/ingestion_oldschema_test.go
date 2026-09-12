package vulndb

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A catalog written by an older binary must not block a rebuild: the update
// path only loses the carried-over first-seen timestamps.
func TestUpdateToleratesUnsupportedPreviousCatalog(t *testing.T) {
	dir := readerCatalog(t)
	alterReaderCatalog(t, dir, "PRAGMA user_version=2; DELETE FROM metadata WHERE key='record_encoding'")
	if _, err := Open(dir); !errors.Is(err, ErrUnsupportedCatalog) {
		t.Fatalf("expected ErrUnsupportedCatalog, got %v", err)
	}
	var old Meta
	if err := readJSON(dir+"/meta.json", &old); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	records := map[string]*Record{"CVE-2025-1234": {ID: "CVE-2025-1234"}}
	if err := setIngestionTimes(context.Background(), dir, old, records, now); err != nil {
		t.Fatalf("setIngestionTimes must tolerate an unsupported previous catalog: %v", err)
	}
	if !records["CVE-2025-1234"].AddedAt.Equal(now) || !records["CVE-2025-1234"].LastSeenAt.Equal(now) {
		t.Fatalf("timestamps not initialised: %+v", records["CVE-2025-1234"])
	}
}
