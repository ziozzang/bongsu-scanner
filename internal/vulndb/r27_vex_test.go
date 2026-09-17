package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestR27RebuildPreservesTombstone(t *testing.T) {
	for _, force := range []bool{true, false} {
		name := "old-conversion"
		if force {
			name = "force"
		}
		t.Run(name, func(t *testing.T) {
			f := newDeltaFixture(t)
			f.setArchive(t, deltaDoc(r25ID, "2026-09-13T00:00:00Z", "stale"))
			f.deleted = deltaRow(r25ID, r25Deleted)
			opts := f.options(t)
			dir := filepath.Join(t.TempDir(), "db")
			r25Update(t, dir, opts)
			f.mu.Lock()
			f.deleted = ""
			f.mu.Unlock()
			opts.Force = force
			if !force {
				path := filepath.Join(dir, "meta.json")
				var meta Meta
				if err := readJSON(path, &meta); err != nil {
					t.Fatal(err)
				}
				for i := range meta.Sources {
					meta.Sources[i].ConversionVersion = 0
				}
				records := deltaRecords(t, dir)
				rebuilt := map[string]*Record{}
				for id, r := range records {
					rebuilt[id] = &r
				}
				if err := os.Remove(filepath.Join(dir, SQLiteFileName)); err != nil {
					t.Fatal(err)
				}
				if err := buildSQLite(context.Background(), dir, rebuilt, &meta); err != nil {
					t.Fatal(err)
				}
				if err := writeJSON(path, meta); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(dir, "manifest.sha256")); err != nil {
					t.Fatal(err)
				}
				if err := writeManifest(dir, Options{}); err != nil {
					t.Fatal(err)
				}
			}
			r25Update(t, dir, opts)
			r25AssertDeleted(t, dir)
		})
	}
}

func TestR27FreshRolloverEquivalence(t *testing.T) {
	for _, tracking := range []string{"2026-09-13T00:00:00Z", r25Deleted, "2026-09-16T00:00:00Z", ""} {
		t.Run(tracking, func(t *testing.T) {
			f := newDeltaFixture(t)
			f.setArchive(t, deltaDoc(r25ID, "2026-09-13T00:00:00Z", "stale"))
			f.deleted = deltaRow(r25ID, r25Deleted)
			opts := f.options(t)
			incremental := filepath.Join(t.TempDir(), "db")
			r25Update(t, incremental, opts)
			f.mu.Lock()
			f.date = "2026-09-17"
			if tracking == "" {
				f.setArchive(t)
			} else {
				f.setArchive(t, deltaDoc(r25ID, tracking, "replacement"))
			}
			f.mu.Unlock()
			r25Update(t, incremental, opts)
			fresh := filepath.Join(t.TempDir(), "db")
			r25Update(t, fresh, opts)
			a, b := r25Cached(t, incremental), r25Cached(t, fresh)
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("incremental=%+v fresh=%+v", a, b)
			}
			if tracking != "" && compareRFC3339(tracking, r25Deleted) <= 0 {
				r25AssertDeleted(t, fresh)
			}
		})
	}
}

func TestR27MalformedArchiveDoesNotProveOmission(t *testing.T) {
	f := newDeltaFixture(t)
	f.setArchive(t, deltaDoc(r25ID, "2026-09-13T00:00:00Z", "stale"))
	f.deleted = deltaRow(r25ID, r25Deleted)
	opts := f.options(t)
	dir := filepath.Join(t.TempDir(), "db")
	r25Update(t, dir, opts)
	f.mu.Lock()
	f.date = "2026-09-17"
	f.deleted = ""
	f.setArchive(t, `{"broken":`)
	f.mu.Unlock()
	for range 2 {
		r25Update(t, dir, opts)
		r25AssertDeleted(t, dir)
	}
}

func TestR27ReconciledMetadata(t *testing.T) {
	f := newDeltaFixture(t)
	f.setArchive(t, deltaDoc(r25ID, "2026-09-13T00:00:00Z", "stale"))
	f.deleted = deltaRow(r25ID, r25Deleted)
	opts := f.options(t)
	dir := filepath.Join(t.TempDir(), "db")
	first := r25Update(t, dir, opts)
	if first.DeltaDeletedEvents != 1 || first.DeltaTombstones != 1 {
		t.Fatalf("first counters: %+v", first)
	}
	f.mu.Lock()
	f.date = "2026-09-17"
	f.deleted = ""
	f.mu.Unlock()
	for range 2 {
		m := r25Update(t, dir, opts)
		// Read the new field by JSON so the regression compiles before it exists.
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(b, &fields); err != nil {
			t.Fatal(err)
		}
		if m.DeltaDeletedEvents != 0 || !strings.Contains(m.VEXStatus(), "tombstones=1") || m.Records != 1 || m.DataThrough.Format(time.RFC3339) != r25Deleted || m.DeltaThrough.Format(time.RFC3339) != r25Deleted || fields["delta_tombstones"] != float64(1) {
			t.Fatalf("stale metadata: %s", b)
		}
		var saved Meta
		if err := readJSON(filepath.Join(dir, "meta.json"), &saved); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(deltaMeta(t, saved), m) {
			t.Fatal("returned/persisted metadata differ")
		}
	}
}

func TestR27IncompleteDeltaWarning(t *testing.T) {
	f := newDeltaFixture(t)
	f.setArchive(t)
	f.changes = deltaRow(r25ID, "2026-09-15T00:00:00Z")
	opts := f.options(t)
	var logs []string
	opts.Progress = func(s string) { logs = append(logs, s) }
	r25Update(t, filepath.Join(t.TempDir(), "db"), opts)
	found := false
	for _, line := range logs {
		if strings.HasPrefix(line, "WARNING: ") && strings.Contains(line, "remaining=1") && strings.Contains(line, "missing=1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no actionable warning: %v", logs)
	}
}

func TestR27ArchiveCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		limit      int64
		want       bool
	}{
		{"valid", vexFixture, vexMaxDocument, false},
		{"malformed", "{broken", vexMaxDocument, true},
		{"invalid-document", `{}`, vexMaxDocument, true},
		{"oversized", vexFixture, 16, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			incomplete := false
			_, err := parseRedHatVEXExpanded(context.Background(), vexArchive(t, tc.body), 1<<20, tc.limit, func(*Record) error { return nil }, nil, &incomplete)
			if err != nil || incomplete != tc.want {
				t.Fatalf("coverage=%v want=%v err=%v", incomplete, tc.want, err)
			}
		})
	}
}

func TestR27TombstoneBound(t *testing.T) {
	d := &vexDeltaFeed{archiveTombstones: map[string]*Record{}, tombstoneOrder: &vexTombstoneHeap{positions: map[string]int{}}}
	for i := 0; i < vexMaxTombstones+2; i++ {
		at := time.Date(2026, 1, 1, 0, 0, 0, i, time.UTC).Format(time.RFC3339Nano)
		d.retainTombstone(&Record{ID: fmt.Sprintf("CVE-2026-%06d", i), Withdrawn: at})
	}
	if len(d.archiveTombstones) != vexMaxTombstones || d.evictedTombstones != 2 || d.archiveTombstones["CVE-2026-000000"] != nil || d.archiveTombstones["CVE-2026-000001"] != nil {
		t.Fatal("tombstone bound did not evict oldest records")
	}
	// Updating an existing ID must update the heap without adding bookkeeping.
	d.retainTombstone(&Record{ID: "CVE-2026-000002", Withdrawn: "2027-01-01T00:00:00Z"})
	d.retainTombstone(&Record{ID: "CVE-2027-1234", Withdrawn: "2027-01-01T00:00:00Z"})
	if d.archiveTombstones["CVE-2026-000002"] == nil || d.archiveTombstones["CVE-2026-000003"] != nil || len(d.tombstoneOrder.positions) != vexMaxTombstones {
		t.Fatal("updated deletion was evicted or heap grew")
	}
}
