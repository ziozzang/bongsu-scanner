package vulndb

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

const r25ID = "CVE-2026-1001"
const r25Deleted = "2026-09-15T00:00:00Z"

func r25Update(t *testing.T, dir string, opts Options) SourceMeta {
	t.Helper()
	m, err := Update(context.Background(), dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	return deltaMeta(t, m)
}

func r25AssertDeleted(t *testing.T, dir string) {
	t.Helper()
	r, ok := deltaRecords(t, dir)[r25ID]
	if !ok || r.Withdrawn != r25Deleted || len(r.Affected) != 0 {
		t.Fatalf("known deletion lost: present=%v record=%+v", ok, r)
	}
	r23Lookup(t, dir, "Red Hat", "stale", 0)
	r23Lookup(t, dir, "Red Hat", "replacement", 0)
}

func r25Cached(t *testing.T, dir string) map[string]Record {
	t.Helper()
	out := map[string]Record{}
	if err := readFeedCache(filepath.Join(dir, "cache", SourceRedHatVEX, "vex-changes.jsonl.gz"), 1<<20, func(r *Record) error {
		out[r.ID] = *r
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func r25Rollover(t *testing.T, tracking string) {
	t.Helper()
	f := newDeltaFixture(t)
	f.setArchive(t, deltaDoc(r25ID, "2026-09-13T00:00:00Z", "stale"))
	f.deleted = deltaRow(r25ID, r25Deleted)
	opts := f.options(t)
	dir := filepath.Join(t.TempDir(), "db")
	r25Update(t, dir, opts)
	r25AssertDeleted(t, dir)
	// Clearing tests first carry a tombstone through a stale archive, then
	// verify that the following archive actually removes the saved history.
	if tracking == "" || compareRFC3339(tracking, r25Deleted) > 0 {
		f.mu.Lock()
		f.date = "2026-09-16"
		f.deleted = ""
		f.mu.Unlock()
		r25Update(t, dir, opts)
		r25AssertDeleted(t, dir)
	}
	f.mu.Lock()
	f.date = "2026-09-17"
	if tracking == "" {
		f.setArchive(t, deltaDoc("CVE-2026-1002", "2026-09-17T00:00:00Z", "unrelated"))
	} else {
		f.setArchive(t, deltaDoc(r25ID, tracking, "replacement"))
	}
	// The saved tombstone must survive even if the publisher prunes its list.
	f.deleted = ""
	f.mu.Unlock()
	for range 2 {
		r25Update(t, dir, opts)
		r, present := deltaRecords(t, dir)[r25ID]
		cached, retained := r25Cached(t, dir)[r25ID]
		switch {
		case tracking == "":
			if present || retained {
				t.Fatalf("omitted CVE retained: record=%+v cache=%+v", r, cached)
			}
		case compareRFC3339(tracking, r25Deleted) > 0:
			if !present || r.Withdrawn != "" || len(r.Affected) != 1 || r.Affected[0].Package != "replacement" || retained {
				t.Fatalf("newer archive did not clear tombstone: record=%+v cache=%+v", r, cached)
			}
		default:
			r25AssertDeleted(t, dir)
			if !retained || cached.Withdrawn != r25Deleted {
				t.Fatalf("tombstone not persisted: %+v", cached)
			}
		}
	}
}

func TestR24ArchiveDeletionRollover(t *testing.T) {
	for _, tracking := range []string{"2026-09-13T00:00:00Z", r25Deleted, "2026-09-15T01:00:00+01:00"} {
		t.Run(tracking, func(t *testing.T) { r25Rollover(t, tracking) })
	}
}

func TestR25ArchiveOmissionClearsTombstone(t *testing.T) { r25Rollover(t, "") }

func TestR25ArchiveNewerTrackingReinstates(t *testing.T) {
	r25Rollover(t, "2026-09-15T00:00:00.000000001Z")
}

func TestR24MissingReaddMustRetainKnownDeletion(t *testing.T) {
	f := newDeltaFixture(t)
	f.setArchive(t, deltaDoc(r25ID, "2026-09-13T00:00:00Z", "stale"))
	f.deleted = deltaRow(r25ID, r25Deleted)
	f.changes = deltaRow(r25ID, "2026-09-16T00:00:00Z")
	opts := f.options(t)
	dir := filepath.Join(t.TempDir(), "db")
	for range 2 {
		m := r25Update(t, dir, opts)
		if m.DeltaMissing != 1 || m.DeltaRemaining != 1 || m.DeltaDeleted != 1 || m.DeltaFetched != 0 {
			t.Fatalf("missing re-add metadata: %+v", m)
		}
		r25AssertDeleted(t, dir)
		var ledger map[string]time.Time
		if err := readJSON(filepath.Join(dir, "cache", SourceRedHatVEX, "vex-changes.jsonl.gz.ledger.json"), &ledger); err != nil {
			t.Fatal(err)
		}
		if len(ledger) != 1 || ledger["true:2026/cve-2026-1001.json"].Format(time.RFC3339) != r25Deleted {
			t.Fatalf("only deletion should be checkpointed: %v", ledger)
		}
	}
}

func TestR24NewerListEventCannotBypassDeletionTrackingPrecedence(t *testing.T) {
	for _, tracking := range []string{"2026-09-14T00:00:00Z", r25Deleted, "2026-09-15T01:00:00+01:00"} {
		t.Run(tracking, func(t *testing.T) {
			f := newDeltaFixture(t)
			f.setArchive(t, deltaDoc(r25ID, "2026-09-13T00:00:00Z", "stale"))
			f.deleted = deltaRow(r25ID, r25Deleted)
			opts := f.options(t)
			incremental := filepath.Join(t.TempDir(), "db")
			r25Update(t, incremental, opts)
			f.mu.Lock()
			f.changes = deltaRow(r25ID, "2026-09-16T00:00:00Z")
			f.etag = "readd"
			f.docs["/2026/cve-2026-1001.json"] = deltaDoc(r25ID, tracking, "replacement")
			f.mu.Unlock()
			fresh := filepath.Join(t.TempDir(), "db")
			for _, dir := range []string{fresh, incremental} {
				for range 2 {
					m := r25Update(t, dir, opts)
					if m.DeltaRemaining != 0 || m.DeltaDeleted != 1 || m.DeltaDocuments != 1 {
						t.Fatalf("precedence metadata: %+v", m)
					}
					r25AssertDeleted(t, dir)
				}
			}
		})
	}
}

func TestR25MissingReaddLaterSucceeds(t *testing.T) {
	f := newDeltaFixture(t)
	f.setArchive(t, deltaDoc(r25ID, "2026-09-13T00:00:00Z", "stale"))
	f.deleted = deltaRow(r25ID, r25Deleted)
	f.changes = deltaRow(r25ID, "2026-09-16T00:00:00Z")
	opts := f.options(t)
	dir := filepath.Join(t.TempDir(), "db")
	r25Update(t, dir, opts)
	r25AssertDeleted(t, dir)
	f.mu.Lock()
	f.docs["/2026/cve-2026-1001.json"] = deltaDoc(r25ID, "2026-09-15T00:00:00.000000001Z", "replacement")
	f.mu.Unlock()
	for i := range 2 {
		m := r25Update(t, dir, opts)
		if m.DeltaFetched != 1-i || m.DeltaDocuments != 1 || m.DeltaDeleted != 1 || m.DeltaMissing != 0 || m.DeltaRemaining != 0 {
			t.Fatalf("retry metadata: %+v", m)
		}
		r := deltaRecords(t, dir)[r25ID]
		if r.Withdrawn != "" || len(r.Affected) != 1 || r.Affected[0].Package != "replacement" {
			t.Fatalf("newer fetched document not applied: %+v", r)
		}
		r23Lookup(t, dir, "Red Hat", "stale", 0)
		r23Lookup(t, dir, "Red Hat", "replacement", 1)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests["/2026/cve-2026-1001.json"] != 2 {
		t.Fatalf("successful re-add fetched again: %v", f.requests)
	}
}
