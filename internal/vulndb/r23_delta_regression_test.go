package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestR22DeletionOtherSource(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			f := newDeltaFixture(t)
			id := "CVE-2026-1001"
			f.setArchive(t, deltaDoc(id, "2026-09-13T00:00:00Z", "stale"))
			f.deleted = deltaRow(id, "2026-09-15T00:00:00Z")
			f.docs["/other.json"] = "{}"
			opts := f.options(t)
			old := registry[SourceDebian]
			registry[SourceDebian] = func() Source { return deltaOtherSource{f.server.URL + "/other.json"} }
			defer func() { registry[SourceDebian] = old }()
			opts.Sources = []string{SourceDebian, SourceRedHatVEX}
			if reverse {
				opts.Sources = []string{SourceRedHatVEX, SourceDebian}
			}
			dir := filepath.Join(t.TempDir(), "db")
			for range 2 {
				if _, err := Update(context.Background(), dir, opts); err != nil {
					t.Fatal(err)
				}
				r := deltaRecords(t, dir)[id]
				if r.Withdrawn != "" || r.Source != SourceDebian || len(r.Affected) != 1 || r.Affected[0].Package != "debian" || len(r.Database) != 0 {
					t.Fatalf("other source changed: %+v", r)
				}
				if len(r.Provenance) != 1 || r.Provenance[0].Name != SourceDebian {
					t.Fatalf("stale provenance: %+v", r.Provenance)
				}
				r23Lookup(t, dir, "Red Hat", "stale", 0)
				r23Lookup(t, dir, "Debian", "debian", 1)
			}
		})
	}
}

func r23Lookup(t *testing.T, dir, eco, pkg string, want int) {
	t.Helper()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rs, err := st.Lookup(eco, pkg)
	if err != nil || len(rs) != want {
		t.Fatalf("lookup %s/%s: %v, %v", eco, pkg, rs, err)
	}
}

func TestR22DeletionThenUnchangedList(t *testing.T) {
	f := newDeltaFixture(t)
	id := "CVE-2026-1001"
	f.setArchive(t, deltaDoc(id, "2026-09-13T00:00:00Z", "old"))
	f.changes = deltaRow(id, "2026-09-14T00:00:00Z")
	f.deleted = deltaRow(id, "2026-09-15T00:00:00Z")
	opts := f.options(t)
	dir := filepath.Join(t.TempDir(), "db")
	for range 3 {
		if _, err := Update(context.Background(), dir, opts); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests["/2026/cve-2026-1001.json"] != 0 {
		t.Fatal("requested deleted document", f.requests)
	}
}

func TestR22EqualInstantDeletion(t *testing.T) {
	for _, stamp := range []string{"2026-09-14T01:00:00+01:00", "2026-09-13T19:00:00-05:00"} {
		t.Run(stamp, func(t *testing.T) {
			f := newDeltaFixture(t)
			id := "CVE-2026-1001"
			f.setArchive(t, deltaDoc(id, stamp, "old"))
			f.deleted = deltaRow(id, "2026-09-14T00:00:00Z")
			dir := filepath.Join(t.TempDir(), "db")
			if _, err := Update(context.Background(), dir, f.options(t)); err != nil {
				t.Fatal(err)
			}
			r23Lookup(t, dir, "Red Hat", "old", 0)
			if r := deltaRecords(t, dir)[id]; r.Withdrawn == "" || len(r.Affected) != 0 {
				t.Fatalf("deletion lost: %+v", r)
			}
			active := Record{ID: id, Source: SourceRedHatVEX, Modified: stamp, Affected: []Affected{{Package: "old"}}}
			dead := Record{ID: id, Source: SourceRedHatVEX, Modified: "2026-09-14T00:00:00Z", Withdrawn: "2026-09-14T00:00:00Z"}
			for _, reverse := range []bool{false, true} {
				a, b := active, dead
				if reverse {
					a, b = b, a
				}
				Merge(&a, &b)
				if !reflect.DeepEqual(a, dead) {
					t.Fatalf("tie: %+v", a)
				}
			}
		})
	}
}

func TestR23DeletionThenReadd(t *testing.T) {
	f := newDeltaFixture(t)
	id := "CVE-2026-1001"
	f.setArchive(t, deltaDoc(id, "2026-09-13T00:00:00Z", "old"))
	f.changes = deltaRow(id, "2026-09-14T00:00:00Z")
	f.deleted = deltaRow(id, "2026-09-15T00:00:00Z")
	opts := f.options(t)
	dir := filepath.Join(t.TempDir(), "db")
	if _, err := Update(context.Background(), dir, opts); err != nil {
		t.Fatal(err)
	}
	// Unchanged list must not resurrect the old change before the re-add.
	if _, err := Update(context.Background(), dir, opts); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.changes += deltaRow(id, "2026-09-16T00:00:00Z")
	f.etag = "readd"
	f.docs["/2026/cve-2026-1001.json"] = deltaDoc(id, "2026-09-16T00:00:00Z", "restored")
	f.mu.Unlock()
	for range 2 {
		if _, err := Update(context.Background(), dir, opts); err != nil {
			t.Fatal(err)
		}
		r := deltaRecords(t, dir)[id]
		if r.Withdrawn != "" || len(r.Affected) != 1 || r.Affected[0].Package != "restored" {
			t.Fatalf("re-add lost: %+v", r)
		}
		r23Lookup(t, dir, "Red Hat", "old", 0)
		r23Lookup(t, dir, "Red Hat", "restored", 1)
	}
}

func TestR23BudgetResumeOrder(t *testing.T) {
	f := newDeltaFixture(t)
	f.changes = deltaRow("CVE-2026-1001", "2026-09-14T00:00:00Z")
	f.docs["/2026/cve-2026-1001.json"] = deltaDoc("CVE-2026-1001", "2026-09-14T00:00:00Z", "first")
	f.deleted = deltaRow("CVE-2026-1002", "2026-09-15T00:00:00Z") + deltaRow("CVE-2026-1003", "2026-09-16T00:00:00Z")
	d := &vexDeltaFeed{budget: 10, maxDocuments: 20, maxDocument: 2048}
	m, dir, err := runDeltaFeed(t, f, d, nil, t.TempDir())
	if err != nil || m.DeltaRemaining != 3 || m.DeltaDeleted != 0 || !m.DeltaThrough.IsZero() {
		t.Fatalf("budget checkpoint passed gap: %+v %v", m, err)
	}
	d.budget = 1 << 20
	d.maxDocuments = 1
	for i := range 3 {
		prev := map[string]SourceMeta{SourceRedHatVEX + "\x00" + f.server.URL + "/changes.csv": m}
		m, dir, err = runDeltaFeed(t, f, d, prev, dir)
		if err != nil || m.DeltaRemaining != 2-i || m.DeltaThrough.Day() != 14+i {
			t.Fatalf("resume %d: %+v %v", i, m, err)
		}
	}
}

func TestR23DeltaMissingDocuments(t *testing.T) {
	for _, tc := range []struct {
		total, missing int
		fail           bool
	}{{1, 1, false}, {10, 1, false}, {10, 2, true}, {20, 2, false}} {
		t.Run(fmt.Sprintf("%d/%d", tc.missing, tc.total), func(t *testing.T) {
			f := newDeltaFixture(t)
			for i := range tc.total {
				id := fmt.Sprintf("CVE-2026-%d", 1000+i)
				f.changes += deltaRow(id, "2026-09-14T00:00:00Z")
				if i >= tc.missing {
					f.docs[fmt.Sprintf("/2026/cve-2026-%d.json", 1000+i)] = deltaDoc(id, "2026-09-14T00:00:00Z", "demo")
				}
			}
			d := &vexDeltaFeed{budget: 1 << 20, maxDocuments: 100, maxDocument: 2048}
			m, dir, err := runDeltaFeed(t, f, d, nil, t.TempDir())
			if (err != nil) != tc.fail {
				t.Fatalf("missing documents: %+v %v", m, err)
			}
			if m.DeltaFetched != tc.total-tc.missing || !strings.Contains(m.VEXStatus(), fmt.Sprintf("skipped=%d", tc.missing)) {
				t.Fatalf("missing not counted/continued: %+v", m)
			}
			if tc.fail {
				return
			}
			// Missing documents remain pending and can recover without a list change.
			f.mu.Lock()
			for i := range tc.missing {
				f.docs[fmt.Sprintf("/2026/cve-2026-%d.json", 1000+i)] = deltaDoc(fmt.Sprintf("CVE-2026-%d", 1000+i), "2026-09-14T00:00:00Z", "recovered")
			}
			f.mu.Unlock()
			prev := map[string]SourceMeta{SourceRedHatVEX + "\x00" + f.server.URL + "/changes.csv": m}
			m, _, err = runDeltaFeed(t, f, d, prev, dir)
			if err != nil || m.DeltaFetched != tc.missing || m.DeltaRemaining != 0 {
				t.Fatalf("missing resume: %+v %v", m, err)
			}
		})
	}
}

func TestR23DeltaTiePrecedence(t *testing.T) {
	var archive, delta, latest Record
	for i, r := range []*Record{&archive, &delta, &latest} {
		event := ""
		if i > 0 {
			event = fmt.Sprintf("2026-09-%dT00:00:00Z", 14+i)
		}
		// JSON exercises the persisted cache marker without depending on its Go type.
		raw := fmt.Sprintf(`{"id":"CVE-2026-1001","source":"redhat-vex","modified":"2026-09-14T00:00:00Z","vex_delta":%q,"affected":[{"package":%q}]}`, event, fmt.Sprint(i))
		if err := json.Unmarshal([]byte(raw), r); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]Record{{archive, delta}, {delta, archive}, {delta, latest}, {latest, delta}} {
		a, b := pair[0], pair[1]
		Merge(&a, &b)
		want := "1"
		if pair[0].Affected[0].Package == "2" || pair[1].Affected[0].Package == "2" {
			want = "2"
		}
		if a.Affected[0].Package != want {
			t.Fatalf("delta precedence: %+v", a)
		}
	}
}

func TestR23LegacyLedgerDeletionCheckpoint(t *testing.T) {
	f := newDeltaFixture(t)
	id := "CVE-2026-1001"
	f.changes = deltaRow(id, "2026-09-14T00:00:00Z")
	f.deleted = deltaRow(id, "2026-09-15T00:00:00Z")
	d := &vexDeltaFeed{budget: 1 << 20, maxDocuments: 20, maxDocument: 2048}
	m, dir, err := runDeltaFeed(t, f, d, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The previous release saved only the selected event kind.
	ledger := map[string]time.Time{"true:2026/cve-2026-1001.json": time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)}
	if err := writeJSON(filepath.Join(dir, "cache", SourceRedHatVEX, "vex-changes.jsonl.gz.ledger.json"), ledger); err != nil {
		t.Fatal(err)
	}
	prev := map[string]SourceMeta{SourceRedHatVEX + "\x00" + f.server.URL + "/changes.csv": m}
	m, _, err = runDeltaFeed(t, f, d, prev, dir)
	if err != nil || m.DeltaRemaining != 0 {
		t.Fatalf("legacy deletion retried: %+v %v", m, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests["/2026/cve-2026-1001.json"] != 0 {
		t.Fatal("legacy ledger requested deleted JSON")
	}
}

func TestR23DeltaDocumentTieAndLegacyCache(t *testing.T) {
	f := newDeltaFixture(t)
	id := "CVE-2026-1001"
	f.setArchive(t, deltaDoc(id, "2026-09-14T01:00:00+01:00", "archive"))
	f.changes = deltaRow(id, "2026-09-15T00:00:00Z")
	f.docs["/2026/cve-2026-1001.json"] = deltaDoc(id, "2026-09-14T00:00:00Z", "delta")
	opts := f.options(t)
	dir := filepath.Join(t.TempDir(), "db")
	for range 2 {
		if _, err := Update(context.Background(), dir, opts); err != nil {
			t.Fatal(err)
		}
		r23Lookup(t, dir, "Red Hat", "archive", 0)
		r23Lookup(t, dir, "Red Hat", "delta", 1)
	}
	// A pre-fix delta cache had no VEXDelta field. Resume must restore its
	// precedence from its checkpoint without forcing a full delta download.
	d := &vexDeltaFeed{budget: 1 << 20, maxDocuments: 20, maxDocument: 2048}
	m, cacheDir, err := runDeltaFeed(t, f, d, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(cacheDir, "cache", SourceRedHatVEX, "vex-changes.jsonl.gz")
	var cached Record
	if err := readFeedCache(cache, 1<<20, func(r *Record) error { cached = *r; return nil }); err != nil {
		t.Fatal(err)
	}
	legacy := cached
	legacy.VEXDelta = ""
	feed := Feed{Source: SourceRedHatVEX, Parse: func(_ context.Context, _ string, _ int64, emit Emit, _ func(string)) error { return emit(&legacy) }}
	if _, err := streamFeedCacheSpool(context.Background(), feed, "", cache, 0, nil, 1<<20, 64<<20, nil); err != nil {
		t.Fatal(err)
	}
	prev := map[string]SourceMeta{SourceRedHatVEX + "\x00" + f.server.URL + "/changes.csv": m}
	m, cacheDir, err = runDeltaFeed(t, f, d, prev, cacheDir)
	if err != nil || m.DeltaFetched != 0 {
		t.Fatalf("legacy cache: %+v %v", m, err)
	}
	if err := readFeedCache(filepath.Join(cacheDir, "cache", SourceRedHatVEX, "vex-changes.jsonl.gz"), 1<<20, func(r *Record) error {
		archive := Record{ID: id, Source: SourceRedHatVEX, Modified: "2026-09-14T01:00:00+01:00", Affected: []Affected{{Package: "archive"}}}
		a := *r
		Merge(&a, &archive)
		if len(a.Affected) != 1 || a.Affected[0].Package != "delta" {
			t.Fatalf("legacy cache lost precedence: %+v", a)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
