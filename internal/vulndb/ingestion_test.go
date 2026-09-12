package vulndb

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestSQLiteUpdatePreservesFirstIngestionAndExactFeed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	legacySQLiteFixture(t, dir, nil)
	body := fixtureZip(t, map[string]string{"legacy.json": osvFixture("CVE-2026-7777", "npm", "old"), "new.json": osvFixture("CVE-2026-9999", "npm", "new")})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	client := httpx.New(time.Minute)
	client.HTTP.Transport = srv.Client().Transport
	opts := Options{Sources: []string{SourceOSV}, Ecosystems: []string{"npm"}, OSVBaseURL: srv.URL, Client: client}
	first, err := Update(context.Background(), dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) Record {
		t.Helper()
		st, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		rs, err := st.Lookup("npm", name)
		if err != nil || len(rs) != 1 {
			t.Fatalf("lookup %s: %+v %v", name, rs, err)
		}
		return rs[0]
	}
	old, newRecord := read("old"), read("new")
	if !old.AddedAt.IsZero() || !old.LastSeenAt.Equal(first.UpdatedAt) {
		t.Fatal("legacy unknown added time was invented")
	}
	if !newRecord.AddedAt.Equal(first.UpdatedAt) || !newRecord.LastSeenAt.Equal(first.UpdatedAt) {
		t.Fatal("new advisory lacks actual collection time")
	}
	if !reflect.DeepEqual(newRecord.Provenance, []RecordSource{{Name: SourceOSV, URL: srv.URL + "/npm/all.zip"}}) {
		t.Fatalf("feed provenance not exact: %+v", newRecord.Provenance)
	}
	second, err := Update(context.Background(), dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	updated := read("new")
	if !updated.AddedAt.Equal(first.UpdatedAt) || !updated.LastSeenAt.Equal(second.UpdatedAt) {
		t.Fatal("refresh changed first ingestion or failed to advance observation")
	}
	old = read("old")
	if !old.AddedAt.IsZero() {
		t.Fatal("unknown legacy AddedAt changed on later refresh")
	}
	dest := filepath.Join(t.TempDir(), "converted")
	meta, err := Convert(context.Background(), dir, dest, Options{Offline: true})
	if err != nil || !meta.UpdatedAt.Equal(second.UpdatedAt) {
		t.Fatal("conversion freshness changed", err)
	}
	st, err := Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.Lookup("npm", "new")
	if err != nil || len(got) != 1 || !got[0].AddedAt.Equal(updated.AddedAt) || !got[0].LastSeenAt.Equal(updated.LastSeenAt) {
		t.Fatal("conversion changed ingestion times", err)
	}
	db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dest, SQLiteFileName), true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var added sql.NullString
	if err = db.QueryRow("SELECT added_at FROM records WHERE id='CVE-2026-7777'").Scan(&added); err != nil || added.Valid {
		t.Fatal("unknown added time must be SQL NULL", err)
	}
}
