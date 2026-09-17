package vulndb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestMaintainedOSVExports(t *testing.T) {
	var logs []string
	opts := Options{Ecosystems: []string{"Ubuntu:24.04", "Ubuntu:24.04:LTS", "Ubuntu:Pro:24.04:LTS", "Ubuntu", "Debian:13", "Debian", "Alpine:v3.20", "Alpine", "Red Hat:9"}, Progress: func(s string) { logs = append(logs, s) }}
	feeds, err := (osvSource{}).Feeds(&opts)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range feeds {
		got = append(got, f.Ecosystems[0])
		if f.URL != DefaultOSVBaseURL+"/"+f.Ecosystems[0]+"/all.zip" || strings.Contains(f.Key, ":") {
			t.Errorf("frozen URL/key: %+v", f)
		}
	}
	if want := []string{"Ubuntu", "Debian", "Alpine", "Red Hat"}; !reflect.DeepEqual(got, want) {
		t.Errorf("exports=%v want %v", got, want)
	}
	if len(logs) != 1 || !strings.Contains(strings.Join(logs, "\n"), "frozen 2024-10") || !strings.Contains(strings.Join(logs, "\n"), "base exports") {
		t.Errorf("mapping log=%v", logs)
	}
	selection, err := (Selection{Ecosystems: opts.Ecosystems}).Normalize()
	if err != nil || !reflect.DeepEqual(selection.Ecosystems, got) {
		t.Errorf("selection=%+v err=%v", selection, err)
	}
	// Invalid suffixes must not disappear during base mapping.
	for _, bad := range []string{"Ubuntu:24.04/evil", "Debian:13?x", "Alpine:v3.20#x"} {
		if _, err := (osvSource{}).Feeds(&Options{Ecosystems: []string{bad}}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestMaintainedFeedDefaultBound(t *testing.T) {
	if DefaultMaxFeedBytes != 1<<30 {
		t.Fatalf("default bound=%d, want 1 GiB", DefaultMaxFeedBytes)
	}
}

func sourceDataThrough(t *testing.T, source SourceMeta) string {
	t.Helper()
	b, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	value, _ := fields["data_through"].(string)
	return value
}

func TestFeedFreshnessRoundTripAndOldCatalog(t *testing.T) {
	const newest = "2024-10-08T12:00:00Z"
	records := map[string]string{}
	for i, modified := range []string{"2024-10-01T00:00:00Z", newest, "2024-10-08T13:00:00+02:00", "invalid", ""} {
		records[fmt.Sprintf("%d.json", i)] = fmt.Sprintf(`{"id":"CVE-2024-%04d","modified":%q,"affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"fixture"},"versions":["1"]}]}`, 1000+i, modified)
	}
	raw := fixtureZip(t, records)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Ubuntu/all.zip" {
			t.Errorf("frozen export requested: %s", r.URL.Path)
		}
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"fixture"`)
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = srv.Client().Transport
	dir := filepath.Join(t.TempDir(), "db")
	opts := Options{Sources: []string{SourceOSV}, Ecosystems: []string{"Ubuntu:24.04:LTS", "Ubuntu:Pro:24.04:LTS"}, OSVBaseURL: srv.URL, Client: client}
	for iteration := 0; iteration < 3; iteration++ {
		var logs []string
		opts.Progress = func(message string) { logs = append(logs, message) }
		if iteration == 2 {
			opts.ResolveSelection = func(old Meta) (Selection, error) { return old.EffectiveSelection(), nil }
		}
		meta, err := Update(context.Background(), dir, opts)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(strings.Join(logs, "\n"), "frozen 2024-10") != 1 {
			t.Errorf("update %d mapping logs=%v", iteration, logs)
		}
		if len(meta.Sources) != 1 {
			t.Fatalf("duplicate feeds: %+v", meta.Sources)
		}
		if got := sourceDataThrough(t, meta.Sources[0]); got != newest {
			t.Fatalf("update %d data through=%q", iteration, got)
		}
		if !reflect.DeepEqual(meta.Selection.Ecosystems, []string{"Ubuntu"}) {
			t.Fatalf("persisted frozen selection: %+v", meta.Selection)
		}
		var manifest Meta
		if err := readJSON(filepath.Join(dir, "meta.json"), &manifest); err != nil {
			t.Fatal(err)
		}
		if got := sourceDataThrough(t, manifest.Sources[0]); got != newest {
			t.Fatalf("manifest=%q", got)
		}
		st, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := st.Meta()
		if err != nil {
			t.Fatal(err)
		}
		if err = st.Close(); err != nil {
			t.Fatal(err)
		}
		if got := sourceDataThrough(t, stored.Sources[0]); got != newest {
			t.Fatalf("SQLite metadata=%q", got)
		}
		db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dir, SQLiteFileName), false))
		if err != nil {
			t.Fatal(err)
		}
		var stamp string
		err = db.QueryRow("SELECT data_through FROM sources").Scan(&stamp)
		if err != nil || stamp != newest {
			db.Close()
			t.Fatalf("SQLite source date=%q err=%v", stamp, err)
		}
		if iteration == 1 {
			// Reproduce a pre-column catalog and a 304 cache without freshness metadata.
			data, _ := json.Marshal(meta)
			var legacy map[string]any
			if err = json.Unmarshal(data, &legacy); err != nil {
				t.Fatal(err)
			}
			legacy["selection"].(map[string]any)["ecosystems"] = []string{"Ubuntu:24.04:LTS", "Ubuntu:Pro:24.04:LTS"}
			for _, value := range legacy["sources"].([]any) {
				delete(value.(map[string]any), "data_through")
			}
			data, err = json.Marshal(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("ALTER TABLE sources DROP COLUMN data_through"); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("UPDATE metadata SET value=? WHERE key='meta'", string(data)); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "meta.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err = db.Close(); err != nil {
			t.Fatal(err)
		}
		if iteration == 1 {
			if err = os.Remove(filepath.Join(dir, "manifest.sha256")); err != nil {
				t.Fatal(err)
			}
			if err = writeManifest(dir, Options{}); err != nil {
				t.Fatal(err)
			}
			st, err := Open(dir)
			if err != nil {
				t.Fatalf("old catalog rejected: %v", err)
			}
			old, err := st.Meta()
			if err != nil {
				t.Fatal(err)
			}
			st.Close()
			if got := sourceDataThrough(t, old.Sources[0]); got != "" {
				t.Fatalf("old catalog date=%q", got)
			}
		}
	}
}
