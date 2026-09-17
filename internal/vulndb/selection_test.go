package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestSelectionOldManifest(t *testing.T) {
	for _, tc := range []struct {
		name, manifest string
		ecosystems     []string
	}{
		{"no feed selection", `{"schema_version":1,"ecosystems":["Ubuntu:24.04:LTS"]}`, DefaultOSVEcosystems},
		{"feed selection", `{"schema_version":1,"ecosystems":["Ubuntu:24.04:LTS"],"sources":[{"name":"osv","ecosystems":["Ubuntu"]},{"name":"alpine-secdb","ecosystems":["Alpine"]},{"name":"osv","ecosystems":["npm","Ubuntu"]}]}`, []string{"Ubuntu", "npm"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var meta Meta
			if err := json.Unmarshal([]byte(tc.manifest), &meta); err != nil {
				t.Fatal(err)
			}
			got := meta.EffectiveSelection()
			if !reflect.DeepEqual(got.Ecosystems, tc.ecosystems) || !reflect.DeepEqual(got.Sources, DefaultSources) || !reflect.DeepEqual(got.AlpineReleases, DefaultAlpineReleases) || got.NVDEnabled {
				t.Fatalf("legacy selection %+v", got)
			}
		})
	}
}

func TestSelectionNVDDefaults(t *testing.T) {
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	current := now.Year()
	var defaults []string
	for year := current - 2; year <= current; year++ {
		defaults = append(defaults, strconv.Itoa(year))
	}
	// The rolling default must persist as empty so a sticky selection keeps
	// following the current year instead of freezing this year's list.
	for _, spec := range []string{"", "default", "defaults", "default,defaults"} {
		s, err := (Selection{Sources: []string{"nvd"}, NVDYears: spec}).normalize(now)
		if err != nil || s.NVDYears != "" || !s.NVDEnabled {
			t.Fatalf("%q: %+v %v", spec, s, err)
		}
		later := now.AddDate(3, 0, 0)
		if years, err := parseNVDYears(s.NVDYears, later); err != nil || years[len(years)-1] != later.Year() {
			t.Fatalf("%q did not roll forward: %v %v", spec, years, err)
		}
	}
	for _, spec := range []string{"default," + strconv.Itoa(current), strconv.Itoa(current) + ",defaults"} {
		s, err := (Selection{Sources: []string{"nvd"}, NVDYears: spec}).normalize(now)
		if err != nil || !s.NVDEnabled || s.NVDYears == "" {
			t.Fatalf("%q: %+v %v", spec, s, err)
		}
		for _, year := range defaults {
			if !strings.Contains(s.NVDYears, year) {
				t.Fatalf("%q lost default year %s: %q", spec, year, s.NVDYears)
			}
		}
	}
	for _, spec := range []string{"bad", "2024,", "default,", ",defaults"} {
		if _, err := (Selection{Sources: []string{"nvd"}, NVDYears: spec}).normalize(now); err == nil {
			t.Fatalf("invalid years accepted: %q", spec)
		}
	}
}

func TestSelectionUpdatePersistsAndRecoversOldCatalog(t *testing.T) {
	body := fixtureZip(t, map[string]string{"fixture.json": osvFixture("CVE-2025-1234", "Ubuntu:24.04:LTS", "fixture")})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Ubuntu/all.zip" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = server.Client().Transport
	dir := filepath.Join(t.TempDir(), "db")
	opts := Options{Sources: []string{"osv"}, Ecosystems: []string{"Ubuntu"}, AlpineReleases: []string{"v3.20"}, OSVBaseURL: server.URL, Client: client}
	meta, err := Update(context.Background(), dir, opts, NVDOptions{Years: "2024"})
	if err != nil {
		t.Fatal(err)
	}
	want := Selection{Sources: []string{"osv"}, Ecosystems: []string{"Ubuntu"}, AlpineReleases: []string{"v3.20"}, NVDYears: "2024"}
	if meta.Selection == nil || !reflect.DeepEqual(*meta.Selection, want) {
		t.Fatalf("update metadata: %+v", meta.Selection)
	}
	var onDisk Meta
	if err := readJSON(filepath.Join(dir, "meta.json"), &onDisk); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(onDisk.Selection, meta.Selection) {
		t.Fatalf("manifest lost selection: %+v", onDisk)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Meta()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.Selection, meta.Selection) {
		t.Fatal("stored selection differs")
	}
	// Simulate a verified older manifest and unsupported SQLite encoding. Updating
	// must resolve from feed declarations without trying to open the old reader.
	onDisk.Selection = nil
	if err := writeJSON(filepath.Join(dir, "meta.json"), onDisk); err != nil {
		t.Fatal(err)
	}
	alterReaderCatalog(t, dir, "PRAGMA user_version=2; DELETE FROM metadata WHERE key='record_encoding'")
	opts.ResolveSelection = func(old Meta) (Selection, error) {
		s := old.EffectiveSelection()
		if !reflect.DeepEqual(s.Ecosystems, []string{"Ubuntu"}) {
			return s, fmt.Errorf("used record ecosystems: %v", s.Ecosystems)
		}
		s.Sources = []string{"osv"}
		return s, nil
	}
	meta, err = Update(context.Background(), dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Selection == nil || !reflect.DeepEqual(meta.Selection.Ecosystems, []string{"Ubuntu"}) {
		t.Fatalf("legacy update: %+v", meta)
	}
	// Failed resolution cannot alter the installed generation.
	before, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	opts.ResolveSelection = func(Meta) (Selection, error) { return Selection{}, fmt.Errorf("invalid selection") }
	if _, err = Update(context.Background(), dir, opts); err == nil {
		t.Fatal("accepted failed resolution")
	}
	after, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed resolution changed catalog")
	}
}
