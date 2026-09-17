package vulndb

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestRedHatEcosystemRelease(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Red Hat", ""}, {"Red Hat:9", "9"},
		{"Red Hat:enterprise_linux:9::appstream", "9"},
		{"Red Hat:enterprise_linux:8::baseos", "8"},
		{"Red Hat:enterprise_linux:7::server", "7"},
		{"Red Hat:enterprise_linux:10.0", "10"}, {"Red Hat:enterprise_linux:10.2", "10"},
		{"Red Hat:openshift:4.9", "openshift:4.9"},
		{"Red Hat:enterprise_linux:unknown::baseos", "enterprise_linux:unknown::baseos"},
	} {
		if got := EcosystemRelease(tc.in); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, stream := range []string{"rhel_eus", "rhel_e4s", "rhel_aus", "rhel_tus", "rhel_els", "rhel_eus_long_life", "enterprise_linux_eus"} {
		if got := EcosystemRelease("Red Hat:" + stream + ":9.4::appstream"); got != stream+":9.4" {
			t.Errorf("%s: %q", stream, got)
		}
	}
}

func TestRedHatConversionAndIndex(t *testing.T) {
	var input osvVuln
	if err := json.Unmarshal([]byte(`{"id":"RHSA-2026:1234","upstream":["CVE-2026-1234"],"affected":[{"package":{"ecosystem":"Red Hat:enterprise_linux:9::appstream","name":"kernel","purl":"pkg:rpm/redhat/kernel"}},{"package":{"ecosystem":"Red Hat:rhel_eus:9.4::appstream","name":"kernel"}}]}`), &input); err != nil {
		t.Fatal(err)
	}
	record, ok := ConvertOSV(&input, SourceOSV)
	if !ok || !slices.Contains(record.Aliases, "CVE-2026-1234") {
		t.Fatalf("conversion: %+v", record)
	}
	dir := t.TempDir()
	if err := buildIndexes(dir, map[string]*Record{record.ID: record}, &Meta{SchemaVersion: SchemaVersion}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dir, SQLiteFileName), true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct{ eco, rel string }{{"Red Hat:enterprise_linux:9::appstream", "9"}, {"Red Hat:rhel_eus:9.4::appstream", "rhel_eus:9.4"}} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM affected WHERE ecosystem=? AND release=?`, tc.eco, tc.rel).Scan(&n); err != nil || n != 1 {
			t.Fatalf("display/index %s: %d, %v", tc.eco, n, err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM package_affected WHERE base_ecosystem='Red Hat' AND name='kernel' AND release=?`, tc.rel).Scan(&n); err != nil || n != 1 {
			t.Fatalf("package index %s: %d, %v", tc.rel, n, err)
		}
	}
}

func TestDefaultRPMFeedsAndEscapedRequestPaths(t *testing.T) {
	for _, eco := range []string{"Red Hat", "Rocky Linux", "AlmaLinux"} {
		if !slices.Contains(DefaultOSVEcosystems, eco) {
			t.Errorf("default ecosystems missing %s", eco)
		}
	}
	for _, eco := range []string{"Ubuntu", "Chainguard"} {
		if slices.Contains(DefaultOSVEcosystems, eco) {
			t.Errorf("oversized default: %s", eco)
		}
	}
	paths := make(chan string, 2)
	body := fixtureZip(t, map[string]string{"record.json": osvFixture("RHSA-2026:1234", "Red Hat:enterprise_linux:9::baseos", "kernel")})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { paths <- r.RequestURI; _, _ = w.Write(body) }))
	defer srv.Close()
	client := httpx.New(time.Minute)
	client.HTTP.Transport = srv.Client().Transport
	_, err := Update(context.Background(), filepath.Join(t.TempDir(), "db"), Options{Sources: []string{SourceOSV}, Ecosystems: []string{"Red Hat", "Rocky Linux"}, OSVBaseURL: srv.URL, Client: client, NoKeepRaw: true})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{<-paths, <-paths}
	slices.Sort(got)
	if !slices.Equal(got, []string{"/Red%20Hat/all.zip", "/Rocky%20Linux/all.zip"}) {
		t.Fatalf("wire paths: %v", got)
	}
}
