package vulndb

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

const vexFixture = `{
 "document":{"title":"example CVE","aggregate_severity":{"text":"Important"},"tracking":{"id":"CVE-2025-12345","initial_release_date":"2025-01-01T00:00:00Z","current_release_date":"2025-02-01T00:00:00Z"}},
 "product_tree":{"branches":[{"branches":[
 {"product":{"product_id":"rhel9","product_identification_helper":{"cpe":"cpe:/o:redhat:enterprise_linux:9::baseos"}}},
 {"product":{"product_id":"eus","product_identification_helper":{"cpe":"cpe:/a:redhat:rhel_eus:9.4::appstream"}}},
 {"product":{"product_id":"other","product_identification_helper":{"cpe":"cpe:/a:redhat:openshift:4"}}},
 {"product":{"product_id":"AppStream-8.10.0.Z.MAIN.EUS:python39:3.9:8100020240412:abcd","product_identification_helper":{"cpe":"cpe:/a:redhat:enterprise_linux:8::appstream"}}}
 ]}],"relationships":[
 {"category":"default_component_of","full_product_name":{"product_id":"fixed"},"product_reference":"example-libs-1:2.0-3.el9.x86_64","relates_to_product_reference":"rhel9"},
 {"category":"default_component_of","full_product_name":{"product_id":"src"},"product_reference":"example-1:2.0-3.el9.src","relates_to_product_reference":"rhel9"},
 {"category":"default_component_of","full_product_name":{"product_id":"fixed-arch"},"product_reference":"example-libs-1:2.0-3.el9.aarch64","relates_to_product_reference":"rhel9"},
 {"category":"default_component_of","full_product_name":{"product_id":"affected"},"product_reference":"unfixed.src","relates_to_product_reference":"rhel9"},
 {"category":"default_component_of","full_product_name":{"product_id":"safe"},"product_reference":"safe","relates_to_product_reference":"rhel9"},
 {"category":"default_component_of","full_product_name":{"product_id":"investigate"},"product_reference":"investigate","relates_to_product_reference":"rhel9"},
 {"category":"default_component_of","full_product_name":{"product_id":"eus-fixed"},"product_reference":"example-0:1.0-4.el9_4.x86_64","relates_to_product_reference":"eus"},
 {"category":"default_component_of","full_product_name":{"product_id":"ignored"},"product_reference":"ignore","relates_to_product_reference":"other"},
 {"category":"default_component_of","full_product_name":{"product_id":"module"},"product_reference":"python39-0:3.9.2-2.module+el8.x86_64::python39:3.9","relates_to_product_reference":"AppStream-8.10.0.Z.MAIN.EUS:python39:3.9:8100020240412:abcd"}
 ]},
 "vulnerabilities":[{"cve":"CVE-2025-12345","product_status":{"fixed":["fixed","fixed-arch","src","eus-fixed","module"],"known_affected":["affected","ignored"],"known_not_affected":["safe"],"under_investigation":["investigate"]},
 "remediations":[{"category":"vendor_fix","url":"https://access.redhat.com/errata/RHSA-2025:1234","product_ids":["fixed","fixed-arch","src"]},{"category":"no_fix_planned","details":"Will not fix","product_ids":["affected"]}],
 "threats":[{"category":"impact","details":"Low","product_ids":["fixed","fixed-arch"]}],
 "scores":[{"cvss_v3":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},"products":["ignored"]},{"cvss_v3":{"vectorString":"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"},"products":["fixed"]}]}]}`

func vexDecode(t *testing.T, data string) *vexDocument {
	t.Helper()
	var doc vexDocument
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}
func vexArchive(t *testing.T, bodies ...string) string {
	t.Helper()
	var b bytes.Buffer
	zw, err := zstd.NewWriter(&b, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for i, body := range bodies {
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("../%d.json", i), Mode: 0600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vex.tar.zst")
	if err := os.WriteFile(path, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestRedHatVEXConversion(t *testing.T) {
	r, err := convertRedHatVEX(context.Background(), vexDecode(t, vexFixture))
	if err != nil || r == nil {
		t.Fatalf("%+v %v", r, err)
	}
	fuzzCheckRecord(t, r)
	if r.ID != "CVE-2025-12345" || r.Source != SourceRedHatVEX || r.Database["severity"] != "Important" || r.Published != "2025-01-01T00:00:00Z" || r.Modified != "2025-02-01T00:00:00Z" {
		t.Fatalf("metadata: %+v", r)
	}
	if len(r.Severity) != 1 || !strings.Contains(r.Severity[0].Score, "AV:L/") {
		t.Fatalf("severity: %v", r.Severity)
	}
	if len(r.Affected) != 7 {
		t.Fatalf("affected=%d %+v", len(r.Affected), r.Affected)
	}
	for _, a := range r.Affected {
		switch a.Package {
		case "example-libs":
			if firstFixedVersion(a) != "1:2.0-3.el9" || a.Database["advisory"] != "RHSA-2025:1234" || a.Database["source_package"] != "example" || a.Database["severity"] != "Low" {
				t.Fatalf("binary: %+v", a)
			}
		case "example":
			if strings.Contains(a.Ecosystem, "rhel_eus") && EcosystemRelease(a.Ecosystem) != "rhel_eus:9.4" {
				t.Fatalf("EUS: %+v", a)
			}
		case "unfixed":
			if a.Database["redhat_status"] != "will-not-fix" || firstFixedVersion(a) != "" || len(a.Ranges) != 1 {
				t.Fatalf("unfixed: %+v", a)
			}
		case "safe":
			if a.Database["redhat_status"] != "not-affected" || len(a.Ranges) != 0 {
				t.Fatalf("marker: %+v", a)
			}
		case "investigate":
			if a.Database["redhat_status"] != "under-investigation" {
				t.Fatalf("investigate: %+v", a)
			}
		case "python39":
			if a.Database["modularity"] != "python39:3.9" || firstFixedVersion(a) != "0:3.9.2-2.module+el8" {
				t.Fatalf("module: %+v", a)
			}
		default:
			t.Fatalf("unexpected affected: %+v", a)
		}
	}
}
func TestRedHatVEXArchiveBounds(t *testing.T) {
	path := vexArchive(t, vexFixture, "{", vexFixture+" {}", strings.Repeat("x", len(vexFixture)+1))
	count := 0
	var log string
	emit := func(*Record) error { count++; return nil }
	err := parseRedHatVEX(context.Background(), path, 1<<20, int64(len(vexFixture)), emit, func(s string) { log = s })
	if err != nil || count != 1 || !strings.Contains(log, "skipped_malformed=1 skipped_oversized=2") {
		t.Fatalf("count=%d log=%s err=%v", count, log, err)
	}
	if err := parseRedHatVEX(context.Background(), path, 512, osvEntryMaxBytes, emit, nil); err == nil {
		t.Fatal("expansion bound ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := parseRedHatVEX(ctx, path, 1<<20, osvEntryMaxBytes, emit, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if err := parseRedHatVEX(ctx, path, 1<<20, osvEntryMaxBytes, func(*Record) error { cancel(); return nil }, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid parse cancel: %v", err)
	}
	sentinel := errors.New("emit")
	if err := parseRedHatVEX(context.Background(), path, 1<<20, osvEntryMaxBytes, func(*Record) error { return sentinel }, nil); !errors.Is(err, sentinel) {
		t.Fatalf("emit: %v", err)
	}
	// A truncated frame must fail even if tar has already reached its EOF.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data[:len(data)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if err := parseRedHatVEX(context.Background(), path, 1<<20, osvEntryMaxBytes, emit, nil); err == nil {
		t.Fatal("truncated zstd accepted")
	}
}
func TestRedHatVEXStatusesAndScope(t *testing.T) {
	for _, status := range []string{"Affected", "Will not fix", "Fix deferred", "Out of support scope", "Under investigation"} {
		r, err := convertRedHatVEX(context.Background(), vexDecode(t, strings.ReplaceAll(vexFixture, "Will not fix", status)))
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range r.Affected {
			if a.Package == "unfixed" && a.Database["redhat_status"] != vexStatus(status) {
				t.Fatalf("%s: %+v", status, a)
			}
		}
	}
	for _, cpe := range []string{"cpe:/o:redhat:enterprise_linux:10.0", "cpe:/a:redhat:rhel_e4s:9.4::appstream", "cpe:/o:redhat:rhel_els:7"} {
		r, err := convertRedHatVEX(context.Background(), vexDecode(t, strings.ReplaceAll(vexFixture, "cpe:/o:redhat:enterprise_linux:9::baseos", cpe)))
		if err != nil {
			t.Fatal(err)
		}
		want := "Red Hat:" + strings.SplitN(cpe, ":", 4)[3]
		found := false
		for _, a := range r.Affected {
			found = found || a.Ecosystem == want
		}
		if !found {
			t.Fatalf("missing %s", want)
		}
	}
	for _, cpe := range []string{"cpe:/a:redhat:jboss:9", "cpe:/o:redhat:enterprise_linux:9evil"} {
		if vexCPE.MatchString(cpe) {
			t.Fatalf("accepted %s", cpe)
		}
	}
	doc := vexDecode(t, vexFixture)
	doc.Document.Tracking.ID = "CVE-2025-99999"
	if _, err := convertRedHatVEX(context.Background(), doc); err == nil {
		t.Fatal("conflicting identity accepted")
	}
	doc = vexDecode(t, vexFixture)
	doc.Document.Title = strings.Repeat("x", 10000)
	r, err := convertRedHatVEX(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	fuzzCheckRecord(t, r)
}
func TestRedHatVEXFeeds(t *testing.T) {
	archive := vexArchive(t, vexFixture)
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	index := "csaf_vex_2026-09-13.tar.zst"
	conditional := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "archive_latest.txt") {
			_, _ = fmt.Fprint(w, index)
			return
		}
		if r.Header.Get("If-None-Match") == `"vex"` && r.Header.Get("If-Modified-Since") == "yesterday" {
			conditional = true
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"vex"`)
		w.Header().Set("Last-Modified", "yesterday")
		_, _ = w.Write(data)
	}))
	defer server.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = server.Client().Transport
	source := redHatVEXSource{baseURL: server.URL}
	opts := Options{Client: client, MaxFeedBytes: 1 << 20}
	feeds, err := source.Feeds(&opts)
	// The archive feed plus the changes.csv delta feed.
	if err != nil || len(feeds) != 2 || feeds[1].Key != "vex-changes" {
		t.Fatalf("feeds=%v err=%v", feeds, err)
	}
	f := feeds[0]
	if f.MaxBytes != opts.MaxFeedBytes || f.Source != SourceRedHatVEX {
		t.Fatalf("feed=%+v", f)
	}
	raw := filepath.Join(t.TempDir(), "raw")
	result, err := fetchFeed(context.Background(), client, f, nil, raw, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	result, err = fetchFeed(context.Background(), client, f, &result.Meta, raw, false, time.Now())
	if err != nil || !result.NotModified || !conditional {
		t.Fatalf("conditional: %+v %v", result, err)
	}
	count := 0
	if err := f.Parse(context.Background(), raw, 0, func(*Record) error { count++; return nil }, nil); err != nil || count != 1 {
		t.Fatalf("parse count=%d err=%v", count, err)
	}
	for _, bad := range []string{"../bad.tar.zst", "https://evil/archive.tar.zst", strings.Repeat("x", 4097)} {
		index = bad
		if _, err := source.Feeds(&opts); err == nil {
			t.Fatalf("accepted index %q", bad[:10])
		}
	}
	opts.Offline = true
	if _, err := source.Feeds(&opts); err == nil {
		t.Fatal("offline index fetched")
	}
}
func TestRedHatVEXSkipsOSVWithoutChangingSelection(t *testing.T) {
	s, ok := LookupSource("osv")
	if !ok {
		t.Fatal("no OSV")
	}
	sources := []string{SourceOSV, SourceRedHatVEX}
	ecos := []string{"Red Hat", "Debian"}
	var logs []string
	opts := Options{Sources: sources, Ecosystems: ecos, Progress: func(s string) { logs = append(logs, s) }}
	feeds, err := s.Feeds(&opts)
	if err != nil || len(feeds) != 1 || feeds[0].Ecosystems[0] != "Debian" || len(logs) != 1 {
		t.Fatalf("feeds=%+v logs=%v err=%v", feeds, logs, err)
	}
	if !reflect.DeepEqual(opts.Sources, []string{SourceOSV, SourceRedHatVEX}) || !reflect.DeepEqual(opts.Ecosystems, []string{"Red Hat", "Debian"}) {
		t.Fatal("selection changed")
	}
	opts.Sources = []string{SourceOSV}
	feeds, err = s.Feeds(&opts)
	if err != nil || len(feeds) != 2 {
		t.Fatalf("restore: %v %v", feeds, err)
	}
	opts.Sources = sources
	opts.Ecosystems = []string{"Red Hat"}
	feeds, err = s.Feeds(&opts)
	if err != nil || len(feeds) != 0 {
		t.Fatalf("only Red Hat: %v %v", feeds, err)
	}
	for _, s := range DefaultSources {
		if s == SourceRedHatVEX {
			t.Fatal("VEX must be opt-in")
		}
	}
}

func TestRedHatVEXSelectionPersistsAndRestoresOSV(t *testing.T) {
	archive := vexArchive(t, vexFixture)
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	zipPath := fuzzZipFile(t, map[string][]byte{"a.json": []byte(`{"id":"RHSA-2025:1234","affected":[{"package":{"ecosystem":"Red Hat:enterprise_linux:9","name":"example"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]}]}`)})
	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	osvRequests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "archive_latest.txt"):
			_, _ = fmt.Fprint(w, "csaf_vex_2026-09-13.tar.zst")
		case strings.HasSuffix(r.URL.Path, ".tar.zst"):
			_, _ = w.Write(data)
		case strings.HasSuffix(r.URL.Path, "changes.csv"), strings.HasSuffix(r.URL.Path, "deletions.csv"):
			// No deltas: an empty list is a valid response.
		default:
			osvRequests++
			_, _ = w.Write(zipData)
		}
	}))
	defer server.Close()
	factory := registry[SourceRedHatVEX]
	registry[SourceRedHatVEX] = func() Source { return &redHatVEXSource{baseURL: server.URL} }
	defer func() { registry[SourceRedHatVEX] = factory }()
	client := httpx.New(time.Second)
	client.HTTP.Transport = server.Client().Transport
	opts := Options{Sources: []string{SourceOSV, SourceRedHatVEX}, Ecosystems: []string{"Red Hat"}, OSVBaseURL: server.URL, Client: client, NoKeepRaw: true}
	dir := filepath.Join(t.TempDir(), "db")
	meta, err := Update(context.Background(), dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	// Two VEX feeds (archive + deltas) and no OSV Red Hat download.
	if osvRequests != 0 || len(meta.Sources) != 2 || meta.Selection == nil || !reflect.DeepEqual(meta.Selection.Sources, opts.Sources) || !reflect.DeepEqual(meta.Selection.Ecosystems, opts.Ecosystems) {
		t.Fatalf("meta=%+v requests=%d", meta, osvRequests)
	}
	for _, source := range meta.Sources {
		if source.Name != SourceRedHatVEX || source.Error != "" || source.DeltaMalformed != 0 {
			t.Fatalf("unexpected source meta: %+v", source)
		}
	}
	opts.Sources = []string{SourceOSV}
	meta, err = Update(context.Background(), dir, opts)
	if err != nil || osvRequests != 1 || len(meta.Sources) != 1 || meta.Sources[0].Name != SourceOSV {
		t.Fatalf("restored meta=%+v requests=%d err=%v", meta, osvRequests, err)
	}
}

func TestRedHatVEXComponentModule(t *testing.T) {
	doc := vexDecode(t, vexFixture)
	for i := range doc.Tree.Relationships {
		if doc.Tree.Relationships[i].Product.ID == "module" {
			doc.Tree.Relationships[i].Parent = "rhel9"
		}
	}
	r, err := convertRedHatVEX(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range r.Affected {
		if a.Package == "python39" {
			found = true
			if a.Database["modularity"] != "python39:3.9" {
				t.Fatalf("%+v", a)
			}
		}
	}
	if !found {
		t.Fatal("module component lost")
	}
}

func TestRedHatVEXRemediationWithoutStatus(t *testing.T) {
	doc := vexDecode(t, vexFixture)
	doc.Vulnerabilities[0].Status.Affected = nil
	r, err := convertRedHatVEX(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range r.Affected {
		if a.Package == "unfixed" {
			found = true
			if a.Database["redhat_status"] != "will-not-fix" {
				t.Fatalf("%+v", a)
			}
		}
	}
	if !found {
		t.Fatal("no-fix remediation lost")
	}
}

func TestRedHatVEXBoundsAndCanceledConversion(t *testing.T) {
	doc := vexDecode(t, vexFixture)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := convertRedHatVEX(ctx, doc); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
	if name, _ := vexPackage(strings.Repeat("x", 1025)); name != "" {
		t.Fatal("unbounded package")
	}
	doc.Tree.Branches = []vexBranch{{}}
	for i := 0; i < 65; i++ {
		doc.Tree.Branches = []vexBranch{{Branches: doc.Tree.Branches}}
	}
	if _, err := convertRedHatVEX(context.Background(), doc); err == nil {
		t.Fatal("unbounded product nesting")
	}
	for _, component := range []string{"pkg-0:1.2-3.el9.x86_64", "pkg-0:1.2-3.el9.src", "pkg-0:1.2-3.el9.x86_64::python39:3.9"} {
		name, evr := vexPackage(component)
		if name != "pkg" || evr != "0:1.2-3.el9" {
			t.Fatalf("%s -> %s %s", component, name, evr)
		}
	}
}

func TestRedHatVEXRecordLimits(t *testing.T) {
	for _, limits := range [][2]int{{2, 1 << 20}, {100, 256}} {
		if _, err := convertRedHatVEXBounded(context.Background(), vexDecode(t, vexFixture), limits[0], limits[1]); err == nil {
			t.Fatalf("ignored limits %v", limits)
		}
	}
	if name, _ := vexPackage("pkg::" + strings.Repeat("x", 1024) + ":stream"); name != "" {
		t.Fatal("unbounded component module")
	}
}

func TestRedHatVEXTrailingJSON(t *testing.T) {
	path := vexArchive(t, vexFixture+" {}")
	emitted := 0
	var progress string
	err := parseRedHatVEX(context.Background(), path, 1<<20, osvEntryMaxBytes, func(*Record) error { emitted++; return nil }, func(s string) { progress = s })
	if err != nil || emitted != 0 || !strings.Contains(progress, "skipped_malformed=1") {
		t.Fatalf("emitted=%d progress=%s err=%v", emitted, progress, err)
	}
}
