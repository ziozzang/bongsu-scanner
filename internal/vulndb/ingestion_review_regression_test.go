package vulndb

import (
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
	"unicode/utf8"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func reviewOSV(t *testing.T, eco string) osvVuln {
	t.Helper()
	var v osvVuln
	if err := json.Unmarshal([]byte(osvFixture("CVE-2026-1234", eco, "curl")), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReviewConversionBounds(t *testing.T) {
	v := reviewOSV(t, "npm")
	v.Summary = strings.Repeat("환", 1000)
	v.Details = strings.Repeat("x", MaxDetails+1)
	v.Aliases = []string{strings.Repeat("A", 129)}
	for i := 0; i < 110; i++ {
		v.Aliases = append(v.Aliases, fmt.Sprintf("CVE-2026-%d", i))
		v.References = append(v.References, Reference{Type: "WEB", URL: fmt.Sprintf("https://example.org/%d", i)})
	}
	v.Affected[0].Versions = make([]string, 20001)
	for i := range v.Affected[0].Versions {
		v.Affected[0].Versions[i] = fmt.Sprint(i)
	}
	r, ok := ConvertOSV(&v, SourceOSV)
	if !ok || len(r.Summary) > 1024 || !utf8.ValidString(r.Summary) || len(r.Details) > MaxDetails || !r.DetailsTruncated {
		t.Fatalf("conversion did not bound text: summary=%d", len(r.Summary))
	}
	if len(r.Aliases) > 100 || len(r.References) > 100 || len(r.Affected[0].Versions) != 20001 {
		t.Fatalf("unbounded lists: aliases=%d references=%d versions=%d", len(r.Aliases), len(r.References), len(r.Affected[0].Versions))
	}
	for _, alias := range r.Aliases {
		if len(alias) > 128 {
			t.Fatal("oversized alias retained")
		}
	}
	v.References[0].URL = "changed"
	v.Affected[0].Versions[0] = "changed"
	if r.References[0].URL == "changed" || r.Affected[0].Versions[0] == "changed" {
		t.Fatal("converted list shares the unbounded input backing array")
	}
}

func TestReviewAffectedSeverity(t *testing.T) {
	var v osvVuln
	if err := json.Unmarshal([]byte(`{"id":"CVE-2026-1234","affected":[{"package":{"ecosystem":"npm","name":"curl"},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}`), &v); err != nil {
		t.Fatal(err)
	}
	r, ok := ConvertOSV(&v, SourceOSV)
	if !ok || len(r.Affected[0].Severity) != 1 || len(r.Severity) != 0 {
		t.Fatalf("package severity lost: %+v", r)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var stored Record
	if err := json.Unmarshal(b, &stored); err != nil || !reflect.DeepEqual(stored.Affected[0].Severity, r.Affected[0].Severity) {
		t.Fatalf("severity not persisted: %s %v", b, err)
	}
}

func TestReviewNativeAffectedMetadata(t *testing.T) {
	for _, native := range []string{SourceDebian, SourceAlpine} {
		for _, reverse := range []bool{false, true} {
			for _, withPURL := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/reverse=%v/purl=%v", native, reverse, withPURL), func(t *testing.T) {
					eco := "Debian:sid"
					if native == SourceAlpine {
						eco = "Alpine:v3.20"
					}
					v := reviewOSV(t, eco)
					osv, _ := ConvertOSV(&v, SourceOSV)
					osv.Affected[0].Database = map[string]any{"urgency": "high", "osv": true, "nested": map[string]any{"osv": true, "urgency": "high"}}
					osv.Affected[0].Specific = map[string]any{"urgency": "high", "osv": true}
					a := osv.Affected[0]
					if withPURL {
						a.PURL = "pkg:deb/debian/curl?distro=sid"
						if native == SourceAlpine {
							a.PURL = "pkg:apk/alpine/curl?distro=3.20"
						}
					}
					a.Database = map[string]any{"urgency": "unimportant", "native": true, "nested": map[string]any{"native": true, "urgency": "unimportant"}}
					a.Specific = map[string]any{"urgency": "unimportant", "native": true}
					a.Severity = []Severity{{Type: "CVSS_V3", Score: "low"}}
					distro := &Record{ID: osv.ID, Source: native, Affected: []Affected{a}}
					if reverse {
						osv, distro = distro, osv
					}
					Merge(osv, distro)
					if len(osv.Affected) != 1 {
						t.Fatalf("duplicate package/ranges retained: %+v", osv.Affected)
					}
					for _, m := range []map[string]any{osv.Affected[0].Database, osv.Affected[0].Specific, osv.Affected[0].Database["nested"].(map[string]any)} {
						if m["urgency"] != "unimportant" || m["native"] != true || m["osv"] != true {
							t.Fatalf("native metadata lost: %v", m)
						}
					}
					if len(osv.Affected[0].Severity) != 1 {
						t.Fatal("merged package severity lost")
					}
				})
			}
		}
	}
}

func TestReviewDebianSidIngestion(t *testing.T) {
	for _, release := range []string{"sid", "unstable"} {
		v := reviewOSV(t, "Debian:"+release)
		r, _ := ConvertOSV(&v, SourceOSV)
		if r.Affected[0].Ecosystem != "Debian:sid" {
			t.Errorf("OSV %s: %s", release, r.Affected[0].Ecosystem)
		}
		p := filepath.Join(t.TempDir(), "debian.json")
		if err := os.WriteFile(p, []byte(fmt.Sprintf(`{"curl":{"CVE-2026-1234":{"releases":{%q:{"status":"open"}}}}}`, release)), 0600); err != nil {
			t.Fatal(err)
		}
		if err := parseDebianTracker(context.Background(), p, func(r *Record) error {
			if r.Affected[0].Ecosystem != "Debian:sid" || r.Affected[0].Database["release"] != release {
				t.Errorf("tracker %s: %+v", release, r.Affected[0])
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReviewAffectedOrdering(t *testing.T) {
	var affected []Affected
	for _, fixed := range []string{"1.10-r0", "1.2-r10", "1.2-r2", "1.2_rc1-r0"} {
		affected = append(affected, Affected{Ecosystem: "Alpine:v3.20", Package: "curl", Ranges: []Range{{Events: []Event{{Introduced: "0"}, {Fixed: fixed}}}}})
	}
	sortAffected(affected)
	for i, want := range []string{"1.2_rc1-r0", "1.2-r2", "1.2-r10", "1.10-r0"} {
		if got := affected[i].Ranges[0].Events[1].Fixed; got != want {
			t.Fatalf("position %d: got %s want %s", i, got, want)
		}
	}
}

func TestReviewParserErrorEscaping(t *testing.T) {
	name := "bad\x1b[31m"
	p := filepath.Join(t.TempDir(), "debian.json")
	key, _ := json.Marshal(name)
	if err := os.WriteFile(p, []byte("{"+string(key)+": false}"), 0600); err != nil {
		t.Fatal(err)
	}
	err := parseDebianTracker(context.Background(), p, func(*Record) error { return nil })
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\r\n") {
		t.Errorf("unsafe Debian error: %q", err)
	}
	p = filepath.Join(t.TempDir(), "osv.zip")
	if err := os.WriteFile(p, fixtureZip(t, map[string]string{name + ".json": "{"}), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = parseOSVZip(context.Background(), p, SourceOSV, nil, func(*Record) error { return nil }, nil)
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\r\n") {
		t.Errorf("unsafe OSV error: %q", err)
	}
}

type reviewIngestionSource struct{ feeds []Feed }

func (reviewIngestionSource) Name() string                     { return "review-ingestion-test" }
func (s reviewIngestionSource) Feeds(*Options) ([]Feed, error) { return s.feeds, nil }

func TestReviewUpdateStreamsCacheAndEscapesErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer srv.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = srv.Client().Transport
	sentinel := errors.New("bad\x1b[31m feed")
	key := "test\x1b[31m"
	var sawCache, secondParsed bool
	source := reviewIngestionSource{feeds: []Feed{
		{Source: "review-ingestion-test", Key: key, File: "one.json", URL: srv.URL + "/one", Parse: func(_ context.Context, p string, _ int64, emit Emit, progress func(string)) error {
			v := reviewOSV(t, "npm")
			r, _ := ConvertOSV(&v, SourceOSV)
			if err := emit(r); err != nil {
				return err
			}
			stage := filepath.Dir(filepath.Dir(filepath.Dir(p)))
			_, err := os.Stat(filepath.Join(stage, "cache", "review-ingestion-test", key+".jsonl.gz"))
			sawCache = err == nil
			progress("parser\x1b[31m progress")
			return sentinel
		}},
		{Source: "review-ingestion-test", Key: "two", File: "two.json", URL: srv.URL + "/two", Parse: func(context.Context, string, int64, Emit, func(string)) error { secondParsed = true; return nil }},
	}}
	old, existed := registry[source.Name()]
	RegisterSource(source.Name(), func() Source { return source })
	t.Cleanup(func() {
		if existed {
			registry[source.Name()] = old
		} else {
			delete(registry, source.Name())
		}
	})
	var logs []string
	dir := filepath.Join(t.TempDir(), "db")
	meta, err := Update(context.Background(), dir, Options{Sources: []string{source.Name()}, Client: client, Progress: func(s string) { logs = append(logs, s) }})
	if !errors.Is(err, sentinel) || !secondParsed || len(meta.Sources) != 2 {
		t.Fatalf("failure isolation/error chain lost: %+v %v", meta, err)
	}
	if !sawCache {
		t.Error("record accumulated before cache was opened")
	}
	if strings.ContainsAny(err.Error(), "\x1b\r") || strings.ContainsAny(strings.Join(logs, ""), "\x1b\r") {
		t.Errorf("unsafe final error/logs: %q %q", err, logs)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed feed installed a database: %v", err)
	}
}
