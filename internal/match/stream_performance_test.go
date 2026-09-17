package match

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type visitorTestStore struct {
	*fakeStore
	visits int
	fail   error
}

func (s *visitorTestStore) LookupFunc(ctx context.Context, eco, name string, fn func(*vulndb.Record) error) error {
	s.visits++
	for i := range s.records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(&s.records[i]); err != nil {
			return err
		}
	}
	return s.fail
}

func TestVisitorMatchesLegacyAndDeduplicatesLastQuery(t *testing.T) {
	rec := advisory("Debian:13", "linux", "2")
	rec.Details = "complete assessment description"
	rec.Aliases = []string{"GHSA-fixture"}
	withdrawn := rec
	withdrawn.ID, withdrawn.Withdrawn = "CVE-2026-9999", "2026-01-01"
	records := []vulndb.Record{rec, withdrawn}
	subjects := []Subject{{Ref: "one", Name: "linux", Upstream: "linux", Ecosystem: "Debian", Type: "deb", Version: "1", Release: "13"}}
	for _, details := range []bool{false, true} {
		legacy := &fakeStore{records: records}
		visitor := &visitorTestStore{fakeStore: &fakeStore{records: records}}
		want, err := Run(context.Background(), legacy, subjects, Options{Details: details, Now: func() time.Time { return time.Unix(0, 0) }})
		if err != nil {
			t.Fatal(err)
		}
		got, err := Run(context.Background(), visitor, subjects, Options{Details: details, Now: func() time.Time { return time.Unix(0, 0) }})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("visitor changed report or assessment text")
		}
		if legacy.calls != 1 || visitor.visits != 1 || visitor.calls != 0 {
			t.Fatalf("lookups: legacy=%d visitor=%d fallback=%d", legacy.calls, visitor.visits, visitor.calls)
		}
		if got.Skipped["withdrawn"] != 2 {
			t.Fatal("deduplication changed per-query skip counts")
		}
	}
	sentinel := errors.New("late visitor failure")
	visitor := &visitorTestStore{fakeStore: &fakeStore{records: records}, fail: sentinel}
	if _, err := Run(context.Background(), visitor, subjects, Options{}); !errors.Is(err, sentinel) {
		t.Fatalf("lost lookup error: %v", err)
	}
}

func TestCompactFilePreservesEditableLoadSemantics(t *testing.T) {
	fixtures := []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"x","Name":"ignored","version":null,"type":"library","custom":9007199254740993}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"root","components":[{"name":"child"}]}},"components":[{"name":"x","components":[{"name":"nested"}]}],"signature":{"value":"old"}}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"root","properties":[{"name":"bscan:host:operating-system","value":"debian"},{"name":"bscan:host:os-version","value":"13"}]}},"components":[{"bom-ref":"x","purl":"pkg:deb/debian/x@1"},{"type":"operating-system","name":"ubuntu","version":"24.04"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"root","name":"x","versionInfo":"1"}]}`,
	}
	for i, input := range fixtures {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			want, err := Load([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			got, err := loadCompactFile([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Subjects, want.Subjects) || !reflect.DeepEqual(got.Context, want.Context) {
				t.Fatal("subjects or context changed")
			}
			a, _ := json.Marshal(want.Raw)
			b, _ := json.Marshal(got.Raw)
			var x, y any
			if err := json.Unmarshal(a, &x); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &y); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(x, y) {
				t.Fatalf("raw values changed:\n%s\n%s", a, b)
			}
		})
	}
}

func TestCycloneDXStreamsFindingChunks(t *testing.T) {
	r := Report{GeneratedAt: time.Unix(0, 0), Findings: make([]Finding, 1000)}
	for i := range r.Findings {
		r.Findings[i] = Finding{ID: fmt.Sprint(i), Subject: Subject{Ref: fmt.Sprint(i)}, Record: RecordSummary{Summary: strings.Repeat("x", 500)}}
	}
	out := &chunkBoundedWriter{max: 4096}
	if err := Write(out, "cyclonedx", r, Document{Format: "cyclonedx", Raw: map[string]any{"version": float64(1)}}); err != nil {
		t.Fatal(err)
	}
	var decoded struct{ Vulnerabilities []json.RawMessage }
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Vulnerabilities) != 1000 {
		t.Fatal("lost vulnerabilities")
	}
	var reserved bytes.Buffer
	if err := Write(&reserved, "json", r, Document{}); err != nil {
		t.Fatal(err)
	}
	var direct bytes.Buffer
	if err := encodeJSONReport(&direct, r); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reserved.Bytes(), direct.Bytes()) {
		t.Fatal("reservation changed JSON bytes")
	}
}
