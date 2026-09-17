package match

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

// Generate independently owned records as a decoder would, without keeping a
// materialized 40K-record fixture alive alongside the matcher.
type largePackageStore struct{ calls int }

func (*largePackageStore) Lookup(string, string) ([]vulndb.Record, error) {
	return nil, fmt.Errorf("large package must use the visitor")
}
func (*largePackageStore) Ecosystems() ([]string, error) { return []string{"Debian:13"}, nil }
func (*largePackageStore) Meta() (vulndb.Meta, error)    { return vulndb.Meta{Records: 40000}, nil }
func (*largePackageStore) Close() error                  { return nil }
func (s *largePackageStore) LookupFunc(ctx context.Context, eco, name string, visit func(*vulndb.Record) error) error {
	s.calls++
	for i := 0; i < 40000; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := vulndb.Record{ID: "CVE-2026-" + strconv.Itoa(100000+i), Affected: make([]vulndb.Affected, 12)}
		for j := range r.Affected {
			r.Affected[j] = vulndb.Affected{Ecosystem: "Debian:13", Package: name, Ranges: []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}, {Fixed: "2"}}}}}
		}
		if err := visit(&r); err != nil {
			return err
		}
	}
	return nil
}

func largePackageSubjects(n int) []Subject {
	subjects := make([]Subject, n)
	for i := range subjects {
		subjects[i] = Subject{Ref: strconv.Itoa(i), Name: "linux", Ecosystem: "Debian", Release: "13", Version: "3"}
	}
	return subjects
}

func TestLargePackageAllocationsPerSubjectBounded(t *testing.T) {
	measure := func(n int) uint64 {
		t.Helper()
		s := new(largePackageStore)
		subjects := largePackageSubjects(n)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		r, err := Run(context.Background(), s, subjects, Options{})
		runtime.ReadMemStats(&after)
		if err != nil || len(r.Findings) != 0 || len(r.Skipped) != 0 || s.calls != 1 {
			t.Fatalf("subjects=%d calls=%d findings=%d skipped=%v error=%v", n, s.calls, len(r.Findings), r.Skipped, err)
		}
		return after.TotalAlloc - before.TotalAlloc
	}
	one, many := measure(1), measure(20)
	// Repeated binary subjects must reuse preparation. Allow runtime sampling
	// noise, but reject another 40K x 12 preparation for each subject.
	if many > one+19*(256<<10) {
		t.Fatalf("allocations scale with subjects: one=%d twenty=%d bytes", one, many)
	}
	t.Logf("one=%d twenty=%d bytes; additional subject budget=256 KiB", one, many)
}

func TestPreparedQuietMissesRetainOnlyIdentities(t *testing.T) {
	record := advisory("Debian:13", "linux", "2")
	records, err := lookupPrepared(context.Background(), &visitorTestStore{fakeStore: &fakeStore{records: []vulndb.Record{record}}}, newVersionCache(), false, "Debian", "linux", map[string]bool{"3": true}, map[string]bool{"13": true})
	if err != nil || len(records) != 1 || records[0].ID != record.ID || len(records[0].affected) != 0 || records[0].summary != nil {
		t.Fatalf("quiet miss retained match state: %+v, %v", records, err)
	}
}

func BenchmarkLargePackage40KRecords12Affected(b *testing.B) {
	for _, n := range []int{1, 20} {
		b.Run(strconv.Itoa(n)+"Subjects", func(b *testing.B) {
			subjects := largePackageSubjects(n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s := new(largePackageStore)
				r, err := Run(context.Background(), s, subjects, Options{})
				if err != nil || len(r.Findings) != 0 || s.calls != 1 {
					b.Fatalf("findings=%d calls=%d error=%v", len(r.Findings), s.calls, err)
				}
			}
		})
	}
}
