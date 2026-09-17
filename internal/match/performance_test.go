package match

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

// TestRealInputProfile is opt-in so ordinary tests need no external database.
// go test -run TestRealInputProfile -cpuprofile cpu.out ./internal/match
func TestRealInputProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("large fixture or external integration; run without -short")
	}
	db, input := os.Getenv("MATCH_PROFILE_DB"), os.Getenv("MATCH_PROFILE_SBOM")
	if db == "" || input == "" {
		t.Skip("set MATCH_PROFILE_DB and MATCH_PROFILE_SBOM")
	}
	store, err := vulndb.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	doc, err := LoadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), store, doc.Subjects, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("subjects=%d findings=%d", report.Subjects, len(report.Findings))
}

type benchmarkStore struct{ records map[string][]vulndb.Record }

func (s *benchmarkStore) Lookup(eco, name string) ([]vulndb.Record, error) {
	return s.records[name], nil
}
func (*benchmarkStore) Ecosystems() ([]string, error) { return []string{"PyPI"}, nil }
func (*benchmarkStore) Meta() (vulndb.Meta, error)    { return vulndb.Meta{Records: 100000}, nil }
func (*benchmarkStore) Close() error                  { return nil }

func BenchmarkRun20KSubjects100KRecords(b *testing.B) {
	store := &benchmarkStore{records: make(map[string][]vulndb.Record)}
	subjects := make([]Subject, 20000)
	for i := 0; i < 1000; i++ {
		name := fmt.Sprintf("package-%d", i)
		for j := 0; j < 100; j++ {
			rec := advisory("PyPI", name, "2.0")
			rec.ID = fmt.Sprintf("CVE-2026-%d", i*100+j)
			rec.Affected[0].Versions = []string{"0.1", "0.2", "0.3", "1.0", "1.1", "1.2", "2.0"}
			store.records[name] = append(store.records[name], rec)
		}
	}
	for i := range subjects {
		subjects[i] = Subject{Ref: fmt.Sprintf("ref-%d", i), Name: fmt.Sprintf("package-%d", i%1000), Ecosystem: "PyPI", Version: "3.0"}
		if i%20 == 0 {
			subjects[i].Version = "1.0"
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report, err := Run(context.Background(), store, subjects, Options{})
		if err != nil {
			b.Fatal(err)
		}
		if len(report.Findings) != 100000 {
			b.Fatalf("findings=%d", len(report.Findings))
		}
	}
}
