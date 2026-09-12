package match

import (
	"context"
	"fmt"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"testing"
)

func BenchmarkRun20KSubjectsRepeatedPackages(b *testing.B) {
	store := &benchmarkStore{records: make(map[string][]vulndb.Record)}
	subjects := make([]Subject, 20000)
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("pkg-%d", i)
		rec := advisory("PyPI", name, "2.0")
		rec.Affected[0].Versions = []string{"0.1", "0.2", "1.0", "1.1"}
		store.records[name] = []vulndb.Record{rec}
	}
	for i := range subjects {
		subjects[i] = Subject{Ref: fmt.Sprint(i), Name: fmt.Sprintf("pkg-%d", i%100), Ecosystem: "PyPI", Version: "1.0"}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report, err := Run(context.Background(), store, subjects, Options{})
		if err != nil || len(report.Findings) != len(subjects) {
			b.Fatalf("findings=%d err=%v", len(report.Findings), err)
		}
	}
}
