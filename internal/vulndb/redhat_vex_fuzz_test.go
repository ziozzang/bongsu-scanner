package vulndb

import (
	"context"
	"encoding/json"
	"testing"
)

func FuzzRedHatVEX(f *testing.F) {
	f.Add([]byte(vexFixture))
	f.Add([]byte(`{"document":{},"vulnerabilities":[]}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		var doc vexDocument
		var r *Record
		err := json.Unmarshal(data, &doc)
		if err == nil {
			r, err = convertRedHatVEX(context.Background(), &doc)
		}
		if err == nil {
			fuzzCheckRecord(t, r)
		}
		path := vexArchive(t, string(data))
		count := 0
		err = parseRedHatVEX(context.Background(), path, 2<<20, 1<<20, func(r *Record) error { fuzzCheckRecord(t, r); count++; return nil }, nil)
		if err == nil && (r != nil) != (count == 1) {
			t.Fatalf("direct=%v archive=%d", r != nil, count)
		}
	})
}
