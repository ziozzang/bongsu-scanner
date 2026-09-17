package vulndb

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func FuzzRedHatVEX(f *testing.F) {
	f.Add([]byte(vexFixture))
	f.Add([]byte(`{"document":{},"vulnerabilities":[]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(strings.Replace(vexFixture, `"branches":[{"branches":[`, `"branches":[`+strings.Repeat(`{},`, 1024)+`{"branches":[`, 1)))
	f.Add([]byte(strings.Replace(vexFixture, `"relationships":[`, `"relationships":[`+strings.Repeat(`{"category":"default_component_of","full_product_name":{"product_id":"no-colon"},"product_reference":"pkg.src","relates_to_product_reference":"rhel9"},`, 1024), 1)))
	f.Add([]byte(strings.ReplaceAll(vexFixture, `"affected"`, `"product-without-colon"`)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		var r *Record
		doc, err := decodeRedHatVEX(context.Background(), bytes.NewReader(data))
		if err == nil {
			r, err = convertRedHatVEX(context.Background(), doc)
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
