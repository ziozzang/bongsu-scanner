package vulndb

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestSQLiteVisitorOwnershipCancellationAndErrors(t *testing.T) {
	store, err := Open(readerCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reader := store.(*sqliteStore)
	want, err := store.Lookup("npm", "example")
	if err != nil {
		t.Fatal(err)
	}
	var got []Record
	if err := reader.LookupFunc(context.Background(), "npm", "example", func(r *Record) error { got = append(got, *r); return nil }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("visitor changed records")
	}
	got[0].Affected[0].Package = "mutated"
	again, err := store.Lookup("npm", "example")
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatal("callback mutated stored records")
	}
	sentinel := errors.New("stop callback")
	if err := reader.LookupFunc(context.Background(), "npm", "example", func(*Record) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("lost callback error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := reader.LookupFunc(ctx, "npm", "example", func(*Record) error { t.Fatal("called after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	if _, err := store.Lookup("npm", "example"); err != nil {
		t.Fatalf("query resources leaked: %v", err)
	}
}

func TestReusedSQLiteDecoderChecksumsCapsAndOwnership(t *testing.T) {
	compress := func(body io.Reader) []byte {
		t.Helper()
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		if _, err := io.Copy(w, body); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	one := compress(strings.NewReader(`{"id":"one","affected":[{"ecosystem":"npm","package":"x","versions":["1"]}]}`))
	two := compress(strings.NewReader(`{"id":"two","affected":[]}`))
	decoder := new(sqliteReadDecoder)
	var first, second Record
	if err := decoder.decode(one, &first); err != nil {
		t.Fatal(err)
	}
	if err := decoder.decode(two, &second); err != nil {
		t.Fatal(err)
	}
	if first.ID != "one" || first.Affected[0].Versions[0] != "1" || second.ID != "two" {
		t.Fatal("reused buffer changed previous record")
	}
	corrupt := bytes.Clone(one)
	corrupt[len(corrupt)-1] ^= 1
	for _, body := range [][]byte{corrupt, one[:len(one)-2], []byte("invalid zlib")} {
		if err := decoder.decode(body, new(Record)); err == nil {
			t.Fatal("accepted corrupt compressed record")
		}
	}
	if err := decoder.decode(two, new(Record)); err != nil {
		t.Fatalf("reset after error failed: %v", err)
	}
	// Reach the actual production 64 MiB expansion cap without a large input.
	expanded := compress(io.LimitReader(repeatedByteReader{}, 64<<20))
	if err := decoder.decode(expanded, new(Record)); err == nil || !strings.Contains(err.Error(), "expanded size limit") {
		t.Fatalf("expansion cap not enforced: %v", err)
	}
}

type repeatedByteReader struct{}

func (repeatedByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}
