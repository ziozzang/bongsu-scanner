package vulndb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type cancelDuringRead struct {
	cancel context.CancelFunc
	reads  int
}

func (r *cancelDuringRead) Read(p []byte) (int, error) {
	r.reads++
	n := copy(p, "first chunk")
	r.cancel()
	return n, nil
}

func TestContextReaderStopsDuringStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &cancelDuringRead{cancel: cancel}
	var dst bytes.Buffer
	_, err := io.Copy(&dst, contextReader{ctx: ctx, r: source})
	if !errors.Is(err, context.Canceled) || source.reads != 1 {
		t.Fatalf("copy error=%v reads=%d", err, source.reads)
	}
	if dst.String() != "first chunk" {
		t.Fatalf("unexpected copied bytes %q", dst.String())
	}
}

func TestCanceledCatalogOperationsDoNotCreateFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := filepath.Join(t.TempDir(), "absent")
	if _, err := OpenContext(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := VerifyContext(ctx, dir, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := cloneOrCopySQLiteContext(ctx, "missing", dir); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestOpenContextDoesNotTieStoreLifetimeToOpeningContext(t *testing.T) {
	dir := readerCatalog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := OpenContext(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cancel()
	if _, err := LookupContext(ctx, st, "npm", "example"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup: %v", err)
	}
	if _, err := LookupIDContext(ctx, st, "CVE-2025-1234"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ID lookup: %v", err)
	}
	records, err := st.Lookup("npm", "example")
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%d error=%v", len(records), err)
	}
}
