package match

import (
	"context"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

// Isolate the input loader's peak from matcher allocations when attributing an
// end-to-end RSS limit. This test is opt-in and does not change loader behavior.
func TestLoadOnlyProfile(t *testing.T) {
	path := os.Getenv("MATCH_PROFILE_SBOM")
	if path == "" {
		t.Skip("set MATCH_PROFILE_SBOM")
	}
	doc, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("subjects=%d", len(doc.Subjects))
	runtime.KeepAlive(doc)
}

// TestRetainedLookupProfile captures live matcher state while a large lookup is
// still reachable, unlike the CLI's final heap profile after Run returns.
func TestRetainedLookupProfile(t *testing.T) {
	path := os.Getenv("MATCH_RETAINED_PROFILE")
	if path == "" {
		t.Skip("set MATCH_RETAINED_PROFILE, MATCH_PROFILE_DB and MATCH_PROFILE_SBOM")
	}
	s, err := vulndb.Open(os.Getenv("MATCH_PROFILE_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	doc, err := LoadFile(os.Getenv("MATCH_PROFILE_SBOM"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), retainedProfileStore{s, path}, doc.Subjects, Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(doc)
}

type retainedProfileStore struct {
	vulndb.Store
	path string
}

func (s retainedProfileStore) LookupFunc(ctx context.Context, eco, name string, visit func(*vulndb.Record) error) error {
	err := s.Store.(interface {
		LookupFunc(context.Context, string, string, func(*vulndb.Record) error) error
	}).LookupFunc(ctx, eco, name, visit)
	if err == nil && name == "linux-libc-dev" {
		runtime.GC()
		f, e := os.Create(s.path)
		if e != nil {
			return e
		}
		err = pprof.WriteHeapProfile(f)
		if e := f.Close(); err == nil {
			err = e
		}
	}
	return err
}
