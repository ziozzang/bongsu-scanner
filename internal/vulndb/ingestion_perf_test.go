package vulndb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestIngestionSpoolMatchesOrderedMerge(t *testing.T) {
	s, err := newIngestionSpool(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	want := map[string]*Record{}
	// Repeated IDs cross source boundaries; source order controls summary,
	// provenance and metadata precedence and must survive partitioning.
	for feed := 0; feed < 3; feed++ {
		for i := 0; i < 300; i++ {
			r := &Record{ID: fmt.Sprintf("OSV-%d", i), Source: fmt.Sprintf("source-%d", feed), Summary: fmt.Sprint(feed), Aliases: []string{fmt.Sprintf("ALIAS-%d", feed)}, Affected: []Affected{{Ecosystem: "npm", Package: "pkg", Versions: []string{"1.0"}, Database: map[string]any{"feed": fmt.Sprint(feed)}}}}
			addProvenance(r, RecordSource{Name: r.Source, URL: "https://example.com/feed"})
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.append(r.ID, append(b, '\n')); err != nil {
				t.Fatal(err)
			}
			if old := want[r.ID]; old != nil {
				Merge(old, r)
			} else {
				want[r.ID] = r
			}
		}
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	previous := map[string]time.Time{"OSV-0": {}, "OSV-1": now.Add(-time.Hour)}
	for id, r := range want {
		if at, ok := previous[id]; ok {
			r.AddedAt = at
		} else {
			r.AddedAt = now
		}
		r.LastSeenAt = now
	}
	var firstOrder []string
	for pass := 0; pass < 2; pass++ {
		var order []string
		err := s.visit(context.Background(), previous, now, func(r *Record) error {
			if !reflect.DeepEqual(r, want[r.ID]) {
				t.Fatalf("record changed: %s", r.ID)
			}
			order = append(order, r.ID)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(order) != len(want) {
			t.Fatalf("got %d records, want %d", len(order), len(want))
		}
		if pass == 0 {
			firstOrder = order
		} else if !reflect.DeepEqual(firstOrder, order) {
			t.Fatal("partition iteration is nondeterministic")
		}
	}
	wantErr := errors.New("stop emitting")
	if err := s.visit(context.Background(), previous, now, func(*Record) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("emit error lost: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.visit(ctx, previous, now, func(*Record) error { t.Fatal("emitted after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestParallelFeedsPreserveSelectionOrder(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer srv.Close()
	client := httpx.New(5 * time.Second)
	client.HTTP.Transport = srv.Client().Transport
	lastFinished := make(chan struct{})
	source := reviewIngestionSource{}
	for i := 0; i < 3; i++ {
		source.feeds = append(source.feeds, Feed{Source: source.Name(), Key: fmt.Sprint(i), File: fmt.Sprintf("%d.json", i), URL: fmt.Sprintf("%s/%d", srv.URL, i), Parse: func(ctx context.Context, _ string, _ int64, emit Emit, _ func(string)) error {
			if i < 2 {
				select {
				case <-lastFinished:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			err := emit(&Record{ID: "OSV-order", Source: source.Name(), Summary: fmt.Sprint(i), Affected: []Affected{{Ecosystem: "npm", Package: "ordered"}}})
			if i == 2 {
				close(lastFinished)
			}
			return err
		}})
	}
	old, exists := registry[source.Name()]
	RegisterSource(source.Name(), func() Source { return source })
	t.Cleanup(func() {
		if exists {
			registry[source.Name()] = old
		} else {
			delete(registry, source.Name())
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dir := filepath.Join(t.TempDir(), "db")
	m, err := Update(ctx, dir, Options{Sources: []string{source.Name()}, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	for i, feed := range m.Sources {
		if feed.URL != source.feeds[i].URL {
			t.Fatal("feed metadata reordered")
		}
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rs, err := st.Lookup("npm", "ordered")
	if err != nil || len(rs) != 1 {
		t.Fatalf("lookup: %v, %v", rs, err)
	}
	if rs[0].Summary != "0" || len(rs[0].Provenance) != 3 {
		t.Fatalf("merge precedence changed: %+v", rs[0])
	}
	for i, provenance := range rs[0].Provenance {
		if provenance.URL != source.feeds[i].URL {
			t.Fatal("provenance reordered")
		}
	}
	if paths, err := filepath.Glob(filepath.Join(dir, ".merge-*")); err != nil || len(paths) != 0 {
		t.Fatalf("temporary partitions published: %v, %v", paths, err)
	}
}
