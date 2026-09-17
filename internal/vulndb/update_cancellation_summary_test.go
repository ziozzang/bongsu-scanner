package vulndb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestUpdateCancellationSummarizesPendingFeeds(t *testing.T) {
	dir := readerCatalog(t)
	before, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	archive := fixtureZip(t, map[string]string{"fixture.json": osvFixture("CVE-2026-1234", "npm", "example")})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := httpx.New(time.Second)
	var requests atomic.Int32
	client.HTTP.Transport = rubysecTransport(func(r *http.Request) (*http.Response, error) {
		n := requests.Add(1)
		if strings.Contains(r.URL.Path, "/npm/") {
			return &http.Response{StatusCode: 200, ContentLength: int64(len(archive)), Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(archive))}, nil
		}
		if n == 4 {
			cancel()
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	var progress []string
	meta, err := Update(ctx, dir, Options{Sources: []string{"osv"}, Ecosystems: []string{"npm", "PyPI", "Go", "crates.io", "RubyGems", "Maven"}, Client: client, Force: true, Progress: func(message string) { progress = append(progress, message) }})
	if !errors.Is(err, context.Canceled) || strings.Count(err.Error(), "context canceled") != 1 {
		t.Fatalf("error=%v", err)
	}
	if len(meta.Sources) != 1 || meta.Sources[0].Records != 1 || meta.Sources[0].FetchedAt.IsZero() || meta.Sources[0].Error != "" {
		t.Fatalf("completed feed metadata lost or canceled feeds retained: %+v", meta)
	}
	log := strings.Join(progress, "\n")
	if strings.Contains(log, "context canceled") || strings.Count(log, "2 feeds not started; 3 feeds interrupted") != 1 {
		t.Fatalf("bad summary:\n%s", log)
	}
	after, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("installed catalog changed: %v", err)
	}
	if err := Verify(dir, nil); err != nil {
		t.Fatal(err)
	}
	stages, _ := filepath.Glob(dir + ".tmp-*")
	if len(stages) != 0 {
		t.Fatalf("staging leaked: %v", stages)
	}
	release, err := lockDatabase(dir)
	if err != nil {
		t.Fatalf("writer lock leaked: %v", err)
	}
	release()
}
