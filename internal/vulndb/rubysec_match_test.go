package vulndb_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type rubysecMatchTransport []byte

func (data rubysecMatchTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, ContentLength: int64(len(data)), Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func TestRubysecCompoundRequirementRanges(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("repo/gems/example/local.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(w, "title: Unsupported requirement\npatched_versions:\n- '>= 2.0'\n- '~> 1.2, >= 1.2.3'\n"); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	client := httpx.New(time.Second)
	client.HTTP.Transport = rubysecMatchTransport(buf.Bytes())
	dir := filepath.Join(t.TempDir(), "db")
	if _, err := vulndb.Update(context.Background(), dir, vulndb.Options{Sources: []string{"rubysec"}, Client: client}); err != nil {
		t.Fatal(err)
	}
	st, err := vulndb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// patched: >= 2.0 OR (~> 1.2 AND >= 1.2.3). RubyGems' two-segment
	// pessimistic constraint ~> 1.2 means >= 1.2, < 2.0, so the safe set is
	// [1.2.3, 2.0) ∪ [2.0, ∞) and everything below 1.2.3 is affected.
	// Compound (AND) requirements are supported, so the advisory yields real
	// ranges instead of a no-usable-range skip.
	for _, tc := range []struct {
		version  string
		affected bool
	}{{"1.1.0", true}, {"1.2.0", true}, {"1.2.2", true}, {"1.2.3", false}, {"1.3.0", false}, {"1.9.9", false}, {"2.0", false}, {"2.5.0", false}} {
		report, err := match.Run(context.Background(), st, []match.Subject{{Ecosystem: "RubyGems", Name: "example", Version: tc.version}}, match.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got := len(report.Findings) == 1; got != tc.affected {
			t.Fatalf("version %s: affected=%v, want %v (skipped=%v)", tc.version, got, tc.affected, report.Skipped)
		}
		if report.Skipped["no-usable-range"] != 0 {
			t.Fatalf("version %s: compound requirement must be mapped, got skipped=%v", tc.version, report.Skipped)
		}
	}
}
