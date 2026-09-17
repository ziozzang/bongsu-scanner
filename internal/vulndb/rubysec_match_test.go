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

func TestRubysecUnmappedMatchReason(t *testing.T) {
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
	report, err := match.Run(context.Background(), st, []match.Subject{{Ecosystem: "RubyGems", Name: "example", Version: "1.2.0"}}, match.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 || report.Skipped["no-usable-range"] != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
}
