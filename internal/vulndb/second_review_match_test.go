package vulndb_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestSecondReviewOSVLastVersionMatchesAfterUpdate(t *testing.T) {
	versions := make([]string, 20001)
	for i := range versions {
		versions[i] = fmt.Sprintf("1.0.%d", i)
	}
	raw, err := json.Marshal(map[string]any{
		"id":       "CVE-2026-1234",
		"affected": []any{map[string]any{"package": map[string]string{"ecosystem": "npm", "name": "example"}, "versions": versions}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	member, err := zw.Create("record.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(buf.Bytes()) }))
	defer srv.Close()
	client := httpx.New(30 * time.Second)
	client.HTTP.Transport = srv.Client().Transport
	dir := filepath.Join(t.TempDir(), "db")
	_, err = vulndb.Update(context.Background(), dir, vulndb.Options{Sources: []string{vulndb.SourceOSV}, Ecosystems: []string{"npm"}, OSVBaseURL: srv.URL, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	st, err := vulndb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	report, err := match.Run(context.Background(), st, []match.Subject{{Ecosystem: "npm", Name: "example", Version: versions[len(versions)-1]}}, match.Options{})
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("last explicit version missed: findings=%v err=%v", report.Findings, err)
	}
}
