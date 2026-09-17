package main

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestDBUpdateUncompressedFlag(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "0")
	const body = `{"id":"CVE-2026-1234","affected":[{"package":{"ecosystem":"Ubuntu:24.04","name":"expat"},"versions":["1"]}]}`
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.Create("record.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	original := dbHTTPClient
	defer func() { dbHTTPClient = original }()
	dbHTTPClient = func(timeout time.Duration) *httpx.Client {
		client := httpx.New(timeout)
		client.HTTP.Transport = outputTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: int64(b.Len()), Body: io.NopCloser(bytes.NewReader(b.Bytes())), Request: r}, nil
		})
		return client
	}
	for _, limit := range []int{0, -1, len(body) - 1, len(body)} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			err := cmdDB(context.Background(), []string{"update", "--db", filepath.Join(t.TempDir(), "db"), "--source", "osv", "--ecosystem", "Ubuntu", "--max-feed-uncompressed", strconv.Itoa(limit)})
			if limit == len(body) {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			want := "total uncompressed bytes"
			if limit <= 0 {
				want = "must be positive"
			}
			if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "--max-feed-uncompressed") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
