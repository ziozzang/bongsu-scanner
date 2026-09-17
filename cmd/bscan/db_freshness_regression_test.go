package main

import (
	"archive/zip"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestDBMaintainedFeedConfiguredDefault(t *testing.T) {
	fs := flag.NewFlagSet("db", flag.ContinueOnError)
	limit := fs.Int64("max-feed-bytes", 1<<30, "")
	if err := applyDBDefaults(fs, config.Defaults().DB); err != nil {
		t.Fatal(err)
	}
	if *limit != 1<<30 {
		t.Fatalf("effective default=%d", *limit)
	}
}

func TestDBFreshnessWarningUnderQuiet(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_CONFIG", "")
	t.Setenv("BONGSU_OFFLINE", "0")
	previous := dbHTTPClient
	t.Cleanup(func() { dbHTTPClient = previous })
	for _, tc := range []struct {
		name, modified string
		warn           bool
	}{{"stale", "2024-10-08T12:00:00Z", true}, {"fresh", time.Now().UTC().Format(time.RFC3339), false}, {"unknown", "", false}} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			w, err := zw.Create("record.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = fmt.Fprintf(w, `{"id":"CVE-2024-1234","modified":%q,"affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"curl"},"versions":["1"]}]}`, tc.modified); err != nil {
				t.Fatal(err)
			}
			if err = zw.Close(); err != nil {
				t.Fatal(err)
			}
			dbHTTPClient = func(timeout time.Duration) *httpx.Client {
				client := httpx.New(timeout)
				client.HTTP.Transport = outputTransport(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, ContentLength: int64(buf.Len()), Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(buf.Bytes())), Request: r}, nil
				})
				return client
			}
			dir := filepath.Join(t.TempDir(), "db")
			progressLog.Lock()
			quiet := progressLog.quiet
			progressLog.quiet = true
			progressLog.Unlock()
			_, logs, err := captureCommandStreams(t, func() error {
				return cmdDB(context.Background(), []string{"update", "--db", dir, "--source", "osv", "--ecosystem", "Ubuntu"})
			})
			progressLog.Lock()
			progressLog.quiet = quiet
			progressLog.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(logs, "WARNING"); got != tc.warn {
				t.Fatalf("warning=%t want %t: %s", got, tc.warn, logs)
			}
			if tc.warn && (!strings.Contains(logs, "Ubuntu") || !strings.Contains(logs, "60 days") || !strings.Contains(logs, "2024-10-08")) {
				t.Fatalf("incomplete warning: %s", logs)
			}
			out, _, err := captureCommandStreams(t, func() error { return cmdDB(context.Background(), []string{"status", "--db", dir}) })
			if err != nil {
				t.Fatal(err)
			}
			date := "unknown"
			if tc.modified != "" {
				date = tc.modified[:10]
			}
			if !strings.Contains(out, "data through: "+date) {
				t.Fatalf("status lacks data date: %s", out)
			}
		})
	}
}
