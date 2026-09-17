package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type impliedSourceTransport func(*http.Request) (*http.Response, error)

func (f impliedSourceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDBAdditionsImplySourceCLI(t *testing.T) {
	for _, tc := range []struct {
		name, initial, flag, value, implied, sources, ecosystem, pkg, feed string
	}{
		{"ecosystem", "alpine-secdb", "--add-ecosystem", "PyPI", "osv", "alpine-secdb,osv", "PyPI", "fixture", "/PyPI/all.zip"},
		{"release", "osv", "--add-alpine-release", "v3.21", "alpine", "osv,alpine-secdb", "Alpine:v3.21", "openssl", "/v3.21/main.json"},
	} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/explicit-source=%t", tc.name, explicit), func(t *testing.T) {
				t.Setenv("BONGSU_HOME", t.TempDir())
				t.Setenv("BONGSU_CONFIG", "")
				t.Setenv("BONGSU_OFFLINE", "0")
				feeds := map[string][]byte{}
				for _, ecosystem := range []string{"npm", "PyPI"} {
					var buf bytes.Buffer
					zw := zip.NewWriter(&buf)
					member, err := zw.Create("CVE-2026-1234.json")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := fmt.Fprintf(member, `{"id":"CVE-2026-1234","affected":[{"package":{"ecosystem":%q,"name":"fixture"},"versions":["1.0"]}]}`, ecosystem); err != nil {
						t.Fatal(err)
					}
					if err := zw.Close(); err != nil {
						t.Fatal(err)
					}
					feeds["/"+ecosystem+"/all.zip"] = buf.Bytes()
				}
				for _, release := range []string{"v3.20", "v3.21"} {
					feeds["/"+release+"/main.json"] = []byte(`{"packages":[{"pkg":{"name":"openssl","secfixes":{"3.1-r1":["CVE-2026-5678"]}}}]}`)
					feeds["/"+release+"/community.json"] = []byte(`{"packages":[]}`)
				}
				var downloads atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					data, ok := feeds[r.URL.Path]
					if !ok {
						http.NotFound(w, r)
						return
					}
					if r.URL.Path == tc.feed {
						downloads.Add(1)
					}
					_, _ = w.Write(data)
				}))
				defer server.Close()
				endpoint, err := url.Parse(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				previous := dbHTTPClient
				t.Cleanup(func() { dbHTTPClient = previous })
				dbHTTPClient = func(timeout time.Duration) *httpx.Client {
					c := httpx.New(timeout)
					c.HTTP.Transport = impliedSourceTransport(func(r *http.Request) (*http.Response, error) {
						if r.URL.Host != endpoint.Host && r.URL.Host != "secdb.alpinelinux.org" {
							return nil, fmt.Errorf("unexpected feed host %q", r.URL.Host)
						}
						r = r.Clone(r.Context())
						r.URL.Scheme, r.URL.Host = endpoint.Scheme, endpoint.Host
						return server.Client().Transport.RoundTrip(r)
					})
					return c
				}
				cfg := config.Defaults()
				cfg.DB.Mirror = server.URL
				if err := config.Save(cfg); err != nil {
					t.Fatal(err)
				}
				dir := filepath.Join(t.TempDir(), "db")
				_, _, err = captureCommandStreams(t, func() error {
					return cmdDB(context.Background(), []string{"update", "--db", dir, "--source", tc.initial, "--ecosystem", "npm", "--alpine-release", "v3.20"})
				})
				if err != nil {
					t.Fatal(err)
				}
				if downloads.Load() != 0 {
					t.Fatal("addition feed was already downloaded")
				}
				args := []string{"update", "--db", dir, tc.flag, tc.value}
				if explicit {
					args = append(args, "--source", tc.initial)
				}
				_, logs, err := captureCommandStreams(t, func() error { return cmdDB(context.Background(), args) })
				if err != nil {
					t.Fatal(err)
				}
				if downloads.Load() != 1 {
					t.Errorf("addition feed downloads=%d, want 1", downloads.Load())
				}
				message := "[db] selection: adding source " + tc.implied + " for " + tc.flag
				if strings.Count(logs, message) != 1 {
					t.Errorf("missing single implied-source log %q: %s", message, logs)
				}
				if explicit && !strings.Contains(logs, "explicit --source") {
					t.Errorf("missing explicit-source explanation: %s", logs)
				}
				store, err := vulndb.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				records, lookupErr := store.Lookup(tc.ecosystem, tc.pkg)
				closeErr := store.Close()
				if lookupErr != nil || closeErr != nil || len(records) != 1 {
					t.Fatalf("added feed lookup=%v, err=%v, close=%v", records, lookupErr, closeErr)
				}
				out, _, err := captureCommandStreams(t, func() error { return cmdDB(context.Background(), []string{"status", "--db", dir}) })
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out, "Selection: sources="+tc.sources+" ") {
					t.Errorf("status missing implied source: %s", out)
				}
				// Repeated additions must not append or announce the same source twice.
				_, logs, err = captureCommandStreams(t, func() error {
					return cmdDB(context.Background(), []string{"update", "--db", dir, tc.flag, tc.value})
				})
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(logs, "adding source") {
					t.Errorf("source already selected: %s", logs)
				}
			})
		}
	}
}
