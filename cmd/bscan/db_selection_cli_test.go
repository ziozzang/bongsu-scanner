package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestDBSelectionCLI(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_CONFIG", "")
	t.Setenv("BONGSU_OFFLINE", "0")
	feeds := map[string][]byte{}
	for _, ecosystem := range []string{"npm", "PyPI", "Ubuntu:24.04:LTS", "Ubuntu:22.04:LTS", "Ubuntu:Pro:24.04:LTS", "Ubuntu"} {
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
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := feeds[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	previous := dbHTTPClient
	t.Cleanup(func() { dbHTTPClient = previous })
	dbHTTPClient = func(timeout time.Duration) *httpx.Client {
		c := httpx.New(timeout)
		c.HTTP.Transport = server.Client().Transport
		return c
	}
	cfg := config.Defaults()
	cfg.DB.Mirror = server.URL
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "db")
	steps := []struct {
		name       string
		args, want []string
		provenance string
	}{
		{"initial", []string{"--source", "osv", "--ecosystem", "npm"}, []string{"npm"}, "flags"},
		{"add", []string{"--add-ecosystem", "PyPI,npm", "--add-ecosystem", "PyPI"}, []string{"npm", "PyPI"}, "installed catalog + --add-ecosystem"},
		{"sticky", nil, []string{"npm", "PyPI"}, "installed catalog"},
		{"replace", []string{"--ecosystem", "PyPI"}, []string{"PyPI"}, "flags"},
		{"ubuntu", []string{"--add-ecosystem", "Ubuntu:24.04,Ubuntu:22.04,Ubuntu:Pro:24.04:LTS,Ubuntu"}, []string{"PyPI", "Ubuntu:24.04:LTS", "Ubuntu:22.04:LTS", "Ubuntu:Pro:24.04:LTS", "Ubuntu"}, "installed catalog + --add-ecosystem"},
	}
	for _, step := range steps {
		if !t.Run(step.name, func(t *testing.T) {
			args := append([]string{"update", "--db", dir}, step.args...)
			_, logs, err := captureCommandStreams(t, func() error { return cmdDB(context.Background(), args) })
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(logs, "selection:") != 1 || !strings.Contains(logs, step.provenance) {
				t.Fatalf("selection log: %s", logs)
			}
			store, err := vulndb.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, eco := range []string{"npm", "PyPI", "Ubuntu:24.04:LTS", "Ubuntu:22.04:LTS", "Ubuntu:Pro:24.04:LTS", "Ubuntu"} {
				records, err := store.Lookup(eco, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				present := false
				for _, record := range records {
					for _, affected := range record.Affected {
						if affected.Ecosystem == eco {
							present = true
						}
					}
				}
				want := false
				for _, value := range step.want {
					if value == eco {
						want = true
					}
				}
				if present != want {
					t.Errorf("%s present=%v want=%v", eco, present, want)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			out, _, err := captureCommandStreams(t, func() error { return cmdDB(context.Background(), []string{"status", "--db", dir}) })
			if err != nil {
				t.Fatal(err)
			}
			expected := "ecosystems=" + strings.Join(step.want, ",") + " "
			if !strings.Contains(out, "Selection:") || !strings.Contains(out, expected) {
				t.Fatalf("status missing %q: %s", expected, out)
			}
		}) {
			return
		}
	}
}
