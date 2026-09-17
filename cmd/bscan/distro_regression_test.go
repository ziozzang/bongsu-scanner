package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	matcher "github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func distroPolicyDB(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, err := z.Create("CVE-2026-12345.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.Write([]byte(`{"id":"CVE-2026-12345","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"package":{"ecosystem":"npm","name":"fixture"},"database_specific":{"urgency":"low"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(b.Bytes()) }))
	defer server.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = server.Client().Transport
	dir := filepath.Join(t.TempDir(), "db")
	if _, err := vulndb.Update(context.Background(), dir, vulndb.Options{Sources: []string{"osv"}, Ecosystems: []string{"npm"}, OSVBaseURL: server.URL, Client: client}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDistroSeverityCLIAndCoverageWarnings(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	db := distroPolicyDB(t)
	input := filepath.Join(t.TempDir(), "input.cdx.json")
	data := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","bom-ref":"fixture","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"},{"type":"library","name":"missing","version":"1","purl":"pkg:pypi/missing@1"}]}`
	if err := os.WriteFile(input, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"cvss", "distro", "max"} {
		t.Run(mode, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "findings.json")
			log, err := captureBatchStderr(t, func() error {
				return cmdMatch(context.Background(), []string{"--db", db, "--severity-source", mode, "--fail-on", "HIGH", "--format", "json", "-o", output, input})
			})
			wantExit := 2
			wantSeverity := "CRITICAL"
			if mode == "distro" {
				wantExit = 0
				wantSeverity = "LOW"
			}
			if exitCode(err) != wantExit {
				t.Fatalf("exit=%d want=%d: %v", exitCode(err), wantExit, err)
			}
			if !strings.Contains(log, "WARNING: coverage gap: PyPI (1 subjects)") || !strings.Contains(log, "bscan db update --ecosystem PyPI") {
				t.Fatalf("missing warning: %s", log)
			}
			raw, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var report matcher.Report
			if err = json.Unmarshal(raw, &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) != 1 || report.Findings[0].Severity != wantSeverity || report.BySeverity[wantSeverity] != 1 {
				t.Fatalf("policy: %+v", report)
			}
			// Scan flags must configure the same matching policy and fail-on threshold.
			var flags scanMatchFlags
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			addScanMatchFlags(fs, &flags)
			if err := fs.Parse([]string{"--match", "--db", db, "--severity-source", mode, "--fail-on", "HIGH"}); err != nil {
				t.Fatal(err)
			}
			scanner, err := prepareScanMatch(context.Background(), flags)
			if err != nil {
				t.Fatal(err)
			}
			defer scanner.store.Close()
			scanLog, err := captureBatchStderr(t, func() error {
				_, failed, err := scanner.write(context.Background(), []string{input}, &scanOutputPaths{}, "fixture")
				if failed != (wantExit == 2) {
					t.Errorf("scan fail-on=%v", failed)
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(scanLog, "WARNING: coverage gap: PyPI (1 subjects)") {
				t.Fatalf("scan warning: %s", scanLog)
			}
		})
	}
	for _, command := range []string{"match", "scan"} {
		args := []string{command, "--severity-source", "invalid", input}
		if command == "scan" {
			args = append([]string{"scan", "--match"}, args[1:]...)
		}
		_, _, err := captureCommandStreams(t, func() error { return run(context.Background(), args) })
		if err == nil || !strings.Contains(err.Error(), "invalid severity source") {
			t.Fatalf("%s: %v", command, err)
		}
	}
}
