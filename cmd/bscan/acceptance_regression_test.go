package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestAcceptanceOfflineRegistry(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected network", 404)
	}))
	defer server.Close()
	for _, policy := range []string{"environment", "config"} {
		t.Run(policy, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("BONGSU_HOME", home)
			t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
			t.Setenv("BONGSU_OFFLINE", "0")
			if policy == "environment" {
				t.Setenv("BONGSU_OFFLINE", "1")
			} else {
				writeCommandConfig(t, home, "offline: true\n")
			}
			for _, scheme := range []string{"registry://", "oci://"} {
				for _, command := range []string{"scan", "batch", "scan-match", "batch-match"} {
					t.Run(scheme+command, func(t *testing.T) {
						name := strings.TrimSuffix(command, "-match")
						output := t.TempDir()
						args := []string{name, "--no-sign", "--insecure-registry", "--output", output}
						if strings.HasSuffix(command, "-match") {
							args = append(args, "--match")
						}
						args = append(args, scheme+strings.TrimPrefix(server.URL, "http://")+"/fixture:latest")
						stdout, stderr, err := captureCommandStreams(t, func() error { return run(context.Background(), args) })
						if exitCode(err) != 1 || err == nil || !strings.Contains(err.Error(), "offline") {
							t.Errorf("want offline exit 1: %v; %s", err, stderr)
						}
						if stdout != "" || requests.Load() != 0 {
							t.Errorf("network=%d stdout=%q", requests.Load(), stdout)
						}
						entries, _ := os.ReadDir(output)
						if len(entries) != 0 {
							t.Errorf("unexpected output: %v", entries)
						}
					})
				}
			}
		})
	}
}

func TestAcceptanceNegativeConcurrency(t *testing.T) {
	home := t.TempDir()
	target := scanMatchFixture(t)
	for _, args := range [][]string{
		{"scan", "--workers", "-1"}, {"batch", "--workers", "-1"}, {"batch", "--jobs", "-1"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			output := t.TempDir()
			full := append(append([]string{}, args...), "--no-sign", "--output", output, target)
			stdout, stderr, code := polishCLI(t, home, full...)
			if code != 1 || !strings.Contains(stderr, args[1]) || !strings.Contains(stderr, "negative") || stdout != "" {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			entries, _ := os.ReadDir(output)
			if len(entries) != 0 {
				t.Fatal(entries)
			}
		})
	}
}

func TestAcceptanceHelpStreams(t *testing.T) {
	home := t.TempDir()
	for _, command := range commandRegistry() {
		if command.Path == "" {
			continue
		}
		t.Run(command.Path, func(t *testing.T) {
			stdout, stderr, code := polishCLI(t, home, append(strings.Fields(command.Path), "--help")...)
			if code != 0 || stderr != "" || stdout == "" {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			if strings.Contains(stdout, "Usage of ") && !strings.Contains(stdout, "Usage of "+command.Path+":") {
				t.Errorf("wrong usage title: %s", stdout)
			}
		})
	}
	for _, path := range []string{"init", "scan", "batch", "hash", "sign", "check", "verify", "encrypt", "decrypt", "scramble encrypt", "scramble decrypt", "db status", "report", "match", "update"} {
		stdout, stderr, code := polishCLI(t, home, append(strings.Fields(path), "--invalid-acceptance-flag")...)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "flag provided but not defined") {
			t.Errorf("%s: code=%d stdout=%s stderr=%s", path, code, stdout, stderr)
		}
	}
}

func TestAcceptancePartialMessage(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	output := t.TempDir()
	target := scanMatchFixture(t)
	if err := os.WriteFile(filepath.Join(target, "second.txt"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := captureCommandStreams(t, func() error {
		return run(context.Background(), []string{"scan", "--no-sign", "--workers", "1", "--max-files", "1", "--fail-on-partial", "--output", output, target})
	})
	if exitCode(err) != 3 || stdout != "" || !strings.Contains(stderr, "partial scan; no SBOM written (--fail-on-partial)") || strings.Contains(stderr, "SBOM will be marked partial") {
		t.Fatalf("err=%v stdout=%s stderr=%s", err, stdout, stderr)
	}
	entries, _ := os.ReadDir(output)
	if len(entries) != 0 {
		t.Fatal(entries)
	}
}

func TestAcceptanceReportArray(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			input := filepath.Join(t.TempDir(), "match.json")
			items := make([]string, count)
			for i := range items {
				items[i] = `{"Findings":[]}`
			}
			if err := os.WriteFile(input, []byte(" \n["+strings.Join(items, ",")+"]"), 0600); err != nil {
				t.Fatal(err)
			}
			err := cmdReport(context.Background(), []string{"--from", input})
			want := fmt.Sprintf("match output for %d SBOMs; pass a single result (use --format json with one SBOM or split the array)", count)
			if exitCode(err) != 1 || err.Error() != want {
				t.Fatalf("got %v, want %s", err, want)
			}
		})
	}
}

func TestAcceptanceUpdateCancellationSummary(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "0")
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := dbHTTPClient
	defer func() { dbHTTPClient = original }()
	var started atomic.Int32
	dbHTTPClient = func(timeout time.Duration) *httpx.Client {
		c := httpx.New(timeout)
		c.HTTP.Transport = outputTransport(func(r *http.Request) (*http.Response, error) {
			if started.Add(1) == 3 {
				cancel()
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		return c
	}
	db := filepath.Join(t.TempDir(), "db")
	stdout, stderr, err := captureCommandStreams(t, func() error {
		return run(ctx, []string{"db", "update", "--db", db, "--source", "osv", "--ecosystem", "npm,PyPI,Go,crates.io,RubyGems"})
	})
	if !errors.Is(err, context.Canceled) || exitCode(err) != 130 || stdout != "" {
		t.Fatalf("err=%v stdout=%s", err, stdout)
	}
	if strings.Contains(stderr, "0001-01-01") || strings.Contains(stderr, "context canceled") || strings.Count(stderr, "2 feeds not started") != 1 {
		t.Fatalf("bad cancellation summary: %s", stderr)
	}
	if strings.Count(err.Error(), "context canceled") != 1 {
		t.Fatalf("repeated cancellation: %v", err)
	}
	stages, _ := filepath.Glob(db + ".tmp-*")
	if len(stages) != 0 {
		t.Fatalf("staging leaked: %v", stages)
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatalf("canceled database published: %v", err)
	}
}

// A local finding must not mask the rejected remote target with exit code 2.
func TestAcceptanceOfflineMixedBatch(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "1")
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	output := t.TempDir()
	stdout, _, err := captureCommandStreams(t, func() error {
		return run(context.Background(), []string{"batch", "--no-sign", "--match", "--db", cliTestDB(t), "--fail-on", "HIGH", "--output", output, scanMatchFixture(t), "registry://example.org/fixture:latest"})
	})
	if exitCode(err) != 1 || err == nil || !strings.Contains(err.Error(), "offline") || stdout != "" {
		t.Fatalf("err=%v exit=%d stdout=%s", err, exitCode(err), stdout)
	}
	entries, _ := os.ReadDir(output)
	if len(entries) != 0 {
		t.Fatalf("batch started before offline validation: %v", entries)
	}
}
