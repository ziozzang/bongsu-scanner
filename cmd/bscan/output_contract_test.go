package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/assessment"
	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/selfupdate"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func captureCommandStreams(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	previous := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = previous }()
	stderr, runErr := captureBatchStderr(t, fn)
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data), stderr, runErr
}

func assertCommandLogs(t *testing.T, mode, stderr string) {
	t.Helper()
	if mode == "quiet" {
		// Quiet suppresses progress; alerts that change how results must be
		// read (feed failures, coverage gaps, unavailable LLM review) stay.
		for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
			if line != "" && !quietAlertLine(line) {
				t.Fatalf("quiet logs: %s", stderr)
			}
		}
		return
	}
	if stderr == "" {
		t.Fatal("missing logs")
	}
	if mode != "json" {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		var event struct{ TS, Level, Stage, Msg string }
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("non-JSON log: %q: %v", line, err)
		}
		if _, err := time.Parse(time.RFC3339Nano, event.TS); err != nil || event.Stage == "" || event.Msg == "" || (event.Level != "info" && event.Level != "warn") {
			t.Fatalf("invalid log event: %+v", event)
		}
	}
}

func outputModeArgs(mode string) []string {
	if mode == "quiet" {
		return []string{"--quiet"}
	}
	return []string{"--log-format", mode}
}

func TestCommandOutputLoggingModes(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	db, target := cliTestDB(t), scanMatchFixture(t)
	input := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"},{"type":"library","name":"unknown"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"text", "json", "quiet"} {
		for _, command := range []string{"match", "scan"} {
			t.Run(mode+"/"+command, func(t *testing.T) {
				args := append(outputModeArgs(mode), command)
				if command == "match" {
					args = append(args, "--db", db, "--format", "json", input)
				} else {
					args = append(args, "--no-sign", "--match", "--db", db, "--output", t.TempDir(), target)
				}
				stdout, stderr, err := captureCommandStreams(t, func() error { return run(context.Background(), args) })
				if err != nil {
					t.Fatal(err)
				}
				assertCommandLogs(t, mode, stderr)
				if command == "match" && !json.Valid([]byte(stdout)) {
					t.Fatalf("polluted result: %s", stdout)
				}
				if command == "scan" && !strings.Contains(stdout, "scan complete:") {
					t.Fatalf("missing primary scan result: %s", stdout)
				}
			})
		}
	}
}

type outputAnalyzer struct{ err error }

func (a outputAnalyzer) Analyze(context.Context, assessment.Input) (assessment.Result, error) {
	return assessment.Result{Status: assessment.NeedsReview}, a.err
}

func quietAlertLine(line string) bool {
	return strings.HasPrefix(line, "[db:error] ") || strings.Contains(line, "WARNING: coverage gap") ||
		strings.HasPrefix(line, "[match:llm] analysis unavailable")
}

func TestHelperOutputLoggingModes(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	for _, mode := range []string{"text", "json", "quiet"} {
		for _, helper := range []string{"db-warning", "llm-success", "llm-warning", "update-warning", "update-signature"} {
			t.Run(mode+"/"+helper, func(t *testing.T) {
				options, _, err := parseGlobalFlags(outputModeArgs(mode))
				if err != nil {
					t.Fatal(err)
				}
				restore, err := applyGlobalFlags(options)
				if err != nil {
					t.Fatal(err)
				}
				defer restore()
				_, stderr, err := captureCommandStreams(t, func() error {
					switch helper {
					case "db-warning":
						return printDBMeta(vulndb.Meta{Sources: []vulndb.SourceMeta{{Name: "fixture", Error: "feed unavailable"}}})
					case "llm-success", "llm-warning":
						var failure error
						if helper == "llm-warning" {
							failure = errors.New("unavailable")
						}
						a := loggedAnalyzer{inner: outputAnalyzer{err: failure}}
						_, _ = a.Analyze(context.Background(), assessment.Input{AdvisoryID: "fixture"})
					case "update-warning":
						u, _, err := newReleaseUpdater(config.Defaults(), "o/r", false)
						if err != nil {
							return err
						}
						u.Client.HTTP.Transport = updatePolicyTransport{}
						_, err = u.Checksums(context.Background(), &selfupdate.Release{Assets: []selfupdate.Asset{{Name: "SHA256SUMS", URL: "https://github.com/o/r/SHA256SUMS"}}})
						return err
					case "update-signature":
						// The signature helper's writer is deliberately injectable; production
						// must supply the logging adapter instead of os.Stderr.
						printUpdateSignature(logWriter{stage: "update"}, "trusted:release", &selfupdate.Checksums{Verified: true, Authenticated: true, Signer: "fixture"})
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				assertCommandLogs(t, mode, stderr)
				if mode == "json" && strings.HasSuffix(helper, "warning") && !strings.Contains(stderr, `"level":"warn"`) {
					t.Fatalf("warning severity lost: %s", stderr)
				}
				if mode == "quiet" && (helper == "db-warning" || helper == "llm-warning") && stderr == "" {
					t.Fatalf("%s alert suppressed by --quiet", helper)
				}
			})
		}
	}
}

func TestCancellationExitCodeMapping(t *testing.T) {
	for _, err := range []error{context.Canceled, errors.Join(errors.New("db update"), context.Canceled), errors.Join(&findingsError{threshold: "HIGH"}, context.Canceled)} {
		if got := exitCode(err); got != 130 {
			t.Errorf("exitCode(%v) = %d, want 130", err, got)
		}
	}
	if got := exitCode(context.DeadlineExceeded); got != 1 {
		t.Fatalf("timeout exit=%d", got)
	}
}

func TestDBMutationOutputContract(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	db := cliTestDB(t)
	archive := filepath.Join(t.TempDir(), "db.tar.gz")
	if err := vulndb.ExportVerified(db, archive, nil); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"text", "json", "quiet"} {
		for _, command := range []string{"import", "convert", "status"} {
			t.Run(mode+"/"+command, func(t *testing.T) {
				if testing.Short() && command == "import" && mode != "text" {
					t.Skip("repeated import; text import and all convert/status logging modes run in short mode")
				}
				args := append(outputModeArgs(mode), "db", command)
				destination := filepath.Join(t.TempDir(), "db")
				switch command {
				case "import":
					args = append(args, "--db", destination, archive)
				case "convert":
					args = append(args, "--db", db, destination)
				case "status":
					args = append(args, "--db", db)
				}
				stdout, stderr, err := captureCommandStreams(t, func() error { return run(context.Background(), args) })
				if err != nil {
					t.Fatal(err)
				}
				if command == "status" {
					if !strings.Contains(stdout, "Records:") || stderr != "" {
						t.Fatalf("status: stdout=%s stderr=%s", stdout, stderr)
					}
				} else {
					if strings.Contains(stdout, "Records:") || !strings.Contains(stdout, destination) {
						t.Fatalf("mutation stdout: %s", stdout)
					}
					assertCommandLogs(t, mode, stderr)
				}
			})
		}
	}
}

type outputTransport func(*http.Request) (*http.Response, error)

func (f outputTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func stubReleaseCheck(t *testing.T, latest string) {
	t.Helper()
	original := releaseHTTPClient
	t.Cleanup(func() { releaseHTTPClient = original })
	releaseHTTPClient = func(timeout time.Duration) *httpx.Client {
		c := newHTTPClient(timeout)
		c.HTTP.Transport = outputTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"tag_name":"` + latest + `"}`)), Request: r}, nil
		})
		return c
	}
}

func TestRunExitCodeMatrix(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	t.Setenv("BONGSU_OFFLINE", "0")
	withVersion(t, "v1.0.0")
	stubReleaseCheck(t, "v2.0.0")
	db, target := cliTestDB(t), scanMatchFixture(t)
	input := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		args     []string
		canceled bool
		want     int
	}{
		{"success", []string{"version"}, false, 0},
		{"execution error", []string{"match", "--db", db, "missing.json"}, false, 1},
		{"match threshold", []string{"match", "--db", db, "--fail-on", "HIGH", input}, false, 2},
		{"scan threshold", []string{"scan", "--no-sign", "--output", t.TempDir(), "--match", "--db", db, "--fail-on", "HIGH", target}, false, 2},
		{"batch threshold", []string{"batch", "--jobs", "1", "--no-sign", "--output", t.TempDir(), "--match", "--db", db, "--fail-on", "HIGH", target}, false, 2},
		{"update available", []string{"update", "--check"}, false, 0},
		{"match canceled", []string{"match", "--db", db, input}, true, 130},
		{"scan canceled", []string{"scan", "--no-sign", "--output", t.TempDir(), target}, true, 130},
		{"db update canceled", []string{"db", "update", "--db", filepath.Join(t.TempDir(), "db"), "--source", "osv", "--ecosystem", "npm"}, true, 130},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			start := time.Now()
			_, _, err := captureCommandStreams(t, func() error { return run(ctx, append([]string{"--quiet"}, tc.args...)) })
			if got := exitCode(err); got != tc.want {
				t.Fatalf("exit=%d want=%d err=%v", got, tc.want, err)
			}
			if tc.canceled && time.Since(start) >= time.Second {
				t.Fatalf("cancellation exceeded 1s: %s", time.Since(start))
			}
		})
	}
}

func TestUpdateOutputContract(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "0")
	withVersion(t, "v1.0.0")
	stubReleaseCheck(t, "v1.0.0")
	for _, mode := range []string{"text", "json", "quiet"} {
		for _, check := range []bool{false, true} {
			args := append(outputModeArgs(mode), "update")
			if check {
				args = append(args, "--check")
			}
			stdout, stderr, err := captureCommandStreams(t, func() error { return run(context.Background(), args) })
			if err != nil {
				t.Fatal(err)
			}
			assertCommandLogs(t, mode, stderr)
			if check {
				if !strings.Contains(stdout, "current: v1.0.0\nlatest:  1.0.0\n") || strings.Contains(stdout, "up to date") {
					t.Fatalf("check stdout=%q", stdout)
				}
			} else if stdout != "" {
				t.Fatalf("update summary on stdout: %q", stdout)
			}
		}
	}
}

func TestDBUpdateOutputContract(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "0")
	var feed bytes.Buffer
	zw := zip.NewWriter(&feed)
	member, err := zw.Create("fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(member, `{"id":"FIXTURE-1","affected":[{"package":{"ecosystem":"npm","name":"fixture"},"versions":["1.0.0"]}]}`); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	original := dbHTTPClient
	defer func() { dbHTTPClient = original }()
	for _, failure := range []bool{false, true} {
		dbHTTPClient = func(timeout time.Duration) *httpx.Client {
			c := httpx.New(timeout)
			c.HTTP.Transport = outputTransport(func(r *http.Request) (*http.Response, error) {
				body := feed.Bytes()
				if failure {
					body = []byte("invalid zip")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
			})
			return c
		}
		for _, mode := range []string{"text", "json", "quiet"} {
			db := filepath.Join(t.TempDir(), "db")
			args := append(outputModeArgs(mode), "db", "update", "--db", db, "--source", "osv", "--ecosystem", "npm")
			stdout, stderr, err := captureCommandStreams(t, func() error { return run(context.Background(), args) })
			if (err != nil) != failure {
				t.Fatalf("failure=%t err=%v", failure, err)
			}
			assertCommandLogs(t, mode, stderr)
			want := db + "\n"
			if failure {
				want = ""
			}
			if stdout != want {
				t.Fatalf("stdout=%q want=%q", stdout, want)
			}
		}
	}
}

func TestMatchCancellationStopsBeforeOutput(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "0")
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)
	db := cliTestDB(t)
	input := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := filepath.Join(t.TempDir(), "findings.json")
	done := make(chan error, 1)
	_, _, err := captureCommandStreams(t, func() error {
		go func() {
			done <- run(ctx, []string{"--quiet", "match", "--db", db, "--db-isolation", "copy", "--llm", "--llm-cache=", "--llm-base-url", server.URL, "--llm-model", "fixture", "-o", output, input})
		}()
		select {
		case <-started:
		case err := <-done:
			t.Fatalf("match ended before request: %v", err)
		case <-time.After(5 * time.Second):
			cancel()
			<-done
			t.Fatal("match did not start")
		}
		start := time.Now()
		cancel()
		select {
		case err := <-done:
			t.Logf("match cancellation: %s", time.Since(start))
			return err
		case <-time.After(time.Second):
			<-done
			t.Fatal("match cancellation exceeded 1s")
			return nil
		}
	})
	if !errors.Is(err, context.Canceled) || exitCode(err) != 130 {
		t.Fatalf("cancellation=%v code=%d", err, exitCode(err))
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("canceled match published output: %v", err)
	}
	for _, directory := range []string{scratch, filepath.Dir(output)} {
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatalf("cancellation leftovers in %s: %v (%v)", directory, entries, err)
		}
	}
}

func TestOwnedFlagErrorsPrintedOnce(t *testing.T) {
	for _, command := range [][]string{{"match"}, {"db", "status"}, {"db", "update"}, {"report"}, {"update"}} {
		for _, mode := range []string{"json", "quiet"} {
			args := append(outputModeArgs(mode), command...)
			args = append(args, "--invalid-output-contract-flag")
			stdout, stderr, code := polishCLI(t, t.TempDir(), args...)
			if code != 1 || stdout != "" || strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, "bscan: ") {
				t.Fatalf("%v: exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
			}
		}
	}
}
