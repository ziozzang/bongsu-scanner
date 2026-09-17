package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLintAnalysisUsesPinnedTools(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make is unavailable")
	}
	cmd := exec.Command(makePath, "-n", "lint")
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make lint: %v\n%s", err, out)
	}
	for _, command := range []string{
		`GOTOOLCHAIN="$(go env GOVERSION)" GOFLAGS=-mod=mod go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 -tests=false ./...`,
		`GOTOOLCHAIN="$(go env GOVERSION)" GOFLAGS=-mod=mod go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 -quiet ./...`,
	} {
		if !strings.Contains(string(out), command) {
			t.Errorf("lint must run %q; got %s", command, out)
		}
	}
	workflow, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(workflow), "\n  lint-analysis:\n")
	if start < 0 {
		t.Fatal("CI is missing the lint-analysis job")
	}
	job := string(workflow)[start+1:]
	if end := strings.Index(job, "\n\n  "); end >= 0 {
		job = job[:end]
	}
	for _, required := range []string{"continue-on-error: false", "run: make lint", "go-version-file: go.mod"} {
		if !strings.Contains(job, required) {
			t.Errorf("lint-analysis must contain %q", required)
		}
	}
}

func TestAnalysisDefaultMakeStillBuilds(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make is unavailable")
	}
	cmd := exec.Command(makePath, "-n")
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "go build ") || strings.Contains(string(out), "staticcheck") {
		t.Fatalf("default make must still build bscan: %s", out)
	}
}
