package assessment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityInputValidationBoundaries(t *testing.T) {
	for name, mutate := range map[string]func(*Input){
		"identity size":   func(in *Input) { in.Package = strings.Repeat("x", 1025) },
		"identity utf8":   func(in *Input) { in.Environment.Arch = "\xff" },
		"fact key size":   func(in *Input) { in.Environment.Facts = map[string]string{strings.Repeat("k", 129): "v"} },
		"fact value size": func(in *Input) { in.Environment.Facts = map[string]string{"k": strings.Repeat("v", 2049)} },
		"fact utf8":       func(in *Input) { in.Environment.Facts = map[string]string{"k": "\xff"} },
		"reference size":  func(in *Input) { in.References = []string{strings.Repeat("x", MaxReferenceBytes+1)} },
		"reference utf8":  func(in *Input) { in.References = []string{"\xff"} },
	} {
		t.Run(name, func(t *testing.T) {
			in := testInput()
			mutate(&in)
			if err := validateInput(in); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	in := testInput()
	in.Package = strings.Repeat("x", 1024)
	in.Summary = strings.Repeat("s", MaxSummaryBytes)
	in.Description = strings.Repeat("d", MaxDescriptionBytes)
	in.Environment.Facts = map[string]string{strings.Repeat("k", 128): strings.Repeat("v", 2048)}
	in.References = []string{strings.Repeat("r", MaxReferenceBytes)}
	if err := validateInput(in); err != nil {
		t.Fatalf("exact field limits rejected: %v", err)
	}
}

func TestSecurityStrictJSONAndResultLimits(t *testing.T) {
	for _, raw := range []string{`{"a":`, `{"a":1,`, `{"a":1`, `{"a":1} {}`, `{"a":1,"a":2}`, `{"b":1}`, `[]`} {
		if _, err := strictObject([]byte(raw), "a"); err == nil {
			t.Errorf("invalid object accepted: %s", raw)
		}
	}
	for _, raw := range []string{
		strings.Repeat(" ", maxResponseBytes+1),
		`{"status":"needs_review","reason":"review","evidence":[1],"preconditions":[],"checks":[]}`,
		`{"status":"needs_review","reason":"review","evidence":[],"preconditions":[],"checks":["\u0000"]}`,
	} {
		if _, err := decodeResult([]byte(raw), testInput()); err == nil {
			t.Error("invalid result accepted")
		}
	}
	for name, mutate := range map[string]func(*Result){
		"invalid utf8 reason": func(r *Result) { r.Reason = "\xff" },
		"invalid utf8 item":   func(r *Result) { r.Checks = []string{"\xff"} },
		"long item":           func(r *Result) { r.Checks = []string{strings.Repeat("x", 1001)} },
		"too many items":      func(r *Result) { r.Checks = make([]string, 13) },
	} {
		t.Run(name, func(t *testing.T) {
			r := Result{Status: NeedsReview, Reason: "Review", Evidence: []string{}, Preconditions: []string{}, Checks: []string{}}
			mutate(&r)
			if _, err := validateResult(r, testInput()); err == nil {
				t.Fatal("invalid result accepted")
			}
		})
	}
}

func TestSecurityCacheIdentityAndCredentialRevalidation(t *testing.T) {
	c := &Client{config: Config{CacheDir: t.TempDir(), Model: "model", APIKey: "secret-key"}}
	const key = "input-digest"
	path := filepath.Join(c.config.CacheDir, key+".json")
	for name, mutate := range map[string]func(*Result){
		"model mismatch":          func(r *Result) { r.Model = "other" },
		"input mismatch":          func(r *Result) { r.InputSHA256 = "other" },
		"invalid result":          func(r *Result) { r.Status = "safe" },
		"reason credential":       func(r *Result) { r.Reason = "contains secret-key" },
		"precondition credential": func(r *Result) { r.Preconditions = []string{"secret-key"} },
		"check credential":        func(r *Result) { r.Checks = []string{"secret-key"} },
	} {
		t.Run(name, func(t *testing.T) {
			r := Result{Status: NeedsReview, Reason: "Review", Evidence: []string{}, Preconditions: []string{}, Checks: []string{}, Model: "model", InputSHA256: key}
			mutate(&r)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if got, ok := c.readCache(key, testInput()); ok {
				t.Fatalf("untrusted cache hit: %#v", got)
			}
		})
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", maxResponseBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.readCache(key, testInput()); ok {
		t.Fatal("oversized cache accepted")
	}
}

func TestSecurityCacheWriteFailuresAreMisses(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, cacheDir := range []string{"", file, filepath.Join(file, "child")} {
		c := &Client{config: Config{CacheDir: cacheDir}}
		c.writeCache("key", Result{})
		if _, ok := c.readCache("key", testInput()); ok {
			t.Fatal("failed write produced cache hit")
		}
	}
	if raw, err := os.ReadFile(file); err != nil || string(raw) != "preserve" {
		t.Fatalf("cache failure changed file: %q, %v", raw, err)
	}
	// A destination directory makes the final rename fail without permissions
	// tricks, including when tests run as root.
	if err := os.Mkdir(filepath.Join(dir, "key.json"), 0700); err != nil {
		t.Fatal(err)
	}
	c := &Client{config: Config{CacheDir: dir}}
	c.writeCache("key", Result{})
	left, err := filepath.Glob(filepath.Join(dir, ".assessment-*"))
	if err != nil || len(left) != 0 {
		t.Fatalf("temporary cache files left: %v, %v", left, err)
	}
}
