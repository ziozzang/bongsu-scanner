package vulndb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDebianTrackerStatuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debian.json")
	data := `{"curl":{"CVE-2025-1234":{"description":"example","releases":{"trixie":{"status":"resolved","fixed_version":"8.1-2","urgency":"unimportant"},"bookworm":{"status":"open"},"bullseye":{"status":"resolved","fixed_version":"0"},"buster":{"status":"undetermined"},"forky":{"status":"resolved"},"sid":{"status":"resolved","fixed_version":"<not-affected>"}}},"invalid":{"releases":{"sid":{"status":"open"}}}}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var got []*Record
	if err := parseDebianTracker(context.Background(), path, func(r *Record) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Affected) != 2 {
		t.Fatalf("unexpected records: %+v", got)
	}
	a := got[0].Affected
	if a[0].Ecosystem != "Debian:12" || len(a[0].Ranges[0].Events) != 1 {
		t.Fatalf("open: %+v", a[0])
	}
	if a[1].Ecosystem != "Debian:13" || a[1].Ranges[0].Events[1].Fixed != "8.1-2" || a[1].Database["urgency"] != "unimportant" {
		t.Fatalf("resolved: %+v", a[1])
	}
	sentinel := errors.New("stop")
	if err := parseDebianTracker(context.Background(), path, func(*Record) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := parseDebianTracker(ctx, path, func(*Record) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, data := range []string{`null`, `[]`, `{} {}`, `{"pkg":`, `{} garbage`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := parseDebianTracker(context.Background(), path, func(*Record) error { return nil }); err == nil {
			t.Errorf("accepted invalid feed %s", data)
		}
	}
}
