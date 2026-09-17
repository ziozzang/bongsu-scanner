package scan

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRegistryRetryDelayBounds(t *testing.T) {
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"0", 0}, {"2", 2 * time.Second}, {" 60 ", 60 * time.Second}, {"61", 60 * time.Second},
		{strings.Repeat("9", 100), 60 * time.Second},
		{now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second},
		{now.Add(2 * time.Hour).Format(http.TimeFormat), 60 * time.Second},
		{now.Add(-time.Hour).Format(http.TimeFormat), 0},
	} {
		if got := registryRetryDelay(tc.value, 0, now); got != tc.want {
			t.Errorf("%q: got %v want %v", tc.value, got, tc.want)
		}
	}
	for _, value := range []string{"", "invalid", "-1", "1.5", "+2"} {
		seen := map[time.Duration]bool{}
		for attempt := 0; attempt < 3; attempt++ {
			for range 16 {
				delay := registryRetryDelay(value, attempt, now)
				if delay < (100*time.Millisecond)<<attempt || delay > (200*time.Millisecond)<<attempt {
					t.Fatalf("unbounded backoff: %v", delay)
				}
				seen[delay] = true
			}
		}
		if len(seen) <= 3 {
			t.Fatal("backoff has no jitter")
		}
	}
}

func TestRegistryReferenceLogSanitization(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct{ input, want string }{
		{"registry://alpine@" + digest, "registry://alpine@" + digest},
		{"registry://ghcr.io/org/image@" + digest, "registry://ghcr.io/org/image@" + digest},
		{"oci://alpine:latest", "oci://alpine:latest"},
		{"/tmp/file?local", "/tmp/file?local"},
		{"registry://user:password@ghcr.io/org/image?token=secret", "registry://ghcr.io/org/image"},
		{"registry://bad%user:password@ghcr.io/org/image?token=secret", "registry://ghcr.io/org/image"},
		{"registry://user:bad/password@ghcr.io/org/image?token=secret", "registry://<invalid>"},
		{"oci://bad host/image?token=secret", "oci://<invalid>"},
	} {
		if got := RegistryReferenceForLog(tc.input); got != tc.want {
			t.Errorf("sanitized reference=%q want=%q", got, tc.want)
		}
	}
}
