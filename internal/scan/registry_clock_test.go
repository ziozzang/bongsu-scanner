package scan

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestRegistryRetryBackoffClock(t *testing.T) {
	for _, status := range []int{429, 500, 503, 404} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c := registrySecurityClient(t)
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				last := time.Now()
				c.http.HTTP.Transport = registryRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					if calls > 0 {
						base := (200 * time.Millisecond) << (calls - 1)
						if elapsed := time.Since(last); elapsed < base/2 || elapsed > base {
							t.Errorf("retry %d delay=%s, want [%s,%s]", calls, elapsed, base/2, base)
						}
					}
					last = time.Now()
					calls++
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				})
				resp, err := c.request(context.Background(), c.base, "", "")
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				want := 4
				if status == 404 {
					want = 1
				}
				if calls != want || resp.StatusCode != status {
					t.Fatalf("calls=%d status=%d, want %d/%d", calls, resp.StatusCode, want, status)
				}
			})
		})
	}
}
