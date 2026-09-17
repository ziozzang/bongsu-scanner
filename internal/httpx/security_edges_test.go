package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityClientDefaultsAndMissingTransport(t *testing.T) {
	c := New(time.Second)
	c.UserAgent, c.MaxBytes = "", 0
	c.AllowedHosts = []string{" ", " Example.COM. "}
	if err := c.CheckURL("https://sub.example.com/path"); err != nil {
		t.Fatal(err)
	}
	if c.limit(0) != DefaultMaxBytes {
		t.Fatal("missing default body cap")
	}
	if err := c.checkURL(nil); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("nil URL: %v", err)
	}
	req, err := c.newRequest(context.Background(), "https://example.com", map[string]string{"X-Empty": ""})
	if err != nil {
		t.Fatal(err)
	}
	if req.UserAgent() != "bscan/"+Version || len(req.Header.Values("X-Empty")) != 0 {
		t.Fatalf("headers = %v", req.Header)
	}
	if _, err := c.newRequest(nil, "https://example.com", nil); err == nil {
		t.Fatal("nil context accepted")
	}
	c.HTTP = nil
	var v any
	if err := c.GetJSON(context.Background(), "https://example.com", nil, &v); err == nil || !strings.Contains(err.Error(), "no HTTP transport") {
		t.Fatalf("GetJSON without transport: %v", err)
	}
	if _, _, _, err := c.Download(context.Background(), "https://example.com", nil, io.Discard, 0); err == nil || !strings.Contains(err.Error(), "no HTTP transport") {
		t.Fatalf("Download without transport: %v", err)
	}
}

func TestSecurityTruncatedResponses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "{}")
	}))
	defer srv.Close()
	c := testClient(t, srv)
	var v any
	if err := c.GetJSON(context.Background(), srv.URL, nil, &v); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("JSON read error: %v", err)
	}
	if _, _, _, err := c.Download(context.Background(), srv.URL, nil, io.Discard, 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("download read error: %v", err)
	}
}

func TestSecurityHTTPTimeouts(t *testing.T) {
	for _, method := range []string{"json", "download"} {
		for _, stage := range []string{"headers", "body"} {
			t.Run(method+"/"+stage, func(t *testing.T) {
				done := make(chan struct{})
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/ready" {
						_, _ = io.WriteString(w, "{}")
						return
					}
					if stage == "body" {
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
					}
					// Block until the client has observed its timeout. Returning on
					// r.Context().Done() raced the client's cancellation: a clean
					// end-of-body could arrive first and surface as a decode error.
					<-done
				}))
				defer srv.Close()
				defer close(done)
				c := testClient(t, srv)
				var v any
				// Establish TLS before starting the short request timeout.
				if err := c.GetJSON(context.Background(), srv.URL+"/ready", nil, &v); err != nil {
					t.Fatal(err)
				}
				c.HTTP.Timeout = 40 * time.Millisecond
				var err error
				if method == "json" {
					err = c.GetJSON(context.Background(), srv.URL+"/wait", nil, &v)
				} else {
					_, _, _, err = c.Download(context.Background(), srv.URL+"/wait", nil, io.Discard, 0)
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("timeout = %v", err)
				}
			})
		}
	}
}

func TestSecuritySanitizeControlStrings(t *testing.T) {
	for _, input := range []string{"a\x1bPpayload\x1b\\b", "a\x1bXpayload\x1b\\b", "a\x1b^payload\x1b\\b", "a\x1b_payload\x1b\\b"} {
		if got := Sanitize(input); got != "ab" {
			t.Errorf("Sanitize(%q) = %q", input, got)
		}
	}
	for _, input := range []string{"safe\x1b", "safe\x1b[31", "safe\x1b]unterminated"} {
		if got := Sanitize(input); got != "safe" {
			t.Errorf("Sanitize(%q) = %q", input, got)
		}
	}
}
