package httpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c := New(5 * time.Second)
	c.HTTP.Transport = srv.Client().Transport
	return c
}

func TestRejectsHTTPScheme(t *testing.T) {
	c := New(time.Second)
	var v struct{}
	if err := c.GetJSON(context.Background(), "http://example.com/x", nil, &v); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("GetJSON http err = %v", err)
	}
	if _, _, _, err := c.Download(context.Background(), "http://example.com/x", nil, io.Discard, 0); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("Download http err = %v", err)
	}
	for _, u := range []string{"", "ftp://example.com/", "https://user:pw@example.com/", "https:///path", "://bad"} {
		if err := c.CheckURL(u); err == nil {
			t.Errorf("CheckURL(%q) accepted", u)
		}
	}
}

func TestAllowedHostsSuffixMatch(t *testing.T) {
	c := New(time.Second)
	c.AllowedHosts = []string{"github.com", "githubusercontent.com"}
	for _, u := range []string{"https://github.com/a", "https://api.github.com/b", "https://objects.githubusercontent.com/c", "https://GitHub.com./d"} {
		if err := c.CheckURL(u); err != nil {
			t.Errorf("CheckURL(%q) = %v", u, err)
		}
	}
	for _, u := range []string{"https://evilgithub.com/a", "https://github.com.evil.example/b", "https://example.com/"} {
		if err := c.CheckURL(u); !errors.Is(err, ErrHostNotAllowed) {
			t.Errorf("CheckURL(%q) = %v, want ErrHostNotAllowed", u, err)
		}
	}
}

func TestGetJSON(t *testing.T) {
	var gotUA, gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotAuth = r.UserAgent(), r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"tag_name":"v1.2.3"}`)
		case "/err":
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "rate \x1b[31mlimited\x1b[0m\n"+strings.Repeat("x", 2000))
		case "/big":
			w.Header().Set("Content-Length", "10000000")
			w.WriteHeader(200)
		case "/stream-big":
			io.WriteString(w, strings.Repeat("a", 5000))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := testClient(t, srv)
	c.UserAgent = "bscan/test"
	var v struct {
		Tag string `json:"tag_name"`
	}
	if err := c.GetJSON(context.Background(), srv.URL+"/ok?secret=1", map[string]string{"Authorization": "Bearer x"}, &v); err != nil || v.Tag != "v1.2.3" {
		t.Fatalf("GetJSON = %v, %#v", err, v)
	}
	if gotUA != "bscan/test" || gotAuth != "Bearer x" {
		t.Fatalf("headers: ua=%q auth=%q", gotUA, gotAuth)
	}

	err := c.GetJSON(context.Background(), srv.URL+"/err?token=abc", nil, &v)
	var se *StatusError
	if !errors.As(err, &se) || se.StatusCode != 403 {
		t.Fatalf("err = %v", err)
	}
	if strings.ContainsRune(se.Error(), 0x1b) || strings.Contains(se.Error(), "\n") {
		t.Fatalf("error not sanitized: %q", se.Error())
	}
	if len([]rune(se.Body)) > SanitizeLimit || !strings.Contains(se.Body, "rate limited") {
		t.Fatalf("body = %q", se.Body)
	}
	if strings.Contains(se.Error(), "token=abc") {
		t.Fatalf("error leaks query: %q", se.Error())
	}

	if err := c.GetJSON(context.Background(), srv.URL+"/big", nil, &v); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("content-length too large: %v", err)
	}
	c.MaxBytes = 1024
	if err := c.GetJSON(context.Background(), srv.URL+"/stream-big", nil, &v); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("streamed too large: %v", err)
	}
}

func TestDownload(t *testing.T) {
	body := bytes.Repeat([]byte("z"), 4096)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/asset":
			if r.Header.Get("If-None-Match") == `"etag1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"etag1"`)
			w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
			w.Write(body)
		case "/chunked":
			w.Header().Set("Transfer-Encoding", "chunked")
			w.Write(body)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "nope")
		}
	}))
	defer srv.Close()
	c := testClient(t, srv)
	ctx := context.Background()

	var buf bytes.Buffer
	n, etag, lm, err := c.Download(ctx, srv.URL+"/asset", nil, &buf, 0)
	if err != nil || n != int64(len(body)) || !bytes.Equal(buf.Bytes(), body) || etag != `"etag1"` || lm == "" {
		t.Fatalf("Download = n=%d etag=%q lm=%q err=%v", n, etag, lm, err)
	}
	if _, _, _, err := c.Download(ctx, srv.URL+"/asset", map[string]string{"If-None-Match": `"etag1"`}, io.Discard, 0); !errors.Is(err, ErrNotModified) {
		t.Fatalf("304 err = %v", err)
	}
	if _, _, _, err := c.Download(ctx, srv.URL+"/asset", nil, io.Discard, 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("content-length cap err = %v", err)
	}
	if _, _, _, err := c.Download(ctx, srv.URL+"/chunked", nil, io.Discard, 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("stream cap err = %v", err)
	}
	if n, _, _, err := c.Download(ctx, srv.URL+"/chunked", nil, io.Discard, int64(len(body))); err != nil || n != int64(len(body)) {
		t.Fatalf("exact cap: n=%d err=%v", n, err)
	}
	var se *StatusError
	if _, _, _, err := c.Download(ctx, srv.URL+"/missing", nil, io.Discard, 0); !errors.As(err, &se) || se.StatusCode != 404 || se.Body != "nope" {
		t.Fatalf("404 err = %v", err)
	}
}

func TestRedirectPolicy(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-http":
			http.Redirect(w, r, "http://127.0.0.1:9/plain", http.StatusFound)
		case "/to-other-host":
			http.Redirect(w, r, "https://evil.example/x", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
		case "/hop":
			http.Redirect(w, r, srv.URL+"/final", http.StatusFound)
		case "/final":
			io.WriteString(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := testClient(t, srv)
	var v struct{ OK bool }
	if err := c.GetJSON(context.Background(), srv.URL+"/to-http", nil, &v); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("https->http redirect err = %v", err)
	}
	if err := c.GetJSON(context.Background(), srv.URL+"/loop", nil, &v); !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("redirect loop err = %v", err)
	}
	if err := c.GetJSON(context.Background(), srv.URL+"/hop", nil, &v); err != nil || !v.OK {
		t.Fatalf("single redirect: %v %#v", err, v)
	}
	c.AllowedHosts = []string{"127.0.0.1"}
	if err := c.GetJSON(context.Background(), srv.URL+"/to-other-host", nil, &v); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("redirect off allow-list err = %v", err)
	}
}

func TestRedirectLimitBoundary(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remaining, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if remaining > 0 {
			http.Redirect(w, r, "/"+strconv.Itoa(remaining-1), http.StatusFound)
			return
		}
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	c := testClient(t, srv)
	var result map[string]any
	if err := c.GetJSON(context.Background(), srv.URL+"/"+strconv.Itoa(MaxRedirects), nil, &result); err != nil {
		t.Fatalf("exactly %d redirects: %v", MaxRedirects, err)
	}
	if err := c.GetJSON(context.Background(), srv.URL+"/"+strconv.Itoa(MaxRedirects+1), nil, &result); !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("over redirect limit: %v", err)
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"":                                   "",
		"plain":                              "plain",
		"a\x1b[31mred\x1b[0m b":              "ared b",
		"line1\nline2\r\n\ttab":              "line1 line2 tab",
		"  leading and trailing  ":           "leading and trailing",
		"bad\xffutf8":                        "badutf8",
		"c1\u0085control":                    "c1control",
		"한글 ok":                              "한글 ok",
		strings.Repeat("x", 300):             strings.Repeat("x", SanitizeLimit-3) + "...",
		strings.Repeat("y", 200):             strings.Repeat("y", 200),
		"zero\x00width\u200b":                "zerowidth",
		"\x1b]0;title\x07 bell\x07":          "bell",
		"plain [31m text":                    "plain [31m text",
		"\x1b[1;32mgreen\x1b[m\x1bc rst":     "green rst",
		"\u009b31mcsi8 \u009d0;x\u009c osc8": "csi8 osc8",
		"\x1b]8;;https://x\x1b\\link":        "link",
		"del\x7fchar":                        "delchar",
		"only   spaces    collapse":          "only spaces collapse",
		"trailing newline\n":                 "trailing newline",
		"\n\n leading whitespace\n\n x":      "leading whitespace x",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
