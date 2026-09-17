// Package httpx is a small hardened HTTP client used for every outbound
// request bscan makes (release metadata, release assets, future vulnerability
// database downloads).
//
// Policy enforced by every request:
//   - only https:// URLs are accepted, including redirect targets;
//   - at most 5 redirects are followed;
//   - an optional host allow-list (suffix match) is applied to the initial URL
//     and to every redirect target;
//   - response bodies are bounded (Content-Length is checked up front and the
//     stream is capped while reading);
//   - server-controlled strings that end up in error messages are sanitized so
//     they cannot inject terminal escape sequences.
package httpx

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Version is embedded in the default User-Agent ("bscan/<Version>").
// The main package overrides Client.UserAgent with its linked version.
var Version = "dev"

const (
	// DefaultMaxBytes bounds JSON responses and downloads when no explicit
	// limit is given.
	DefaultMaxBytes int64 = 4 << 20
	// MaxRedirects is the number of redirects followed before giving up.
	MaxRedirects = 5
	// errorBodyBytes is how much of a non-2xx body is included in errors.
	errorBodyBytes = 512
	// SanitizeLimit is the maximum length (in runes) of a sanitized string.
	SanitizeLimit = 200
)

var (
	ErrInsecureURL      = errors.New("httpx: only https:// URLs are allowed")
	ErrHostNotAllowed   = errors.New("httpx: host is not in the allow-list")
	ErrTooManyRedirects = errors.New("httpx: too many redirects")
	ErrTooLarge         = errors.New("httpx: response body exceeds size limit")
	ErrNotModified      = errors.New("httpx: not modified")
)

// StatusError is returned for non-2xx responses (other than 304 on Download).
type StatusError struct {
	StatusCode int
	Status     string // sanitized status line
	Body       string // sanitized, truncated body
	URL        string // scheme://host/path of the original request (no query)
}

func (e *StatusError) Error() string {
	s := "httpx: " + e.URL + ": HTTP " + e.Status
	if e.Body != "" {
		s += ": " + e.Body
	}
	return s
}

// Client wraps *http.Client with bscan's outbound policy. HTTP.Transport may
// be replaced (for example by tests that trust an httptest TLS certificate);
// CheckRedirect must be kept as installed by New.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	// MaxBytes bounds GetJSON responses and Download when maxBytes <= 0.
	MaxBytes int64
	// AllowedHosts, when non-empty, restricts request and redirect targets to
	// hosts equal to, or ending with "." + one of these entries.
	AllowedHosts []string
}

// New returns a Client with sane timeouts, proxy support from the environment,
// TLS 1.2+, https-only redirects, and a "bscan/<Version>" User-Agent.
func New(timeout time.Duration) *Client {
	c := &Client{UserAgent: "bscan/" + Version, MaxBytes: DefaultMaxBytes}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	c.HTTP = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return ErrTooManyRedirects
			}
			return c.checkURL(req.URL)
		},
	}
	return c
}

// CheckURL reports whether rawURL satisfies the client's policy.
func (c *Client) CheckURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("httpx: invalid URL: %w", err)
	}
	return c.checkURL(u)
}

func (c *Client) checkURL(u *url.URL) error {
	if u == nil || !strings.EqualFold(u.Scheme, "https") {
		return ErrInsecureURL
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || u.User != nil {
		return ErrInsecureURL
	}
	if len(c.AllowedHosts) == 0 {
		return nil
	}
	for _, allowed := range c.AllowedHosts {
		allowed = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(allowed), "."))
		if allowed == "" {
			continue
		}
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrHostNotAllowed, host)
}

func (c *Client) newRequest(ctx context.Context, rawURL string, headers map[string]string) (*http.Request, error) {
	if err := c.CheckURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	ua := c.UserAgent
	if ua == "" {
		ua = "bscan/" + Version
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.HTTP == nil {
		return nil, errors.New("httpx: client has no HTTP transport")
	}
	return c.HTTP.Do(req)
}

// statusError drains up to errorBodyBytes of the body into a StatusError.
func statusError(req *http.Request, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyBytes))
	u := *req.URL
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return &StatusError{
		StatusCode: resp.StatusCode,
		Status:     Sanitize(resp.Status),
		Body:       Sanitize(string(body)),
		URL:        u.String(),
	}
}

func (c *Client) limit(maxBytes int64) int64 {
	if maxBytes > 0 {
		return maxBytes
	}
	if c.MaxBytes > 0 {
		return c.MaxBytes
	}
	return DefaultMaxBytes
}

// GetJSON fetches rawURL and decodes the JSON body into v. The body is
// limited to MaxBytes; non-2xx responses yield a *StatusError.
func (c *Client) GetJSON(ctx context.Context, rawURL string, headers map[string]string, v any) error {
	req, err := c.newRequest(ctx, rawURL, headers)
	if err != nil {
		return err
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError(req, resp)
	}
	limit := c.limit(0)
	if resp.ContentLength > limit {
		return fmt.Errorf("%w (%d bytes)", ErrTooLarge, resp.ContentLength)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return ErrTooLarge
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("httpx: decode JSON from %s: %w", req.URL.Host, err)
	}
	return nil
}

// Download streams the body of rawURL into w, writing at most maxBytes
// (Client.MaxBytes when maxBytes <= 0). A 304 response returns ErrNotModified
// (callers pass If-None-Match / If-Modified-Since through headers). A body
// whose Content-Length exceeds the limit is rejected before any byte is read.
func (c *Client) Download(ctx context.Context, rawURL string, headers map[string]string, w io.Writer, maxBytes int64) (n int64, etag, lastModified string, err error) {
	req, err := c.newRequest(ctx, rawURL, headers)
	if err != nil {
		return 0, "", "", err
	}
	resp, err := c.do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = resp.Body.Close()
	}()
	etag = Sanitize(resp.Header.Get("ETag"))
	lastModified = Sanitize(resp.Header.Get("Last-Modified"))
	if resp.StatusCode == http.StatusNotModified {
		return 0, etag, lastModified, ErrNotModified
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return 0, etag, lastModified, statusError(req, resp)
	}
	limit := c.limit(maxBytes)
	if resp.ContentLength > limit {
		return 0, etag, lastModified, fmt.Errorf("%w (%d > %d bytes)", ErrTooLarge, resp.ContentLength, limit)
	}
	n, err = io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return n, etag, lastModified, err
	}
	if n > limit {
		return n, etag, lastModified, fmt.Errorf("%w (> %d bytes)", ErrTooLarge, limit)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return n, etag, lastModified, fmt.Errorf("httpx: short body: got %d of %d bytes", n, resp.ContentLength)
	}
	return n, etag, lastModified, nil
}

// Sanitize makes a server-supplied string safe for terminal output: ANSI
// escape sequences (CSI/OSC and other ESC-introduced sequences), C0/C1 control
// characters, and invalid UTF-8 are dropped, whitespace runs collapse to one
// space, and the result is capped at SanitizeLimit runes (with a trailing
// "..." when truncated).
func Sanitize(s string) string {
	out := make([]rune, 0, len(s))
	pendingSpace := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			continue
		case r == 0x1b || r == 0x9b || r == 0x9d:
			i += skipEscape(s[i:], r)
			continue
		case r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f':
			pendingSpace = len(out) > 0
			continue
		case unicode.IsControl(r), !unicode.IsPrint(r) && !unicode.IsSpace(r):
			continue
		case unicode.IsSpace(r):
			pendingSpace = len(out) > 0
			continue
		}
		if pendingSpace {
			out = append(out, ' ')
			pendingSpace = false
		}
		out = append(out, r)
		if len(out) > SanitizeLimit {
			break
		}
	}
	if len(out) > SanitizeLimit {
		out = append(out[:SanitizeLimit-3], '.', '.', '.')
	}
	return string(out)
}

// skipEscape returns how many bytes of rest belong to the escape sequence
// introduced by intro (ESC, CSI, or OSC) so the whole sequence is dropped
// rather than leaving its printable tail ("[31m") behind.
func skipEscape(rest string, intro rune) int {
	csi, osc := intro == 0x9b, intro == 0x9d
	i := 0
	if intro == 0x1b && len(rest) > 0 {
		switch rest[0] {
		case '[':
			csi, i = true, 1
		case ']':
			osc, i = true, 1
		case 'P', 'X', '^', '_': // DCS/SOS/PM/APC: terminated by ST
			osc, i = true, 1
		default:
			// Two-character sequence (e.g. ESC c, ESC ( B): drop the next byte.
			return 1
		}
	}
	switch {
	case csi:
		for i < len(rest) {
			b := rest[i]
			i++
			if b >= 0x40 && b <= 0x7e {
				break
			}
		}
	case osc:
		for i < len(rest) {
			b := rest[i]
			i++
			if b == 0x07 || b == 0x9c { // BEL or ST (single byte C1)
				break
			}
			if b == 0x1b && i < len(rest) && rest[i] == '\\' { // ESC \ (ST)
				i++
				break
			}
		}
	}
	return i
}
