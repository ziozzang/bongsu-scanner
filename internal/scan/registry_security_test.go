package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type registryRoundTripFunc func(*http.Request) (*http.Response, error)

func (f registryRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type registryErrorReader struct{ err error }

func (r registryErrorReader) Read([]byte) (int, error) { return 0, r.err }

func registrySecurityClient(t *testing.T) *registryClient {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BSCAN_REGISTRY_USER", "")
	t.Setenv("BSCAN_REGISTRY_PASSWORD", "")
	layout := t.TempDir()
	if err := os.MkdirAll(filepath.Join(layout, "blobs", "sha256"), 0700); err != nil {
		t.Fatal(err)
	}
	c, err := newRegistryClient(registryReference{host: "registry.example", repository: "org/image"}, Options{InsecureRegistry: true}, layout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.http.HTTP.CloseIdleConnections)
	return c
}

func TestRegistrySecurityPlaintextCredentials(t *testing.T) {
	for _, auth := range []string{"Basic dXNlcjpwYXNz", "Bearer secret"} {
		t.Run(strings.Fields(auth)[0], func(t *testing.T) {
			c := registrySecurityClient(t)
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			defer server.Close()
			resp, err := c.request(context.Background(), server.URL, "", auth)
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "HTTPS") || hits.Load() != 0 {
				t.Fatalf("credential request: hits=%d err=%v", hits.Load(), err)
			}
			resp, err = c.request(context.Background(), server.URL, "", "")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if hits.Load() != 1 {
				t.Fatal("anonymous loopback request blocked")
			}
		})
	}
	for _, kind := range []string{"basic", "bearer"} {
		t.Run("challenge-"+kind, func(t *testing.T) {
			c := registrySecurityClient(t)
			c.base = "http://127.0.0.1:5000"
			c.user, c.password = "user", "password"
			err := c.authenticate(context.Background(), http.Header{"Www-Authenticate": {kind + ` realm="https://auth.example/token"`}})
			if err == nil || !strings.Contains(err.Error(), "anonymous") {
				t.Fatalf("HTTP challenge accepted: %v", err)
			}
		})
	}
}

func TestRegistrySecurityTokenRealmAndScope(t *testing.T) {
	c := registrySecurityClient(t)
	var calls int
	c.http.HTTP.Transport = registryRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if got := r.URL.Query()["scope"]; len(got) != 1 || got[0] != "repository:org/image:pull" {
			t.Errorf("excessive scope: %v", got)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"token":"secret"}`)), Header: make(http.Header), Request: r}, nil
	})
	for _, realm := range []string{"http://127.0.0.1/token", "https://auth.example/token?scope=repository:other:push"} {
		err := c.authenticate(context.Background(), http.Header{"Www-Authenticate": {`Bearer realm="` + realm + `",scope="repository:org/image:pull,push repository:other:push"`}})
		if strings.HasPrefix(realm, "http:") {
			if err == nil || calls != 0 {
				t.Fatalf("HTTP realm accepted: calls=%d err=%v", calls, err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("token requests=%d", calls)
	}
}

func TestRegistrySecurityRedirectDowngrade(t *testing.T) {
	c := registrySecurityClient(t)
	var hits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"?token=secret", 307)
	}))
	defer source.Close()
	c.http.HTTP.Transport = source.Client().Transport
	for _, auth := range []string{"", "Bearer secret"} {
		resp, err := c.request(context.Background(), source.URL, "", auth)
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil || strings.Contains(err.Error(), "secret") || hits.Load() != 0 {
			t.Fatalf("downgrade hits=%d err=%v", hits.Load(), err)
		}
	}
}

func TestRegistrySecurityNetworkErrors(t *testing.T) {
	for _, stage := range []string{"transport", "token", "manifest", "blob-copy", "blob-probe"} {
		for _, cause := range []error{errors.New("server-secret-token"), fmt.Errorf("server-secret-token: %w", context.Canceled), fmt.Errorf("server-secret-token: %w", context.DeadlineExceeded)} {
			t.Run(stage+"/"+cause.Error(), func(t *testing.T) {
				c := registrySecurityClient(t)
				raw := "blob"
				c.http.HTTP.Transport = registryRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					if stage == "transport" {
						return nil, cause
					}
					var body io.Reader = registryErrorReader{cause}
					if stage == "blob-probe" {
						body = io.MultiReader(strings.NewReader(raw), body)
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {mediaTypeOCIManifest}}, ContentLength: -1, Body: io.NopCloser(body), Request: r}, nil
				})
				var err error
				switch stage {
				case "transport":
					_, err = c.request(context.Background(), c.base, "", "")
				case "token":
					err = c.authenticate(context.Background(), http.Header{"Www-Authenticate": {`Bearer realm="https://auth.example/token"`}})
				case "manifest":
					_, _, err = c.manifest(context.Background(), "latest", nil)
				default:
					err = c.blob(context.Background(), ociDescriptor{Digest: digestOf([]byte(raw)), Size: int64(len(raw))}, false)
				}
				if err == nil || strings.Contains(err.Error(), "server-secret-token") {
					t.Fatalf("unsafe error: %v", err)
				}
				for _, kind := range []error{context.Canceled, context.DeadlineExceeded} {
					if errors.Is(cause, kind) != errors.Is(err, kind) {
						t.Fatalf("classification lost: %v", err)
					}
				}
			})
		}
	}
}

func TestRegistrySecurityManifestCacheAndBudget(t *testing.T) {
	t.Run("cache", func(t *testing.T) {
		f := newRegistryFixture(t)
		child := f.manifests["arm64"]
		child.Platform = nil
		children := make([]ociDescriptor, 64)
		for i := range children {
			children[i] = child
		}
		f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": children})
		c := f.tlsClient(t)
		want, _ := parsePlatform("linux/amd64")
		_, _, err := c.selectManifest(context.Background(), "latest", nil, want, 0)
		if !errors.Is(err, errRegistryPlatform) {
			t.Fatal(err)
		}
		f.mu.Lock()
		hits := f.hits["/v2/org/image/manifests/"+child.Digest]
		f.mu.Unlock()
		if hits != 1 {
			t.Fatalf("same manifest downloaded %d times, want 1", hits)
		}
		child.Size++
		if _, _, err := c.manifest(context.Background(), child.Digest, &child); err == nil {
			t.Fatal("cached size mismatch accepted")
		}
	})
	t.Run("global-descriptors", func(t *testing.T) {
		f := newRegistryFixture(t)
		child := f.manifests["arm64"]
		child.Platform = nil
		children := make([]ociDescriptor, 16)
		for i := range children {
			children[i] = child
		}
		nested := mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": children})
		d := ociDescriptor{Digest: digestOf(nested), Size: int64(len(nested)), MediaType: mediaTypeOCIIndex}
		f.data[d.Digest] = nested
		roots := make([]ociDescriptor, 17)
		for i := range roots {
			roots[i] = d
		}
		f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": roots})
		c := f.tlsClient(t)
		want, _ := parsePlatform("linux/amd64")
		_, _, err := c.selectManifest(context.Background(), "latest", nil, want, 0)
		if err == nil || !strings.Contains(err.Error(), "budget") {
			t.Fatalf("global budget: %v", err)
		}
	})
	t.Run("requests", func(t *testing.T) {
		f := newRegistryFixture(t)
		c := f.tlsClient(t)
		for i := 0; i < 256; i++ {
			if _, _, err := c.manifest(context.Background(), "latest", nil); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := c.manifest(context.Background(), "latest", nil); err == nil || !strings.Contains(err.Error(), "budget") {
			t.Fatalf("request budget: %v", err)
		}
	})
}

func TestRegistrySecurityRetryAfter(t *testing.T) {
	for _, form := range []string{"seconds", "date"} {
		t.Run(form, func(t *testing.T) {
			c := registrySecurityClient(t)
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				c.http.HTTP.Transport = registryRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					value := "2"
					if form == "date" {
						value = time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
					}
					return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {value}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				})
				start := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
				defer cancel()
				_, err := c.request(ctx, c.base, "", "")
				if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
					t.Fatalf("retry before Retry-After: calls=%d err=%v", calls, err)
				}
				if elapsed := time.Since(start); elapsed != 400*time.Millisecond {
					t.Fatalf("retry cancellation elapsed %s, want exactly 400ms of virtual time", elapsed)
				}
			})
		})
	}
}

func TestRegistrySecurityMediaTypes(t *testing.T) {
	for _, kind := range []string{"content-type", "content-mismatch", "index-child", "unselected-child", "descriptor-mismatch", "config", "layer"} {
		t.Run(kind, func(t *testing.T) {
			f := newRegistryFixture(t)
			switch kind {
			case "content-type", "content-mismatch":
				f.hook = func(w http.ResponseWriter, r *http.Request) bool {
					if !strings.HasSuffix(r.URL.Path, "/manifests/latest") {
						return false
					}
					mt := "text/plain"
					if kind == "content-mismatch" {
						mt = mediaTypeOCIManifest
					}
					w.Header().Set("Content-Type", mt)
					w.Write(f.root)
					return true
				}
			case "index-child", "unselected-child", "descriptor-mismatch":
				d := f.manifests["amd64"]
				d.MediaType = "application/unknown"
				if kind == "unselected-child" {
					d.Platform = &ociPlatform{OS: "windows", Architecture: "amd64"}
				}
				if kind == "descriptor-mismatch" {
					d.MediaType = mediaTypeOCIIndex
				}
				f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": []ociDescriptor{d, f.manifests["amd64"]}})
			case "config", "layer":
				config := f.configs["amd64"]
				layer := f.layers["amd64"]
				if kind == "config" {
					config.MediaType = "application/unknown"
				} else {
					layer.MediaType = "application/unknown"
				}
				f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIManifest, "config": config, "layers": []ociDescriptor{layer}})
			}
			c := f.tlsClient(t)
			want, _ := parsePlatform("linux/amd64")
			_, _, err := c.selectManifest(context.Background(), "latest", nil, want, 0)
			if err == nil || !(strings.Contains(err.Error(), "media type") || strings.Contains(err.Error(), "Content-Type")) {
				t.Fatalf("invalid media type accepted: %v", err)
			}
		})
	}
}

func TestRegistrySecurityCombinedChallenges(t *testing.T) {
	for _, header := range []string{
		`Basic realm="legacy", Bearer realm="https://auth.example/token",service="a,b",scope="repository:org/image:pull,push"`,
		`Newauth abc==, Basic realm="legacy", bEaReR realm="https://auth.example/token", SERVICE="a,b", scope="repository:org/image:pull,push"`,
		`Bearer realm="https://auth.example/token",service="a,b",scope="repository:org/image:pull,push", Basic realm="legacy"`,
	} {
		kind, params, err := registryChallenge(http.Header{"Www-Authenticate": {header}})
		if err != nil || kind != "bearer" || params["realm"] != "https://auth.example/token" || params["service"] != "a,b" || params["scope"] != "repository:org/image:pull,push" {
			t.Fatalf("challenge: %s %#v %v", kind, params, err)
		}
	}
	kind, params, err := registryChallenge(http.Header{"Www-Authenticate": {`Basic realm="a\"b, c\\d"`}})
	if err != nil || kind != "basic" || params["realm"] != `a"b, c\d` {
		t.Fatalf("escaped quote: %#v %v", params, err)
	}
}

func TestRegistrySecurityNormalizedLength(t *testing.T) {
	for _, host := range []string{"", "docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		for _, n := range []int{247, 248, 255} {
			_, err := parseRegistryReference("registry://" + host + strings.Repeat("a", n))
			if (err == nil) != (n == 247) {
				t.Errorf("host=%s length=%d err=%v", host, n, err)
			}
		}
	}
}
