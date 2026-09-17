package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRegistryTargetDispatch(t *testing.T) {
	for _, scheme := range []string{"registry://", "oci://"} {
		_, err := Target(context.Background(), scheme+"bad host/image", Options{})
		if err == nil || !strings.Contains(err.Error(), "invalid registry reference") {
			t.Fatalf("%s dispatch: %v", scheme, err)
		}
	}
}

// Each platform has a distinct config and package version, making selection
// observable through the final catalog, not just the chosen descriptor.
type registryFixture struct {
	server         *httptest.Server
	root           []byte
	data           map[string][]byte
	manifests      map[string]ociDescriptor
	configs        map[string]ociDescriptor
	layers         map[string]ociDescriptor
	user, password string
	accessToken    bool
	hook           func(http.ResponseWriter, *http.Request) bool
	mu             sync.Mutex
	hits           map[string]int
}

func newRegistryFixture(t *testing.T) *registryFixture {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BSCAN_REGISTRY_USER", "")
	t.Setenv("BSCAN_REGISTRY_PASSWORD", "")
	f := &registryFixture{data: map[string][]byte{}, manifests: map[string]ociDescriptor{}, configs: map[string]ociDescriptor{}, layers: map[string]ociDescriptor{}, hits: map[string]int{}}
	var manifests []ociDescriptor
	for _, arch := range []string{"amd64", "arm64"} {
		layerRaw := buildTar(t, []tarEntry{
			{name: "lib/apk/db/installed", data: []byte("P:busybox\nV:1.36.1-r" + map[string]string{"amd64": "1", "arm64": "2"}[arch] + "\nA:" + arch + "\n\n")},
			{name: "etc/os-release", data: []byte("ID=alpine\nVERSION_ID=3.20.0\n")},
		})
		layer := gzipBytes(t, layerRaw)
		ld := ociDescriptor{MediaType: mediaTypeOCILayerGzip, Digest: digestOf(layer), Size: int64(len(layer))}
		cfg := mustJSON(t, map[string]any{"architecture": arch, "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{digestOf(layerRaw)}}})
		cd := ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digestOf(cfg), Size: int64(len(cfg))}
		manifest := mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIManifest, "config": cd, "layers": []ociDescriptor{ld}})
		md := ociDescriptor{MediaType: mediaTypeOCIManifest, Digest: digestOf(manifest), Size: int64(len(manifest)), Platform: &ociPlatform{OS: "linux", Architecture: arch}}
		f.data[ld.Digest], f.data[cd.Digest], f.data[md.Digest] = layer, cfg, manifest
		f.layers[arch], f.configs[arch], f.manifests[arch] = ld, cd, md
		manifests = append(manifests, md)
	}
	f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": manifests})
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		f.mu.Unlock()
		if f.hook != nil && f.hook(w, r) {
			return
		}
		if r.URL.Path == "/token" {
			user, password, basic := r.BasicAuth()
			if user != f.user || password != f.password || (f.user == "" && basic) {
				t.Error("unexpected token credentials")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if r.URL.Query().Get("service") != "fixture" || r.URL.Query().Get("scope") != "repository:org/image:pull" {
				t.Error("incorrect token service or scope")
			}
			key := "token"
			if f.accessToken {
				key = "access_token"
			}
			fmt.Fprintf(w, `{"%s":"fixture-secret-token"}`, key)
			return
		}
		if r.TLS != nil && r.Header.Get("Authorization") != "Bearer fixture-secret-token" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+r.Host+`/token",service="fixture",scope="repository:org/image:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v2/org/image/manifests/") {
			for _, mt := range []string{mediaTypeOCIIndex, mediaTypeOCIManifest, mediaTypeDockerList, mediaTypeDockerManifest} {
				if !strings.Contains(r.Header.Get("Accept"), mt) {
					t.Errorf("Accept lacks %s", mt)
				}
			}
			ref := strings.TrimPrefix(r.URL.Path, "/v2/org/image/manifests/")
			raw := f.data[ref]
			if ref == "latest" || ref == digestOf(f.root) {
				raw = f.root
			}
			if raw != nil {
				var probe struct {
					MediaType string `json:"mediaType"`
				}
				if err := json.Unmarshal(raw, &probe); err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", probe.MediaType)
				w.Header().Set("Docker-Content-Digest", digestOf(raw))
				w.Write(raw)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/v2/org/image/blobs/") {
			if raw := f.data[strings.TrimPrefix(r.URL.Path, "/v2/org/image/blobs/")]; raw != nil {
				w.Write(raw)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *registryFixture) target() string {
	return "registry://" + strings.TrimPrefix(f.server.URL, "http://") + "/org/image:latest"
}

func registryTempRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	return root
}

func assertRegistryClean(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("registry temporary files remain: %v, %v", entries, err)
	}
}

func TestRegistryImage(t *testing.T) {
	for _, tc := range []struct {
		name, platform, arch, auth string
		alias, digest              bool
	}{
		{"default", "", runtime.GOARCH, "", false, false},
		{"arm64-env-auth", "linux/arm64", "arm64", "env", true, false},
		{"amd64-config-auth", "linux/amd64", "amd64", "docker", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRegistryFixture(t)
			tmp := registryTempRoot(t)
			if tc.auth != "" {
				f.user, f.password, f.accessToken = "fixture-user", "fixture:password", true
				if tc.auth == "env" {
					t.Setenv("BSCAN_REGISTRY_USER", f.user)
					t.Setenv("BSCAN_REGISTRY_PASSWORD", f.password)
				} else {
					dir := filepath.Join(os.Getenv("HOME"), ".docker")
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
					cfg := mustJSON(t, map[string]any{"auths": map[string]any{strings.TrimPrefix(f.server.URL, "http://"): map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(f.user + ":" + f.password))}}})
					if err := os.WriteFile(filepath.Join(dir, "config.json"), cfg, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.auth != "" {
				c := f.tlsClient(t)
				// Resolve credentials against the original fixture host for the Docker config case.
				var err error
				c.user, c.password, err = registryCredentials(strings.TrimPrefix(f.server.URL, "http://"))
				if err != nil {
					t.Fatal(err)
				}
				want, _ := parsePlatform(tc.platform)
				if _, _, err := c.selectManifest(context.Background(), "latest", nil, want, 0); err != nil {
					t.Fatal(err)
				}
			}
			target := f.target()
			if tc.digest {
				target = strings.TrimSuffix(target, ":latest") + "@" + digestOf(f.root)
			}
			if tc.alias {
				target = strings.Replace(target, "registry://", "oci://", 1)
			}
			var logs strings.Builder
			r, err := Target(context.Background(), target, Options{InsecureRegistry: true, Platform: tc.platform, Progress: func(p Progress) { logs.WriteString(p.Message) }})
			if err != nil {
				t.Fatal(err)
			}
			assertRegistryClean(t, tmp)
			if r.SourceType != "registry-image" || r.Source != strings.Replace(target, "oci://", "registry://", 1) || r.SourceHash != "" {
				t.Fatalf("incorrect registry provenance: %+v", r)
			}
			if len(r.Packages) != 1 || r.Packages[0].Name != "busybox" || r.Packages[0].Version != "1.36.1-r"+map[string]string{"amd64": "1", "arm64": "2"}[tc.arch] {
				t.Fatalf("incorrect package inventory: %+v", r.Packages)
			}
			if r.Image == nil || r.Image.Digest != f.manifests[tc.arch].Digest || r.Image.OS != "linux" || r.Image.Architecture != tc.arch || len(r.Image.Layers) != 1 || !r.Image.Layers[0].Verified {
				t.Fatalf("incorrect image metadata: %+v", r.Image)
			}
			if !tc.digest && (len(r.Image.Tags) != 1 || r.Image.Tags[0] != strings.TrimPrefix(f.target(), "registry://")) {
				t.Fatalf("tags: %v", r.Image.Tags)
			}
			for _, secret := range []string{"fixture-secret-token", "fixture:password"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatal("credentials leaked to progress")
				}
			}
			other := "arm64"
			if tc.arch == "arm64" {
				other = "amd64"
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.hits["/v2/org/image/blobs/"+f.layers[other].Digest] != 0 {
				t.Fatal("downloaded unselected platform")
			}
		})
	}
}

func TestRegistryReferenceNormalization(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		input, host, repo, ref string
		digest                 bool
	}{
		{"registry://docker.io/alpine:3.20", "registry-1.docker.io", "library/alpine", "3.20", false},
		{"registry://docker.io/library/alpine:3.20", "registry-1.docker.io", "library/alpine", "3.20", false},
		{"oci://alpine", "registry-1.docker.io", "library/alpine", "latest", false},
		{"registry://ghcr.io/org/img@" + digest, "ghcr.io", "org/img", digest, true},
		{"registry://localhost:5000/org/img:tag", "localhost:5000", "org/img", "tag", false},
	} {
		r, err := parseRegistryReference(tc.input)
		if err != nil || r.host != tc.host || r.repository != tc.repo || r.reference != tc.ref || r.digest != tc.digest {
			t.Fatalf("%s: %+v, %v", tc.input, r, err)
		}
	}
	for _, input := range []string{"registry://", "registry://host.io/../img", "registry://user:password@host.io/img", "registry://host.io/img?x=y", "registry://ghcr.io/img@sha256:../bad", "registry://host.io/UPPER", "registry://localhost:5000/"} {
		if _, err := parseRegistryReference(input); err == nil {
			t.Errorf("accepted invalid reference %q", input)
		}
	}
}

func TestRegistryDownloadFailuresAndCleanup(t *testing.T) {
	for _, kind := range []string{"layer-digest", "config-digest", "manifest-digest", "manifest-size", "blob-size", "blob-limit", "total-limit", "chunked-overflow", "platform", "canceled", "archive-error"} {
		t.Run(kind, func(t *testing.T) {
			f := newRegistryFixture(t)
			tmp := registryTempRoot(t)
			opts := Options{InsecureRegistry: true, Platform: "linux/amd64", AllowDigestMismatch: true}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ld := f.layers["amd64"]
			wantErr := "mismatch"
			switch kind {
			case "layer-digest", "config-digest":
				d := ld
				if kind == "config-digest" {
					d = f.configs["amd64"]
				}
				raw := append([]byte(nil), f.data[d.Digest]...)
				raw[0] ^= 1
				f.data[d.Digest] = raw
			case "manifest-digest":
				d := f.manifests["amd64"]
				f.data[d.Digest] = append(f.data[d.Digest], ' ')
			case "manifest-size":
				d := f.manifests["amd64"]
				d.Size++
				f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": []ociDescriptor{d}})
			case "blob-size":
				f.data[ld.Digest] = append(f.data[ld.Digest], 'x')
			case "blob-limit":
				// A layer larger than the metadata must fail before its request.
				ld.Size = 4096
				f.replaceLayers(t, []ociDescriptor{ld})
				opts.MaxRegistryBlobBytes = 2048
				wantErr = "size limit"
			case "total-limit":
				opts.MaxRegistryBytes = int64(len(f.root)) + f.manifests["amd64"].Size + f.configs["amd64"].Size + ld.Size - 1
				wantErr = "total download limit"
			case "chunked-overflow":
				f.hook = func(w http.ResponseWriter, r *http.Request) bool {
					if r.URL.Path != "/v2/org/image/blobs/"+ld.Digest {
						return false
					}
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					w.Write(append(append([]byte(nil), f.data[ld.Digest]...), 'x'))
					return true
				}
			case "platform":
				opts.Platform = "windows/amd64"
				wantErr = "platform"
			case "canceled":
				f.hook = func(w http.ResponseWriter, r *http.Request) bool {
					if r.URL.Path != "/v2/org/image/blobs/"+ld.Digest {
						return false
					}
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					w.Write(f.data[ld.Digest][:10])
					w.(http.Flusher).Flush()
					cancel()
					<-r.Context().Done()
					return true
				}
				wantErr = "context canceled"
			case "archive-error":
				raw := []byte("not a gzip layer")
				ld.Digest, ld.Size = digestOf(raw), int64(len(raw))
				f.data[ld.Digest] = raw
				f.replaceLayers(t, []ociDescriptor{ld})
				wantErr = ""
			}
			_, err := Target(ctx, f.target(), opts)
			if err == nil || !strings.Contains(err.Error(), wantErr) {
				t.Fatalf("expected %q error, got %v", wantErr, err)
			}
			if kind == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			assertRegistryClean(t, tmp)
			if kind == "blob-limit" || kind == "total-limit" {
				f.mu.Lock()
				defer f.mu.Unlock()
				if f.hits["/v2/org/image/blobs/"+ld.Digest] != 0 {
					t.Fatal("requested over-limit layer")
				}
			}
		})
	}
}

func (f *registryFixture) replaceLayers(t *testing.T, layers []ociDescriptor) {
	t.Helper()
	raw := mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIManifest, "config": f.configs["amd64"], "layers": layers})
	d := f.manifests["amd64"]
	d.Digest, d.Size = digestOf(raw), int64(len(raw))
	f.manifests["amd64"], f.data[d.Digest] = d, raw
	f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": []ociDescriptor{d}})
}

func TestRegistryRetries(t *testing.T) {
	for _, status := range []int{429, 500, 503, 404} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newRegistryFixture(t)
			tmp := registryTempRoot(t)
			var requests atomic.Int32
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/v2/org/image/manifests/latest" {
					return false
				}
				requests.Add(1)
				if testing.Short() {
					// Backoff timing is covered with virtual time in TestRegistryRetryBackoffClock.
					w.Header().Set("Retry-After", "0")
				}
				w.WriteHeader(status)
				fmt.Fprint(w, "fixture-secret-token")
				return true
			}
			_, err := Target(context.Background(), f.target(), Options{InsecureRegistry: true})
			want := int32(4)
			if status == 404 {
				want = 1
			}
			if err == nil || requests.Load() != want || strings.Contains(err.Error(), "fixture-secret-token") {
				t.Fatalf("attempts=%d, error=%v", requests.Load(), err)
			}
			assertRegistryClean(t, tmp)
		})
	}
}

func TestRegistryHTTPPolicy(t *testing.T) {
	f := newRegistryFixture(t)
	ref, err := parseRegistryReference(f.target())
	if err != nil {
		t.Fatal(err)
	}
	for _, insecure := range []bool{false, true} {
		c, err := newRegistryClient(ref, Options{InsecureRegistry: insecure}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer c.http.HTTP.CloseIdleConnections()
		for _, raw := range []string{"https://ghcr.io/v2/", "http://localhost:5000/v2/", "http://127.0.0.1:5000/v2/", "http://example.com/v2/", "http://127.0.0.2/v2/", "http://localhost.example.com/v2/", "https://user:password@ghcr.io/v2/"} {
			u, _ := url.Parse(raw)
			want := u.User == nil && (u.Scheme == "https" || (insecure && registryLocalhost(u)))
			if (c.checkURL(u) == nil) != want {
				t.Errorf("insecure=%t URL=%s", insecure, raw)
			}
		}
	}
	_, err = Target(context.Background(), f.target(), Options{})
	if err == nil {
		t.Fatal("plain HTTP registry accepted without opt-in")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hits) != 0 {
		t.Fatal("sent plaintext request without opt-in")
	}
}

func TestRegistryTransientRecovery(t *testing.T) {
	f := newRegistryFixture(t)
	var attempts atomic.Int32
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/token" && attempts.Add(1) <= 2 {
			w.WriteHeader(503)
			return true
		}
		return false
	}
	c := f.tlsClient(t)
	if _, _, err := c.manifest(context.Background(), "latest", nil); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("token attempts: %d", attempts.Load())
	}
}

func TestRegistryDirectAndNestedManifests(t *testing.T) {
	for _, kind := range []string{"single-docker", "nested", "platform-from-config", "config-platform-mismatch"} {
		t.Run(kind, func(t *testing.T) {
			f := newRegistryFixture(t)
			md := f.manifests["amd64"]
			switch kind {
			case "single-docker":
				f.root = []byte(strings.ReplaceAll(string(f.data[md.Digest]), mediaTypeOCIManifest, mediaTypeDockerManifest))
			case "nested":
				f.data[digestOf(f.root)] = f.root
				d := ociDescriptor{Digest: digestOf(f.root), Size: int64(len(f.root)), MediaType: mediaTypeOCIIndex}
				f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeDockerList, "manifests": []ociDescriptor{d}})
			case "platform-from-config":
				md.Platform = nil
				f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": []ociDescriptor{md}})
			case "config-platform-mismatch":
				md = f.manifests["arm64"]
				md.Platform = &ociPlatform{OS: "linux", Architecture: "amd64"}
				f.root = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": []ociDescriptor{md}})
			}
			r, err := Target(context.Background(), f.target(), Options{InsecureRegistry: true, Platform: "linux/amd64"})
			if kind == "config-platform-mismatch" {
				if !errors.Is(err, errRegistryPlatform) {
					t.Fatalf("config mismatch accepted: %v", err)
				}
				return
			}
			if err != nil || r.Image.Architecture != "amd64" || len(r.Packages) != 1 {
				t.Fatalf("result: %+v, error: %v", r, err)
			}
		})
	}
}

func TestRegistryTokenAndBackoffCancellation(t *testing.T) {
	for _, stage := range []string{"token", "backoff"} {
		t.Run(stage, func(t *testing.T) {
			f := newRegistryFixture(t)
			tmp := registryTempRoot(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/token" {
					return false
				}
				if stage == "backoff" {
					w.WriteHeader(429)
					cancel()
					return true
				}
				w.WriteHeader(200)
				fmt.Fprint(w, `{"token":"`)
				w.(http.Flusher).Flush()
				cancel()
				<-r.Context().Done()
				return true
			}
			c := f.tlsClient(t)
			_, _, err := c.manifest(ctx, "latest", nil)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			assertRegistryClean(t, tmp)
		})
	}
}

func TestRegistryRedirectCredentials(t *testing.T) {
	var leaked atomic.Bool
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(r.Header.Get("Authorization") != "")
		fmt.Fprint(w, "ok")
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/blob?signature=secret", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c, err := newRegistryClient(registryReference{host: strings.TrimPrefix(source.URL, "https://")}, Options{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.http.HTTP.Transport = source.Client().Transport
	defer c.http.HTTP.CloseIdleConnections()
	resp, err := c.request(context.Background(), source.URL, "application/octet-stream", "Bearer secret")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if leaked.Load() {
		t.Fatal("authorization leaked across origins")
	}
}

func TestRegistryCredentialsDockerHubAndPrecedence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BSCAN_REGISTRY_USER", "")
	t.Setenv("BSCAN_REGISTRY_PASSWORD", "")
	dir := filepath.Join(os.Getenv("HOME"), ".docker")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	data := mustJSON(t, map[string]any{"auths": map[string]any{"https://index.docker.io/v1/": map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte("hub-user:hub-password"))}}})
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	u, p, err := registryCredentials("registry-1.docker.io")
	if err != nil || u != "hub-user" || p != "hub-password" {
		t.Fatal("Docker Hub credentials not resolved")
	}
	u, p, err = registryCredentials("ghcr.io")
	if err != nil || u != "" || p != "" {
		t.Fatal("credentials used for wrong host")
	}
	t.Setenv("BSCAN_REGISTRY_USER", "env-user")
	t.Setenv("BSCAN_REGISTRY_PASSWORD", "env-password")
	u, p, err = registryCredentials("registry-1.docker.io")
	if err != nil || u != "env-user" || p != "env-password" {
		t.Fatal("environment credentials did not take precedence")
	}
}

func (f *registryFixture) tlsClient(t *testing.T) *registryClient {
	t.Helper()
	server := httptest.NewTLSServer(f.server.Config.Handler)
	t.Cleanup(server.Close)
	layout := t.TempDir()
	if err := os.MkdirAll(filepath.Join(layout, "blobs", "sha256"), 0700); err != nil {
		t.Fatal(err)
	}
	c, err := newRegistryClient(registryReference{host: strings.TrimPrefix(server.URL, "https://"), repository: "org/image"}, Options{}, layout)
	if err != nil {
		t.Fatal(err)
	}
	c.http.HTTP.Transport = server.Client().Transport
	t.Cleanup(c.http.HTTP.CloseIdleConnections)
	return c
}
