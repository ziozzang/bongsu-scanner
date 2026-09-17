package scan

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

const maxRegistryManifests = 256

const registryAccept = mediaTypeOCIIndex + ", " + mediaTypeOCIManifest + ", " + mediaTypeDockerList + ", " + mediaTypeDockerManifest

var (
	registryRepository = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	registryTag        = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$`)
	registryHost       = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?(?::[0-9]+)?$`)
)

type registryReference struct {
	host, repository, reference, name string
	digest                            bool
}

func validRegistryDigest(d string) bool {
	if len(d) != 71 || !strings.HasPrefix(d, "sha256:") || strings.ToLower(d) != d {
		return false
	}
	_, err := hex.DecodeString(d[7:])
	return err == nil
}

func parseRegistryReference(target string) (registryReference, error) {
	ref := strings.TrimPrefix(strings.TrimPrefix(target, "registry://"), "oci://")
	bad := errors.New("invalid registry reference (expected host/repository[:tag|@sha256:digest])")
	if strings.ContainsAny(ref, "?#%\\ \t\r\n") || ref == "" {
		return registryReference{}, bad
	}
	r := registryReference{reference: "latest"}
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		r.reference, ref, r.digest = ref[i+1:], ref[:i], true
		if !validRegistryDigest(r.reference) {
			return registryReference{}, bad
		}
	}
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		tag := ref[i+1:]
		if !registryTag.MatchString(tag) {
			return registryReference{}, bad
		}
		if !r.digest {
			r.reference = tag
		}
		ref = ref[:i]
	}
	first, rest, hasSlash := strings.Cut(ref, "/")
	r.host, r.repository = "docker.io", ref
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.host, r.repository = strings.ToLower(first), rest
	}
	if r.host == "docker.io" || r.host == "index.docker.io" || r.host == "registry-1.docker.io" {
		r.host = "registry-1.docker.io"
		if !strings.Contains(r.repository, "/") {
			r.repository = "library/" + r.repository
		}
	}
	if !registryHost.MatchString(r.host) || !registryRepository.MatchString(r.repository) || len(r.repository) > 255 {
		return registryReference{}, bad
	}
	nameHost := r.host
	if nameHost == "registry-1.docker.io" {
		nameHost = "docker.io"
	}
	r.name = nameHost + "/" + r.repository
	if r.digest {
		r.name += "@" + r.reference
	} else {
		r.name += ":" + r.reference
	}
	return r, nil
}

// ValidateRegistryReference validates registry targets without echoing their contents.
// Other target types are left to their respective scanners.
func ValidateRegistryReference(target string) error {
	if !strings.HasPrefix(target, "registry://") && !strings.HasPrefix(target, "oci://") {
		return nil
	}
	_, err := parseRegistryReference(target)
	return err
}

// RegistryReferenceForLog removes credentials and queries even from rejected references.
func RegistryReferenceForLog(target string) string {
	if !strings.HasPrefix(target, "registry://") && !strings.HasPrefix(target, "oci://") {
		return target
	}
	// Preserve valid shorthand digest references: their '@' is not userinfo.
	if _, err := parseRegistryReference(target); err == nil {
		return target
	}
	scheme, ref, _ := strings.Cut(target, "://")
	ref, _, _ = strings.Cut(ref, "?")
	ref, _, _ = strings.Cut(ref, "#")
	authority, path, slash := strings.Cut(ref, "/")
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		authority = authority[i+1:]
	}
	ref = authority
	if slash {
		ref += "/" + path
	}
	safe := scheme + "://" + ref
	if _, err := parseRegistryReference(safe); err != nil {
		return scheme + "://<invalid>"
	}
	return safe
}

type registryClient struct {
	http                          *httpx.Client
	ref                           registryReference
	base, user, password          string
	authorization                 string
	insecure                      bool
	remaining, maxBlob            int64
	layout                        string
	downloaded                    map[string]int64
	manifests                     map[string]ociDescriptor
	manifestRequests, descriptors int
}

func newRegistryClient(ref registryReference, opts Options, layout string) (*registryClient, error) {
	c := &registryClient{http: httpx.New(5 * time.Minute), ref: ref, insecure: opts.InsecureRegistry,
		remaining: opts.MaxRegistryBytes, maxBlob: opts.MaxRegistryBlobBytes, layout: layout, downloaded: make(map[string]int64), manifests: make(map[string]ociDescriptor)}
	if c.remaining < 0 || c.maxBlob < 0 {
		return nil, errors.New("registry download limits must not be negative")
	}
	if c.remaining == 0 {
		c.remaining = 8 << 30
	}
	if c.maxBlob == 0 {
		c.maxBlob = 8 << 30
	}
	c.base = "https://" + ref.host
	u, _ := url.Parse(c.base)
	if c.insecure && registryLocalhost(u) {
		c.base = "http://" + ref.host
	}
	// Keep httpx's transport (timeouts, TLS, environment proxies). Registry
	// challenges require access to raw response headers, unlike GetJSON.
	c.http.HTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > httpx.MaxRedirects {
			return httpx.ErrTooManyRedirects
		}
		if req.URL.Scheme != "https" {
			return httpx.ErrInsecureURL
		}
		if err := c.checkURL(req.URL); err != nil {
			return err
		}
		if len(via) > 0 && (req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme) {
			req.Header.Del("Authorization")
		}
		return nil
	}
	var err error
	c.user, c.password, err = registryCredentials(ref.host)
	return c, err
}

func registryLocalhost(u *url.URL) bool {
	return u != nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")
}

func (c *registryClient) checkURL(u *url.URL) error {
	if u == nil || u.User != nil || u.Fragment != "" {
		return httpx.ErrInsecureURL
	}
	if c.insecure && u.Scheme == "http" && registryLocalhost(u) {
		return nil
	}
	return c.http.CheckURL(u.String())
}

func registryCredentials(host string) (string, string, error) {
	user, password := os.Getenv("BSCAN_REGISTRY_USER"), os.Getenv("BSCAN_REGISTRY_PASSWORD")
	if user != "" || password != "" {
		return user, password, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", nil
	}
	f, err := os.Open(filepath.Join(home, ".docker", "config.json")) // #nosec G304 -- Uses the local Docker config or private, internally constructed OCI staging paths.
	if os.IsNotExist(err) {
		return "", "", nil
	}
	if err != nil {
		return "", "", errors.New("cannot read Docker registry credentials")
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&cfg); err != nil {
		return "", "", errors.New("invalid Docker registry credentials file")
	}
	keys := []string{host, "https://" + host, "https://" + host + "/v1/"}
	if host == "registry-1.docker.io" {
		keys = append(keys, "docker.io", "index.docker.io", "https://index.docker.io/v1/", "https://docker.io/v1/")
	}
	for _, key := range keys {
		if auth := cfg.Auths[key].Auth; auth != "" {
			raw, err := base64.StdEncoding.DecodeString(auth)
			user, password, ok := strings.Cut(string(raw), ":")
			if err != nil || !ok {
				return "", "", errors.New("invalid Docker registry auth entry")
			}
			return user, password, nil
		}
	}
	return "", "", nil
}

// request retries transient HTTP statuses three times. Error bodies and URL
// queries are deliberately omitted: token services may echo credentials.
func (c *registryClient) request(ctx context.Context, rawURL, accept, authorization string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("invalid registry request URL")
	}
	if err := c.checkURL(u); err != nil {
		return nil, err
	}
	if authorization != "" && u.Scheme != "https" {
		return nil, errors.New("registry credentials require HTTPS; HTTP loopback allows anonymous access only")
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, errors.New("invalid registry request")
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("User-Agent", c.http.UserAgent)
		req.Header.Set("Accept-Encoding", "identity")
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := c.http.HTTP.Do(req)
		if err != nil {
			return nil, registryNetworkError(ctx, err, "registry HTTP request failed (connection, timeout, or URL policy)")
		}
		if attempt >= 3 || (resp.StatusCode != 429 && (resp.StatusCode < 500 || resp.StatusCode > 599)) {
			return resp, nil
		}
		delay := registryRetryDelay(resp.Header.Get("Retry-After"), attempt, time.Now())
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = resp.Body.Close()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// Never retain an untrusted transport error, including in an unwrap chain.
func registryNetworkError(ctx context.Context, err error, message string) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s: %w", message, ctx.Err())
	}
	for _, kind := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, kind) {
			return fmt.Errorf("%s: %w", message, kind)
		}
	}
	return errors.New(message)
}

func registryRetryDelay(value string, attempt int, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value != "" && strings.Trim(value, "0123456789") == "" {
		seconds, err := strconv.ParseUint(value, 10, 64)
		if err != nil || seconds > 60 {
			return 60 * time.Second
		}
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		return min(max(date.Sub(now), 0), 60*time.Second)
	}
	base := (200 * time.Millisecond) << min(attempt, 8)
	return base/2 + time.Duration(rand.Int64N(int64(base/2)+1)) // #nosec G404 -- Randomness only jitters retry delays; it is not used for keys, tokens, or security decisions.
}

// Split challenge lists only at unquoted commas (RFC 9110 section 11.3).
// A token followed by '=' continues auth-params; any other token starts a challenge.
func registryChallenge(h http.Header) (string, map[string]string, error) {
	type challenge struct{ scheme, params string }
	var challenges []challenge
	for _, value := range h.Values("WWW-Authenticate") {
		start, quoted, escaped := 0, false, false
		var parts []string
		for i := 0; i < len(value); i++ {
			ch := value[i]
			if escaped {
				escaped = false
			} else if quoted && ch == '\\' {
				escaped = true
			} else if ch == '"' {
				quoted = !quoted
			} else if ch == ',' && !quoted {
				parts = append(parts, value[start:i])
				start = i + 1
			}
		}
		if quoted || escaped {
			continue
		}
		parts = append(parts, value[start:])
		current := -1
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			token, rest := registryAuthToken(part)
			if token == "" {
				current = -1
				continue
			}
			rest = strings.TrimLeft(rest, " \t")
			if strings.HasPrefix(rest, "=") {
				if current >= 0 {
					challenges[current].params += "," + part
				}
				continue
			}
			challenges = append(challenges, challenge{strings.ToLower(token), rest})
			current = len(challenges) - 1
		}
	}
	// Prefer Bearer if both are offered, avoiding an unnecessary Basic exchange.
	for _, kind := range []string{"bearer", "basic"} {
		for _, ch := range challenges {
			if ch.scheme != kind {
				continue
			}
			if params, ok := registryAuthParams(ch.params); ok {
				return kind, params, nil
			}
		}
	}
	return "", nil, errors.New("registry returned no supported authentication challenge")
}

func registryAuthToken(s string) (string, string) {
	i := 0
	for i < len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			break
		}
		i++
	}
	return s[:i], s[i:]
}

func registryAuthParams(s string) (map[string]string, bool) {
	params := make(map[string]string)
	for s = strings.TrimSpace(s); s != ""; {
		key, rest := registryAuthToken(s)
		rest = strings.TrimLeft(rest, " \t")
		if key == "" || !strings.HasPrefix(rest, "=") {
			return nil, false
		}
		s = strings.TrimLeft(rest[1:], " \t")
		var value string
		if strings.HasPrefix(s, "\"") {
			var b strings.Builder
			s = s[1:]
			closed := false
			for len(s) > 0 {
				c := s[0]
				s = s[1:]
				if c == '"' {
					closed = true
					break
				}
				if c == '\\' {
					if s == "" {
						return nil, false
					}
					c = s[0]
					s = s[1:]
				}
				if c < 0x20 && c != '\t' || c == 0x7f {
					return nil, false
				}
				b.WriteByte(c)
			}
			if !closed {
				return nil, false
			}
			value = b.String()
		} else {
			value, s = registryAuthToken(s)
			if value == "" {
				return nil, false
			}
		}
		key = strings.ToLower(key)
		if _, exists := params[key]; exists {
			return nil, false
		}
		params[key] = value
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			break
		}
		if s[0] != ',' {
			return nil, false
		}
		s = strings.TrimSpace(s[1:])
	}
	return params, true
}

func (c *registryClient) authenticate(ctx context.Context, h http.Header) error {
	kind, params, err := registryChallenge(h)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(c.base, "https://") {
		return errors.New("registry authentication requires HTTPS; HTTP loopback allows anonymous access only")
	}
	basic := ""
	if c.user != "" || c.password != "" {
		basic = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.user+":"+c.password))
	}
	if kind == "basic" {
		if basic == "" {
			return errors.New("registry requires credentials")
		}
		c.authorization = basic
		return nil
	}
	u, err := url.Parse(params["realm"])
	if err != nil || u == nil {
		return errors.New("invalid registry token realm")
	}
	if u.Scheme != "https" {
		return errors.New("registry token realm requires HTTPS")
	}
	if err := c.checkURL(u); err != nil {
		return err
	}
	q := u.Query()
	if service := params["service"]; service != "" {
		q.Set("service", service)
	}
	q.Set("scope", "repository:"+c.ref.repository+":pull")
	u.RawQuery = q.Encode()
	resp, err := c.request(ctx, u.String(), "application/json", basic)
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry token request: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return registryNetworkError(ctx, err, "cannot read registry token response")
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if len(raw) > 1<<20 || json.Unmarshal(raw, &token) != nil {
		return errors.New("invalid registry token response")
	}
	if token.Token == "" {
		token.Token = token.AccessToken
	}
	if token.Token == "" || strings.ContainsAny(token.Token, "\r\n") {
		return errors.New("registry returned an empty or invalid token")
	}
	c.authorization = "Bearer " + token.Token
	return nil
}

func (c *registryClient) get(ctx context.Context, resource, accept string) (*http.Response, error) {
	rawURL := c.base + "/v2/" + c.ref.repository + "/" + resource
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := c.request(ctx, rawURL, accept, c.authorization)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || attempt > 0 {
			return nil, fmt.Errorf("registry request: HTTP %d", resp.StatusCode)
		}
		// Only the registry itself may challenge us, never a redirected CDN.
		if resp.Request.URL.Host != c.ref.host {
			return nil, errors.New("registry redirect returned an authentication challenge")
		}
		if err := c.authenticate(ctx, resp.Header); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("registry authentication failed")
}

func (c *registryClient) manifest(ctx context.Context, ref string, expected *ociDescriptor) (ociDescriptor, []byte, error) {
	if expected != nil && !isIndexType(expected.MediaType) && !isManifestType(expected.MediaType) {
		return ociDescriptor{}, nil, errors.New("unsupported registry manifest descriptor media type")
	}
	if d, ok := c.manifests[ref]; ok {
		if expected != nil && (expected.Digest != d.Digest || expected.Size != d.Size || expected.MediaType != d.MediaType) {
			return d, nil, errors.New("registry cached manifest descriptor mismatch")
		}
		raw, err := os.ReadFile(filepath.Join(c.layout, digestPath(d.Digest)))
		return d, raw, err
	}
	if c.manifestRequests >= maxRegistryManifests {
		return ociDescriptor{}, nil, errors.New("registry manifest request budget exceeded")
	}
	c.manifestRequests++
	limit := min(int64(maxMetadata), c.maxBlob, c.remaining)
	if expected != nil && (!validRegistryDigest(expected.Digest) || expected.Size < 0 || expected.Size > limit) {
		return ociDescriptor{}, nil, errors.New("invalid or oversized registry manifest descriptor")
	}
	resp, err := c.get(ctx, "manifests/"+ref, registryAccept)
	if err != nil {
		return ociDescriptor{}, nil, err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = resp.Body.Close()
	}()
	contentType, _, typeErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if typeErr != nil || (!isIndexType(contentType) && !isManifestType(contentType)) {
		return ociDescriptor{}, nil, errors.New("unsupported registry manifest Content-Type")
	}
	if resp.ContentLength > limit {
		return ociDescriptor{}, nil, httpx.ErrTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return ociDescriptor{}, nil, registryNetworkError(ctx, err, "cannot read registry manifest response")
	}
	if int64(len(raw)) > limit {
		return ociDescriptor{}, nil, httpx.ErrTooLarge
	}
	c.remaining -= int64(len(raw))
	sum := sha256.Sum256(raw)
	d := ociDescriptor{Digest: fmt.Sprintf("sha256:%x", sum), Size: int64(len(raw))}
	if expected != nil && (d.Digest != expected.Digest || d.Size != expected.Size) {
		return d, nil, errors.New("registry manifest digest or size mismatch")
	}
	if strings.HasPrefix(ref, "sha256:") && d.Digest != ref {
		return d, nil, errors.New("registry manifest digest mismatch")
	}
	if header := resp.Header.Get("Docker-Content-Digest"); header != "" && header != d.Digest {
		return d, nil, errors.New("registry manifest digest header mismatch")
	}
	var probe struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
	}
	if json.Unmarshal(raw, &probe) != nil || probe.SchemaVersion != 2 {
		return d, nil, errors.New("invalid registry manifest (expected schema version 2)")
	}
	d.MediaType = probe.MediaType
	if d.MediaType == "" {
		d.MediaType = contentType
	}
	if !isIndexType(d.MediaType) && !isManifestType(d.MediaType) {
		return d, nil, errors.New("unsupported registry manifest media type")
	}
	if d.MediaType != contentType || expected != nil && expected.MediaType != d.MediaType {
		return d, nil, errors.New("registry manifest media type mismatch")
	}
	if err := os.WriteFile(filepath.Join(c.layout, digestPath(d.Digest)), raw, 0600); err != nil {
		return d, nil, err
	}
	c.downloaded[d.Digest] = d.Size
	c.manifests[d.Digest] = d
	return d, raw, nil
}

func (c *registryClient) blob(ctx context.Context, d ociDescriptor, metadata bool) error {
	if !validRegistryDigest(d.Digest) || d.Size < 0 {
		return errors.New("invalid registry blob descriptor")
	}
	limit := c.maxBlob
	if metadata {
		limit = min(limit, int64(maxMetadata))
	}
	if d.Size > limit {
		return errors.New("registry blob exceeds size limit")
	}
	if size, ok := c.downloaded[d.Digest]; ok {
		if size != d.Size {
			return errors.New("registry blob size mismatch")
		}
		return nil
	}
	if d.Size > c.remaining {
		return errors.New("registry total download limit exceeded")
	}
	resp, err := c.get(ctx, "blobs/"+d.Digest, "application/octet-stream")
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = resp.Body.Close()
	}()
	if resp.ContentLength >= 0 && resp.ContentLength != d.Size {
		return errors.New("registry blob size mismatch")
	}
	f, err := os.OpenFile(filepath.Join(c.layout, digestPath(d.Digest)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	// Read at most the declared size, then probe one byte without writing it.
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, d.Size))
	closeErr := f.Close()
	c.remaining -= n
	if copyErr != nil {
		return registryNetworkError(ctx, copyErr, "cannot read registry blob response")
	}
	if closeErr != nil {
		return closeErr
	}
	var extra [1]byte
	more, readErr := io.ReadFull(resp.Body, extra[:])
	if readErr != nil && readErr != io.EOF {
		return registryNetworkError(ctx, readErr, "cannot read registry blob response")
	}
	if n != d.Size || more != 0 {
		return errors.New("registry blob size mismatch")
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.Digest {
		return errors.New("registry blob digest mismatch")
	}
	c.downloaded[d.Digest] = n
	return nil
}

var errRegistryPlatform = errors.New("no registry image manifest for requested platform")

func (c *registryClient) selectManifest(ctx context.Context, ref string, expected *ociDescriptor, want platformSpec, depth int) (ociDescriptor, ociManifest, error) {
	if depth > 4 {
		return ociDescriptor{}, ociManifest{}, errors.New("registry index nesting too deep")
	}
	d, raw, err := c.manifest(ctx, ref, expected)
	if err != nil {
		return d, ociManifest{}, err
	}
	if isIndexType(d.MediaType) {
		var index ociIndex
		if json.Unmarshal(raw, &index) != nil || len(index.Manifests) > maxIndexManifests {
			return d, ociManifest{}, errors.New("invalid or oversized registry index")
		}
		if len(index.Manifests) > maxRegistryManifests-c.descriptors {
			return d, ociManifest{}, errors.New("registry manifest descriptor budget exceeded")
		}
		c.descriptors += len(index.Manifests)
		for _, child := range index.Manifests {
			if !isIndexType(child.MediaType) && !isManifestType(child.MediaType) {
				return d, ociManifest{}, errors.New("unsupported registry index descriptor media type")
			}
		}
		// Prefer an advertised match, then inspect descriptors without platform.
		for _, exact := range []bool{true, false} {
			for _, child := range index.Manifests {
				if isAttestation(child) || (exact && !want.matches(child.Platform)) || (!exact && child.Platform != nil) {
					continue
				}
				selected, m, err := c.selectManifest(ctx, child.Digest, &child, want, depth+1)
				if errors.Is(err, errRegistryPlatform) {
					continue
				}
				return selected, m, err
			}
		}
		return d, ociManifest{}, fmt.Errorf("%w: %s", errRegistryPlatform, want)
	}
	var m ociManifest
	if json.Unmarshal(raw, &m) != nil || len(m.Layers) > maxImageLayers {
		return d, m, errors.New("invalid or oversized registry image manifest")
	}
	if m.Config.MediaType != "application/vnd.oci.image.config.v1+json" && m.Config.MediaType != "application/vnd.docker.container.image.v1+json" {
		return d, m, errors.New("unsupported registry image config media type")
	}
	for _, layer := range m.Layers {
		switch layer.MediaType {
		case mediaTypeOCILayer, mediaTypeOCILayerGzip, mediaTypeOCILayerZstd,
			"application/vnd.oci.image.layer.nondistributable.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
			"application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
		default:
			return d, m, errors.New("unsupported registry layer media type")
		}
	}
	if err := c.blob(ctx, m.Config, true); err != nil {
		return d, m, err
	}
	cfgRaw, err := os.ReadFile(filepath.Join(c.layout, digestPath(m.Config.Digest)))
	if err != nil {
		return d, m, err
	}
	var cfg imageConfig
	if json.Unmarshal(cfgRaw, &cfg) != nil {
		return d, m, errors.New("invalid registry image config")
	}
	d.Platform = &ociPlatform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}
	// Some ARM configs omit the variant advertised by their descriptor.
	if d.Platform.Variant == "" && expected != nil && expected.Platform != nil {
		d.Platform.Variant = expected.Platform.Variant
	}
	if !want.matches(d.Platform) {
		return d, m, fmt.Errorf("%w: %s", errRegistryPlatform, want)
	}
	return d, m, nil
}

func registryImage(ctx context.Context, target string, opts Options) (Result, error) {
	if opts.Offline {
		return Result{}, errors.New("registry scan disabled: offline mode; use a local directory/archive or docker:// image")
	}
	ref, err := parseRegistryReference(target)
	if err != nil {
		return Result{}, err
	}
	want, err := parsePlatform(opts.Platform)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	tmp, err := os.MkdirTemp("", "bongsu-registry-*")
	if err != nil {
		return Result{}, err
	}
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.RemoveAll(tmp)
	}()
	layout := filepath.Join(tmp, "layout")
	if err := os.MkdirAll(filepath.Join(layout, "blobs", "sha256"), 0700); err != nil {
		return Result{}, err
	}
	c, err := newRegistryClient(ref, opts, layout)
	if err != nil {
		return Result{}, err
	}
	defer c.http.HTTP.CloseIdleConnections()
	report(opts, "registry", "fetching "+ref.name+" ("+want.String()+")", false)
	d, manifest, err := c.selectManifest(ctx, ref.reference, nil, want, 0)
	if err != nil {
		return Result{}, err
	}
	for _, layer := range manifest.Layers {
		if err := c.blob(ctx, layer, false); err != nil {
			return Result{}, err
		}
	}
	if !ref.digest {
		d.Annotations = map[string]string{"org.opencontainers.image.ref.name": ref.name}
	}
	index, err := json.Marshal(struct {
		SchemaVersion int             `json:"schemaVersion"`
		MediaType     string          `json:"mediaType"`
		Manifests     []ociDescriptor `json:"manifests"`
	}{2, mediaTypeOCIIndex, []ociDescriptor{d}})
	if err != nil {
		return Result{}, err
	}
	for name, data := range map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": index} {
		if err := os.WriteFile(filepath.Join(layout, name), data, 0600); err != nil {
			return Result{}, err
		}
	}
	archive := filepath.Join(tmp, "image.tar")
	if err := registryLayoutTar(ctx, layout, archive); err != nil {
		return Result{}, err
	}
	// The tar is an implementation detail, just like docker image save output.
	opts.skipSourceHash = true
	result, err := archiveContext(ctx, archive, opts)
	if err != nil {
		return Result{}, err
	}
	result.Name, result.Source, result.SourceType = ref.name, "registry://"+ref.name, "registry-image"
	return result, nil
}

func registryLayoutTar(ctx context.Context, layout, archive string) error {
	f, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- Uses the local Docker config or private, internally constructed OCI staging paths.
	if err != nil {
		return err
	}
	tw := tar.NewWriter(f)
	walkErr := filepath.WalkDir(layout, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(layout, name)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(rel), Mode: 0600, Size: info.Size()}); err != nil {
			return err
		}
		src, err := os.Open(name) // #nosec G122 G304 -- Layout is generated internally in a private 0700 temporary directory, inaccessible to other users. Uses the local Docker config or private, internally constructed OCI staging paths.
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, contextReader{ctx, src})
		return errors.Join(copyErr, src.Close())
	})
	return errors.Join(walkErr, tw.Close(), f.Close())
}
