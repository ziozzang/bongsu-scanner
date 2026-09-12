// Package selfupdate downloads a GitHub release binary, verifies it against a
// (optionally signed) SHA256SUMS file, and atomically replaces the running
// executable.
//
// Trust model:
//   - Every request goes through internal/httpx: https only, host allow-list,
//     bounded bodies, sanitized error strings.
//   - SHA256SUMS provides transfer integrity for the binary.
//   - SHA256SUMS.sig (an internal/sign detached record) provides authenticity
//     when a trusted release key is available; verification is pinned to that
//     key, never to the key embedded in the record.
package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

const (
	// APIBase is the default GitHub REST endpoint.
	APIBase = "https://api.github.com"

	// ReleasePublicKey is the project release signing key (PKIX PEM or 32-byte
	// hex, as accepted by sign.ParsePublic). It is consulted only when the
	// user has not pinned a trusted key named "release" in their config.
	// Empty means "no built-in key": signatures are then not verified unless
	// the user pins one.
	ReleasePublicKey = ""

	// DefaultMaxAssetBytes caps a release binary download when the release
	// metadata does not carry a size. Real bscan binaries are ~10 MiB.
	DefaultMaxAssetBytes int64 = 256 << 20
	// MaxChecksumsBytes caps the SHA256SUMS download.
	MaxChecksumsBytes int64 = 1 << 20
	// MaxSignatureBytes caps the SHA256SUMS.sig download.
	MaxSignatureBytes int64 = 64 << 10

	checksumsAsset = "SHA256SUMS"
	signatureAsset = "SHA256SUMS.sig"
)

// AllowedHosts is the host allow-list applied to release metadata and asset
// downloads (suffix match, see httpx.Client.AllowedHosts).
var AllowedHosts = []string{"github.com", "githubusercontent.com", "objects.githubusercontent.com", "api.github.com"}

var (
	ErrSignatureRequired = errors.New("selfupdate: release signature required but not verifiable")
	ErrSignatureInvalid  = errors.New("selfupdate: SHA256SUMS signature verification failed")
	ErrChecksumMismatch  = errors.New("selfupdate: checksum mismatch")
)

var (
	versionRe = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	repoRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

type Release struct {
	TagName string  `json:"tag_name"`
	Body    string  `json:"body"`
	Assets  []Asset `json:"assets"`
}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Version returns the tag without a leading "v".
func (r Release) Version() string { return strings.TrimPrefix(r.TagName, "v") }

func (r Release) Find(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// Checksums is the parsed, policy-checked SHA256SUMS of a release.
type Checksums struct {
	// Entries maps asset file name to lower-case hex SHA-256.
	Entries map[string]string
	// Verified is true when SHA256SUMS.sig validated against the pinned key.
	Verified bool
	// Authenticated reports whether the verified record also signs its metadata,
	// including Signer. Version 1 only authenticates the checksum digest and time.
	Authenticated bool
	// Signer is the signer label from the signature record (sanitized).
	Signer string
}

// Updater performs release lookups and downloads with a fixed policy.
type Updater struct {
	Client  *httpx.Client
	APIBase string // defaults to APIBase
	Repo    string // "owner/repository"
	// Token is sent only to the API endpoint (never to asset hosts).
	Token string
	// ReleaseKey is the pinned key used to verify the required SHA256SUMS.sig.
	// nil disables verification unless RequireSignature is set (otherwise Warn
	// receives a warning).
	ReleaseKey ed25519.PublicKey
	// RequireSignature makes a missing key or signature fatal.
	RequireSignature bool
	// SignatureMinVersion rejects older signature records; zero defaults to 1.
	SignatureMinVersion int
	// Warn receives non-fatal warnings; defaults to os.Stderr.
	Warn io.Writer
}

// NewClient returns an httpx client restricted to GitHub hosts.
func NewClient(timeout time.Duration) *httpx.Client {
	c := httpx.New(timeout)
	c.AllowedHosts = append([]string(nil), AllowedHosts...)
	return c
}

func (u *Updater) warnf(format string, args ...any) {
	w := u.Warn
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, format, args...)
}

func (u *Updater) client() (*httpx.Client, error) {
	if u.Client == nil {
		return nil, errors.New("selfupdate: no HTTP client configured")
	}
	return u.Client, nil
}

// Latest fetches the latest release. The tag must look like a version.
func (u *Updater) Latest(ctx context.Context) (*Release, error) {
	c, err := u.client()
	if err != nil {
		return nil, err
	}
	if !repoRe.MatchString(u.Repo) {
		return nil, fmt.Errorf("selfupdate: invalid repository %q", httpx.Sanitize(u.Repo))
	}
	base := u.APIBase
	if base == "" {
		base = APIBase
	}
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if u.Token != "" {
		headers["Authorization"] = "Bearer " + u.Token
	}
	var rel Release
	if err := c.GetJSON(ctx, strings.TrimSuffix(base, "/")+"/repos/"+u.Repo+"/releases/latest", headers, &rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("selfupdate: release has no tag")
	}
	if !IsVersion(rel.TagName) {
		return nil, fmt.Errorf("selfupdate: release tag %q is not a version", httpx.Sanitize(rel.TagName))
	}
	return &rel, nil
}

// Checksums downloads SHA256SUMS and, when a release key is pinned, verifies
// SHA256SUMS.sig against it. A pinned key always requires a signature. A missing
// key is a warning unless RequireSignature is set; an invalid signature is fatal.
func (u *Updater) Checksums(ctx context.Context, rel *Release) (*Checksums, error) {
	c, err := u.client()
	if err != nil {
		return nil, err
	}
	sumsAsset, ok := rel.Find(checksumsAsset)
	if !ok {
		return nil, errors.New("selfupdate: release has no SHA256SUMS")
	}
	raw, err := downloadBytes(ctx, c, sumsAsset, MaxChecksumsBytes)
	if err != nil {
		return nil, fmt.Errorf("download SHA256SUMS: %w", err)
	}
	out := &Checksums{Entries: parseChecksums(raw)}
	if len(out.Entries) == 0 {
		return nil, errors.New("selfupdate: SHA256SUMS has no entries")
	}

	sigAsset, hasSig := rel.Find(signatureAsset)
	switch {
	case u.ReleaseKey == nil:
		if u.RequireSignature {
			return nil, fmt.Errorf("%w: no trusted 'release' key", ErrSignatureRequired)
		}
		u.warnf("[update] warning: release signature not verified (no trusted 'release' key)\n")
		return out, nil
	case !hasSig:
		return nil, fmt.Errorf("%w: a release key is pinned but release has no %s", ErrSignatureRequired, signatureAsset)
	}
	sigRaw, err := downloadBytes(ctx, c, sigAsset, MaxSignatureBytes)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", signatureAsset, err)
	}
	rec, err := VerifyChecksums(raw, sigRaw, u.ReleaseKey)
	if err != nil {
		return nil, err
	}
	if rec.Version < u.SignatureMinVersion {
		return nil, fmt.Errorf("%w: signature version %d is below signature_min_version %d", ErrSignatureInvalid, rec.Version, u.SignatureMinVersion)
	}
	out.Verified = true
	out.Authenticated = rec.Authenticated()
	out.Signer = httpx.Sanitize(rec.Signer)
	return out, nil
}

// VerifyChecksums checks that sigRaw is a valid sign.Record for sums, signed
// by the pinned key pub. It never trusts the key embedded in the record.
func VerifyChecksums(sums, sigRaw []byte, pub ed25519.PublicKey) (sign.Record, error) {
	var rec sign.Record
	if pub == nil {
		return rec, fmt.Errorf("%w: no pinned key", ErrSignatureInvalid)
	}
	if err := json.Unmarshal(sigRaw, &rec); err != nil {
		return rec, fmt.Errorf("%w: malformed record: %v", ErrSignatureInvalid, err)
	}
	if err := rec.Verify(pub); err != nil {
		return rec, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	digest := sha256.Sum256(sums)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), rec.DigestSHA256) {
		return rec, fmt.Errorf("%w: signed digest does not match SHA256SUMS", ErrSignatureInvalid)
	}
	return rec, nil
}

func parseChecksums(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || len(f[0]) != sha256.Size*2 {
			continue
		}
		if _, err := hex.DecodeString(f[0]); err != nil {
			continue
		}
		name := strings.TrimPrefix(f[1], "*")
		if name == "" || name != filepath.Base(name) {
			continue
		}
		out[name] = strings.ToLower(f[0])
	}
	return out
}

func downloadBytes(ctx context.Context, c *httpx.Client, asset Asset, max int64) ([]byte, error) {
	if asset.Size > max {
		return nil, fmt.Errorf("%w: %s is %d bytes", httpx.ErrTooLarge, asset.Name, asset.Size)
	}
	var buf strings.Builder
	if _, _, _, err := c.Download(ctx, asset.URL, nil, &buf, max); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// AssetName returns the release asset name for this platform.
func AssetName(ver string) (string, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return "", fmt.Errorf("no release build for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	arch := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]
	return fmt.Sprintf("bscan_%s_linux_%s", ver, arch), nil
}

// Download fetches asset into a temporary file in dir (which must be on the
// same filesystem as the executable to be replaced), enforcing the size cap
// and the expected SHA-256. On any failure the temporary file is removed.
func (u *Updater) Download(ctx context.Context, asset Asset, wantSHA256, dir string) (string, error) {
	c, err := u.client()
	if err != nil {
		return "", err
	}
	if len(wantSHA256) != sha256.Size*2 {
		return "", fmt.Errorf("selfupdate: invalid expected checksum for %s", httpx.Sanitize(asset.Name))
	}
	limit := DefaultMaxAssetBytes
	if asset.Size > 0 {
		if asset.Size > DefaultMaxAssetBytes {
			return "", fmt.Errorf("%w: %s is %d bytes", httpx.ErrTooLarge, httpx.Sanitize(asset.Name), asset.Size)
		}
		limit = asset.Size
	}
	f, err := os.CreateTemp(dir, ".bscan-update-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	h := sha256.New()
	n, _, _, err := c.Download(ctx, asset.URL, nil, io.MultiWriter(f, h), limit)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", httpx.Sanitize(asset.Name), err)
	}
	if asset.Size > 0 && n != asset.Size {
		return "", fmt.Errorf("selfupdate: %s: got %d bytes, release metadata says %d", httpx.Sanitize(asset.Name), n, asset.Size)
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, wantSHA256) {
		return "", fmt.Errorf("%w for %s", ErrChecksumMismatch, httpx.Sanitize(asset.Name))
	}
	ok = true
	return tmp, nil
}

// Executable returns the real path (symlinks resolved) of the running binary.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// Replace atomically renames src over exe (symlinks in exe are resolved so the
// real file is replaced and the link is left intact), preserving the original
// file mode. src must live on the same filesystem as the resolved target;
// Download with dir = filepath.Dir(Executable()) guarantees that.
func Replace(src, exe string) (string, error) {
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("selfupdate: %s is not a regular file", real)
	}
	if err := os.Chmod(src, info.Mode().Perm()); err != nil {
		return "", err
	}
	if err := os.Rename(src, real); err != nil {
		return "", err
	}
	if d, err := os.Open(filepath.Dir(real)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return real, nil
}

// IsVersion reports whether v is exactly a release version (^v?\d+(\.\d+)*
// with an optional pre-release / build suffix; no surrounding whitespace).
func IsVersion(v string) bool { return versionRe.MatchString(v) }

// IsDevBuild reports whether v denotes an unversioned development build
// ("dev", empty, unparsable, or a pre-release containing "dev").
func IsDevBuild(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || v == "dev" || !IsVersion(v) {
		return true
	}
	return strings.Contains(prerelease(v), "dev")
}

// Compare orders two version strings: numeric fields first, then a
// pre-release ("1.2.3-rc1") sorts below the release ("1.2.3"). Build metadata
// after "+" is ignored. It never panics on malformed input.
func Compare(a, b string) int {
	av, bv := fields(a), fields(b)
	for i := 0; i < len(av) || i < len(bv); i++ {
		var x, y int
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	ap, ah := prerelease(a), hasPrerelease(a)
	bp, bh := prerelease(b), hasPrerelease(b)
	switch {
	case ah && !bh:
		return -1
	case !ah && bh:
		return 1
	case !ah && !bh:
		return 0
	}
	return comparePrerelease(ap, bp)
}

func core(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	return v
}

// fields returns the numeric dotted fields of v; unparsable fields are 0 and
// an empty core yields []int{0}.
func fields(v string) []int {
	c := core(v)
	if c == "" {
		return []int{0}
	}
	parts := strings.Split(c, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			n = 0
		}
		out[i] = n
	}
	return out
}

func hasPrerelease(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	return strings.Contains(v, "-")
}

func prerelease(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	_, pre, _ := strings.Cut(v, "-")
	return pre
}

func comparePrerelease(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case aerr == nil:
			return -1 // numeric identifiers sort before alphanumeric
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}
