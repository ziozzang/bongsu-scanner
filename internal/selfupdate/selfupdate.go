// Package selfupdate downloads a GitHub release binary, verifies SHA256SUMS,
// and atomically replaces the running executable.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const APIBase = "https://api.github.com"

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

func Latest(ctx context.Context, client *http.Client, repo, token string) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBase+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "bongsu-selfupdate")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("GitHub API %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release has no tag")
	}
	return &rel, nil
}

func (r Release) Version() string { return strings.TrimPrefix(r.TagName, "v") }
func (r Release) Find(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

func AssetName(ver string) (string, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return "", fmt.Errorf("no release build for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	arch := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]
	return fmt.Sprintf("bongsu_%s_linux_%s", ver, arch), nil
}

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
	return 0
}
func fields(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v = strings.FieldsFunc(v, func(r rune) bool { return r == '-' || r == '+' })[0]
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i := range parts {
		out[i], _ = strconv.Atoi(parts[i])
	}
	return out
}

func Checksums(ctx context.Context, client *http.Client, rel *Release) (map[string]string, error) {
	asset, ok := rel.Find("SHA256SUMS")
	if !ok {
		return nil, fmt.Errorf("release has no SHA256SUMS")
	}
	b, err := downloadBytes(ctx, client, asset.URL, 1<<20)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && len(f[0]) == 64 {
			out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return out, nil
}

func DownloadVerified(ctx context.Context, client *http.Client, asset Asset, want, dir string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "bongsu-selfupdate")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", asset.Name, resp.Status)
	}
	f, err := os.CreateTemp(dir, ".bongsu-update-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 1<<30)); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return "", fmt.Errorf("checksum mismatch for %s", asset.Name)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	ok = true
	return tmp, nil
}

func Replace(src string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return exe, os.Rename(src, exe)
}

func downloadBytes(ctx context.Context, client *http.Client, u string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "bongsu-selfupdate")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}
