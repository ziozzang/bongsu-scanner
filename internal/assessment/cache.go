package assessment

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// Cache records contain only validated outputs, never credentials or raw
// provider messages. Cache failures are misses; assessment does not require it.
func (c *Client) readCache(key string, in Input) (Result, bool) {
	if c.config.CacheDir == "" {
		return Result{}, false
	}
	path := filepath.Join(c.config.CacheDir, key+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxResponseBytes {
		return Result{}, false
	}
	f, err := os.Open(path) // #nosec G304 -- Cache filename is a hash under the configured local cache directory.
	if err != nil {
		return Result{}, false
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return Result{}, false
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return Result{}, false
	}
	if _, err := strictObject(raw, "status", "reason", "evidence", "preconditions", "checks", "model", "input_sha256", "cached"); err != nil {
		return Result{}, false
	}
	var r Result
	if json.Unmarshal(raw, &r) != nil || r.Model != c.config.Model || r.InputSHA256 != key {
		return Result{}, false
	}
	r, err = validateResult(r, in)
	if err != nil || c.containsCredential(r) {
		return Result{}, false
	}
	r.Cached = true
	return r, true
}
func (c *Client) writeCache(key string, r Result) {
	if c.config.CacheDir == "" {
		return
	}
	if err := os.MkdirAll(c.config.CacheDir, 0700); err != nil {
		return
	}
	f, err := os.CreateTemp(c.config.CacheDir, ".assessment-*")
	if err != nil {
		return
	}
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.Remove(f.Name())
	}()
	raw, err := json.Marshal(r)
	if err != nil {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
		return
	}
	if _, err = f.Write(raw); err != nil {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
		return
	}
	if err = f.Close(); err != nil {
		return
	}
	_ = os.Rename(f.Name(), filepath.Join(c.config.CacheDir, key+".json"))
}
