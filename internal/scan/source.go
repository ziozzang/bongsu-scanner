package scan

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxMetadata = 16 << 20

type Options struct {
	IncludeFileHashes bool
	Now               time.Time
}

type store map[string]File

func Target(ctx context.Context, target string, opts Options) (Result, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	switch {
	case target == "host" || target == "host://":
		return Directory("/", "host", opts)
	case strings.HasPrefix(target, "docker://"):
		return dockerSave(ctx, strings.TrimPrefix(target, "docker://"), false, opts)
	case strings.HasPrefix(target, "container://"):
		return dockerSave(ctx, strings.TrimPrefix(target, "container://"), true, opts)
	}
	st, err := os.Stat(target)
	if err != nil {
		return Result{}, err
	}
	if st.IsDir() {
		return Directory(target, filepath.Base(filepath.Clean(target)), opts)
	}
	return Archive(target, opts)
}

func Directory(root, name string, opts Options) (Result, error) {
	fs := store{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			if root == "/" && shouldSkipHostDir(p) {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if !opts.IncludeFileHashes && !interesting(rel) {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		rec, err := readFile(rel, f, info.Size(), "")
		if err == nil {
			fs[rel] = rec
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	r := buildResult(name, root, "directory", fs, nil, opts.Now)
	return r, nil
}

func shouldSkipHostDir(p string) bool {
	switch filepath.Clean(p) {
	case "/proc", "/sys", "/dev", "/run", "/tmp", "/mnt", "/media":
		return true
	}
	return false
}

func dockerSave(ctx context.Context, ref string, container bool, opts Options) (Result, error) {
	if strings.TrimSpace(ref) == "" {
		return Result{}, fmt.Errorf("empty Docker reference")
	}
	image := ref
	if container {
		out, err := exec.CommandContext(ctx, "docker", "container", "inspect", "--format", "{{.Image}}", ref).Output()
		if err != nil {
			return Result{}, fmt.Errorf("docker inspect %s: %w", ref, err)
		}
		image = strings.TrimSpace(string(out))
	}
	tmp, err := os.CreateTemp("", "bongsu-image-*.tar")
	if err != nil {
		return Result{}, err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)
	cmd := exec.CommandContext(ctx, "docker", "image", "save", "-o", tmpPath, image)
	if out, err := cmd.CombinedOutput(); err != nil {
		return Result{}, fmt.Errorf("docker image save: %w: %s", err, strings.TrimSpace(string(out)))
	}
	r, err := Archive(tmpPath, opts)
	if err == nil {
		r.Name, r.Source = ref, map[bool]string{true: "container://", false: "docker://"}[container]+ref
		r.SourceType = map[bool]string{true: "container", false: "docker-image"}[container]
	}
	return r, err
}

func Archive(file string, opts Options) (Result, error) {
	digest, err := digestFile(file)
	if err != nil {
		return Result{}, err
	}
	entries, cleanup, err := readOuter(file)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()
	fs, layers, kind, err := unpackImage(entries)
	if err != nil {
		return Result{}, err
	}
	if kind == "" {
		kind = "archive"
		fs = store{}
		if err := applyTarFile(file, fs, ""); err != nil {
			return Result{}, err
		}
	}
	r := buildResult(filepath.Base(file), file, kind, fs, layers, opts.Now)
	r.SourceHash = digest
	return r, nil
}

type outerEntry struct {
	Data []byte
	Temp string
	Size int64
	Hash string
}

func readOuter(file string) (map[string]outerEntry, func(), error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, func() {}, err
	}
	defer f.Close()
	tempDir, err := os.MkdirTemp("", "bongsu-archive-*")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }
	var rd io.Reader = f
	if strings.HasSuffix(strings.ToLower(file), ".gz") || strings.HasSuffix(strings.ToLower(file), ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		defer gz.Close()
		rd = gz
	}
	tr := tar.NewReader(rd)
	out := map[string]outerEntry{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		if !h.FileInfo().Mode().IsRegular() {
			continue
		}
		sum := sha256.New()
		entry := outerEntry{Size: h.Size}
		if h.Size > maxMetadata {
			tmp, err := os.CreateTemp(tempDir, "entry-*")
			if err != nil {
				cleanup()
				return nil, func() {}, err
			}
			if _, err := io.Copy(io.MultiWriter(tmp, sum), tr); err != nil {
				tmp.Close()
				cleanup()
				return nil, func() {}, err
			}
			if err := tmp.Close(); err != nil {
				cleanup()
				return nil, func() {}, err
			}
			entry.Temp = tmp.Name()
		} else {
			b, err := io.ReadAll(io.TeeReader(tr, sum))
			if err != nil {
				cleanup()
				return nil, func() {}, err
			}
			entry.Data = b
		}
		entry.Hash = hex.EncodeToString(sum.Sum(nil))
		out[clean(h.Name)] = entry
	}
	return out, cleanup, nil
}

func unpackImage(entries map[string]outerEntry) (store, []File, string, error) {
	if e, ok := entries["manifest.json"]; ok { // docker-archive
		var manifests []struct {
			Config   string
			RepoTags []string
			Layers   []string
		}
		if err := json.Unmarshal(e.Data, &manifests); err != nil || len(manifests) == 0 {
			return nil, nil, "", fmt.Errorf("invalid Docker manifest.json")
		}
		fs := store{}
		var layers []File
		for _, layer := range manifests[0].Layers {
			e, ok := entries[clean(layer)]
			if !ok {
				return nil, nil, "", fmt.Errorf("Docker layer %q missing", layer)
			}
			layers = append(layers, File{Path: layer, Size: e.Size, SHA256: e.Hash})
			if err := applyOuterLayer(e, fs, layer); err != nil {
				return nil, nil, "", err
			}
		}
		return fs, layers, "docker-archive", nil
	}
	if idx, ok := entries["index.json"]; ok && entries["oci-layout"].Data != nil {
		var index struct {
			Manifests []struct {
				Digest string `json:"digest"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(idx.Data, &index); err != nil || len(index.Manifests) == 0 {
			return nil, nil, "", fmt.Errorf("invalid OCI index")
		}
		manifestEntry, ok := entries[digestPath(index.Manifests[0].Digest)]
		if !ok {
			return nil, nil, "", fmt.Errorf("OCI manifest blob missing")
		}
		var manifest struct {
			Layers []struct {
				Digest    string `json:"digest"`
				MediaType string `json:"mediaType"`
				Size      int64  `json:"size"`
			} `json:"layers"`
		}
		if err := json.Unmarshal(manifestEntry.Data, &manifest); err != nil {
			return nil, nil, "", err
		}
		fs := store{}
		var layers []File
		for _, l := range manifest.Layers {
			e, ok := entries[digestPath(l.Digest)]
			if !ok {
				return nil, nil, "", fmt.Errorf("OCI layer %s missing", l.Digest)
			}
			layers = append(layers, File{Path: l.Digest, Size: e.Size, SHA256: strings.TrimPrefix(l.Digest, "sha256:")})
			if err := applyOuterLayer(e, fs, l.Digest); err != nil {
				return nil, nil, "", err
			}
		}
		return fs, layers, "oci-archive", nil
	}
	return nil, nil, "", nil
}

func digestPath(d string) string {
	p := strings.SplitN(d, ":", 2)
	if len(p) != 2 {
		return d
	}
	return "blobs/" + p[0] + "/" + p[1]
}

func applyTarFile(file string, fs store, layer string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	var rd io.Reader = f
	if strings.HasSuffix(strings.ToLower(file), ".gz") || strings.HasSuffix(strings.ToLower(file), ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		rd = gz
	}
	return applyTar(rd, fs, layer)
}

func applyOuterLayer(entry outerEntry, fs store, layer string) error {
	if entry.Temp != "" {
		f, err := os.Open(entry.Temp)
		if err != nil {
			return err
		}
		defer f.Close()
		return applyLayerReader(f, fs, layer)
	}
	return applyLayerReader(bytes.NewReader(entry.Data), fs, layer)
}

func applyLayerReader(input io.Reader, fs store, layer string) error {
	buf := bufio.NewReader(input)
	var rd io.Reader = buf
	header, err := buf.Peek(2)
	if err != nil && err != io.EOF {
		return err
	}
	if len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b {
		gz, err := gzip.NewReader(buf)
		if err != nil {
			return err
		}
		defer gz.Close()
		rd = gz
	}
	return applyTar(rd, fs, layer)
}

func applyTar(rd io.Reader, fs store, layer string) error {
	tr := tar.NewReader(rd)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := clean(h.Name)
		if name == "" || strings.HasPrefix(name, "../") {
			continue
		}
		base := path.Base(name)
		if strings.HasPrefix(base, ".wh.") {
			dir := path.Dir(name)
			if base == ".wh..wh..opq" {
				prefix := strings.TrimPrefix(dir+"/", "./")
				for p := range fs {
					if strings.HasPrefix(p, prefix) {
						delete(fs, p)
					}
				}
			} else {
				victim := path.Join(dir, strings.TrimPrefix(base, ".wh."))
				delete(fs, victim)
				for p := range fs {
					if strings.HasPrefix(p, victim+"/") {
						delete(fs, p)
					}
				}
			}
			continue
		}
		if !h.FileInfo().Mode().IsRegular() {
			continue
		}
		rec, err := readFile(name, tr, h.Size, layer)
		if err != nil {
			return err
		}
		fs[name] = rec
	}
}

func readFile(name string, r io.Reader, size int64, layer string) (File, error) {
	h := sha256.New()
	var data []byte
	if size <= maxMetadata && interesting(name) {
		b, err := io.ReadAll(io.TeeReader(r, h))
		if err != nil {
			return File{}, err
		}
		data = b
	} else if _, err := io.Copy(h, r); err != nil {
		return File{}, err
	}
	return File{Path: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil)), Data: data, Layer: layer}, nil
}

func clean(p string) string {
	return strings.TrimPrefix(path.Clean(strings.ReplaceAll(p, "\\", "/")), "./")
}

func interesting(p string) bool {
	p = strings.ToLower(p)
	base := path.Base(p)
	if p == "var/lib/dpkg/status" || p == "lib/apk/db/installed" || strings.HasSuffix(p, "/os-release") {
		return true
	}
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "go.mod", "go.sum", "requirements.txt",
		"cargo.lock", "pom.properties", "metadata":
		return true
	}
	return strings.HasSuffix(p, ".dist-info/metadata")
}

func buildResult(name, source, kind string, fs store, layers []File, now time.Time) Result {
	files := make([]File, 0, len(fs))
	for _, f := range fs {
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	r := Result{Name: name, Source: source, SourceType: kind, ScannedAt: now.UTC(), Files: files, Layers: layers}
	r.Packages, r.OSName, r.OSVersion = catalog(files)
	return r
}

func digestFile(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
