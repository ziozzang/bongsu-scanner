package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// tarEntry describes one entry for buildTar; typeflag zero means regular file.
type tarEntry struct {
	name     string
	data     []byte
	mode     int64
	typeflag byte
	link     string
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: e.typeflag, Linkname: e.link}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func filesByPath(r Result) map[string]File {
	out := map[string]File{}
	for _, f := range r.Files {
		out[f.Path] = f
	}
	return out
}

func packageVersions(r Result) map[string]string {
	out := map[string]string{}
	for _, p := range r.Packages {
		out[p.Name] = p.Version
	}
	return out
}

const apkDB = "P:musl\nV:1.2.5-r0\nA:x86_64\n\nP:curl\nV:8.9.0-r0\nA:x86_64\n\n"

// ociImage is a minimal OCI image: one config and a list of layer blobs.
type ociImage struct {
	layers   [][]byte // blob bytes as stored (compressed or not)
	diffIDs  []string
	platform *ociPlatform
	created  string
}

// ociBlobs adds config/manifest/layers to entries and returns the manifest
// descriptor. declaredLayerDigest overrides a layer's declared digest.
func ociBlobs(t *testing.T, entries map[string][]byte, img ociImage, declaredLayerDigest map[int]string) ociDescriptor {
	t.Helper()
	cfg := map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"created":      img.created,
		"rootfs":       map[string]any{"type": "layers", "diff_ids": img.diffIDs},
	}
	if img.platform != nil {
		cfg["architecture"], cfg["os"] = img.platform.Architecture, img.platform.OS
		if img.platform.Variant != "" {
			cfg["variant"] = img.platform.Variant
		}
	}
	cfgRaw := mustJSON(t, cfg)
	cfgDigest := digestOf(cfgRaw)
	entries[digestPath(cfgDigest)] = cfgRaw
	var layers []ociDescriptor
	for i, blob := range img.layers {
		d := digestOf(blob)
		entries[digestPath(d)] = blob
		if override, ok := declaredLayerDigest[i]; ok {
			d = override
		}
		mt := mediaTypeOCILayer
		if detectFormat(blob) == formatGzip {
			mt = mediaTypeOCILayerGzip
		}
		layers = append(layers, ociDescriptor{MediaType: mt, Digest: d, Size: int64(len(blob))})
	}
	manifest := ociManifest{
		MediaType: mediaTypeOCIManifest,
		Config:    ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: cfgDigest, Size: int64(len(cfgRaw))},
		Layers:    layers,
	}
	raw := mustJSON(t, manifest)
	d := digestOf(raw)
	entries[digestPath(d)] = raw
	return ociDescriptor{MediaType: mediaTypeOCIManifest, Digest: d, Size: int64(len(raw)), Platform: img.platform}
}

func ociLayoutTar(t *testing.T, entries map[string][]byte, index ociIndex) []byte {
	t.Helper()
	entries["oci-layout"] = []byte(`{"imageLayoutVersion":"1.0.0"}`)
	entries["index.json"] = mustJSON(t, index)
	var list []tarEntry
	for name, data := range entries {
		list = append(list, tarEntry{name: name, data: data})
	}
	return buildTar(t, list)
}

func simpleOCI(t *testing.T, declared map[int]string) ([]byte, ociDescriptor, []byte, []byte) {
	t.Helper()
	layerTar := buildTar(t, []tarEntry{
		{name: "lib/apk/db/installed", data: []byte(apkDB)},
		{name: "etc/os-release", data: []byte("ID=alpine\nVERSION_ID=3.20.3\n")},
	})
	blob := gzipBytes(t, layerTar)
	entries := map[string][]byte{}
	desc := ociBlobs(t, entries, ociImage{layers: [][]byte{blob}, diffIDs: []string{digestOf(layerTar)}, created: "2024-01-02T03:04:05Z"}, declared)
	desc.Annotations = map[string]string{"org.opencontainers.image.ref.name": "alpine:3.20"}
	outer := ociLayoutTar(t, entries, ociIndex{MediaType: mediaTypeOCIIndex, Manifests: []ociDescriptor{desc}})
	return outer, desc, blob, layerTar
}

func TestOCIArchiveVerifiesLayerDigests(t *testing.T) {
	outer, desc, blob, layerTar := simpleOCI(t, nil)
	p := writeTemp(t, "image.tar", outer)
	r, err := Archive(p, Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceType != "oci-archive" || len(r.Layers) != 1 {
		t.Fatalf("type=%s layers=%d", r.SourceType, len(r.Layers))
	}
	if r.Layers[0].SHA256 != strings.TrimPrefix(digestOf(blob), "sha256:") || r.Layers[0].Path != digestOf(blob) {
		t.Fatalf("layer file = %#v", r.Layers[0])
	}
	if r.Image == nil {
		t.Fatal("image metadata missing")
	}
	img := r.Image
	if img.Digest != desc.Digest || !strings.HasPrefix(img.ID, "sha256:") || img.OS != "linux" || img.Architecture != "amd64" || img.Created != "2024-01-02T03:04:05Z" {
		t.Fatalf("image = %#v", img)
	}
	if len(img.Tags) != 1 || img.Tags[0] != "alpine:3.20" {
		t.Fatalf("tags = %v", img.Tags)
	}
	if len(img.Layers) != 1 {
		t.Fatalf("layer infos = %#v", img.Layers)
	}
	li := img.Layers[0]
	if !li.Verified || li.Digest != digestOf(blob) || li.DiffID != digestOf(layerTar) || li.MediaType != mediaTypeOCILayerGzip || li.Size != int64(len(blob)) {
		t.Fatalf("layer info = %#v", li)
	}
	if got := packageVersions(r); got["curl"] != "8.9.0-r0" || got["musl"] != "1.2.5-r0" {
		t.Fatalf("packages = %v", got)
	}
	if r.OSName != "alpine" || r.OSVersion != "3.20.3" || r.OS == nil {
		t.Fatalf("os = %s %s", r.OSName, r.OSVersion)
	}
	// The same layout gzip-compressed without an extension must scan identically.
	gzPath := writeTemp(t, "image", gzipBytes(t, outer))
	r2, err := Archive(gzPath, Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Packages) != len(r.Packages) || r2.Image.Layers[0].Digest != li.Digest || !r2.Image.Layers[0].Verified {
		t.Fatalf("compressed outer archive result differs: %#v", r2.Image)
	}
}

func TestOCIArchiveDigestMismatch(t *testing.T) {
	fake := "sha256:" + strings.Repeat("ab", 32)
	outer, _, blob, _ := simpleOCI(t, map[int]string{0: fake})
	// The blob is stored under its real digest, so the declared path is missing.
	p := writeTemp(t, "image.tar", outer)
	_, err := Archive(p, Options{Now: time.Unix(1, 0)})
	if err == nil {
		t.Fatal("expected error for missing blob under declared digest")
	}
	// Now place the real blob under the tampered path so verification runs.
	outer2 := appendTarEntry(t, outer, tarEntry{name: digestPath(fake), data: blob})
	p2 := writeTemp(t, "image2.tar", outer2)
	_, err = Archive(p2, Options{Now: time.Unix(1, 0)})
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") || !strings.Contains(err.Error(), fake) {
		t.Fatalf("expected digest mismatch error, got %v", err)
	}
	r, err := Archive(p2, Options{Now: time.Unix(1, 0), AllowDigestMismatch: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Image == nil || len(r.Image.Layers) != 1 || r.Image.Layers[0].Verified {
		t.Fatalf("expected Verified=false: %#v", r.Image)
	}
	if r.Image.Layers[0].Digest != digestOf(blob) || r.Layers[0].SHA256 != strings.TrimPrefix(digestOf(blob), "sha256:") {
		t.Fatalf("actual digest must be recorded: %#v", r.Image.Layers[0])
	}
}

// appendTarEntry rewrites a tar with one more regular file.
func appendTarEntry(t *testing.T, outer []byte, extra tarEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tr := tar.NewReader(bytes.NewReader(outer))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(tw, tr); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: extra.name, Mode: 0o644, Size: int64(len(extra.data))}); err != nil {
		t.Fatal(err)
	}
	tw.Write(extra.data)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestOCINestedIndexPlatformSelection(t *testing.T) {
	entries := map[string][]byte{}
	mk := func(marker string, plat *ociPlatform) ociDescriptor {
		layer := buildTar(t, []tarEntry{
			{name: "lib/apk/db/installed", data: []byte("P:" + marker + "\nV:1.0\n\n")},
			{name: "etc/os-release", data: []byte("ID=alpine\n")},
		})
		return ociBlobs(t, entries, ociImage{layers: [][]byte{layer}, diffIDs: []string{digestOf(layer)}, platform: plat}, nil)
	}
	other := "arm64"
	if runtime.GOARCH == "arm64" {
		other = "amd64"
	}
	attestation := ociDescriptor{MediaType: mediaTypeOCIManifest, Digest: "sha256:" + strings.Repeat("00", 32), Size: 1,
		Platform:    &ociPlatform{OS: "unknown", Architecture: "unknown"},
		Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"}}
	hostDesc := mk("pkg-host", &ociPlatform{OS: "linux", Architecture: runtime.GOARCH})
	otherDesc := mk("pkg-other", &ociPlatform{OS: "linux", Architecture: other, Variant: "v8"})
	nested := ociIndex{MediaType: mediaTypeOCIIndex, Manifests: []ociDescriptor{attestation, otherDesc, hostDesc}}
	nestedRaw := mustJSON(t, nested)
	entries[digestPath(digestOf(nestedRaw))] = nestedRaw
	top := ociIndex{MediaType: mediaTypeOCIIndex, Manifests: []ociDescriptor{{
		MediaType: mediaTypeOCIIndex, Digest: digestOf(nestedRaw), Size: int64(len(nestedRaw)),
		Annotations: map[string]string{"org.opencontainers.image.ref.name": "multi:latest"},
	}}}
	p := writeTemp(t, "multi.tar", ociLayoutTar(t, entries, top))

	r, err := Archive(p, Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := packageVersions(r)["pkg-host"]; !ok || r.Image.Digest != hostDesc.Digest || r.Image.Architecture != runtime.GOARCH {
		t.Fatalf("default platform selection wrong: pkgs=%v image=%#v", packageVersions(r), r.Image)
	}
	if len(r.Image.Tags) != 1 || r.Image.Tags[0] != "multi:latest" {
		t.Fatalf("tags = %v", r.Image.Tags)
	}
	r, err = Archive(p, Options{Now: time.Unix(1, 0), Platform: "linux/" + other + "/v8"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := packageVersions(r)["pkg-other"]; !ok || r.Image.Digest != otherDesc.Digest || r.Image.Variant != "v8" {
		t.Fatalf("explicit platform selection wrong: pkgs=%v image=%#v", packageVersions(r), r.Image)
	}
	if _, err := Archive(p, Options{Now: time.Unix(1, 0), Platform: "plan9/mips"}); err == nil || !strings.Contains(err.Error(), "no image manifest for platform plan9/mips") {
		t.Fatalf("expected platform error, got %v", err)
	}
	if _, err := Archive(p, Options{Now: time.Unix(1, 0), Platform: "bogus"}); err == nil || !strings.Contains(err.Error(), "invalid platform") {
		t.Fatalf("expected invalid platform error, got %v", err)
	}
}

func TestOCISingleForeignPlatformFallback(t *testing.T) {
	entries := map[string][]byte{}
	layer := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=debian\nVERSION_ID=\"12\"\n")}})
	desc := ociBlobs(t, entries, ociImage{layers: [][]byte{layer}, diffIDs: []string{digestOf(layer)}, platform: &ociPlatform{OS: "linux", Architecture: "s390x"}}, nil)
	p := writeTemp(t, "s390x.tar", ociLayoutTar(t, entries, ociIndex{Manifests: []ociDescriptor{desc}}))
	var msgs []string
	r, err := Archive(p, Options{Now: time.Unix(1, 0), Progress: func(e Progress) { msgs = append(msgs, e.Message) }})
	if err != nil {
		t.Fatal(err)
	}
	if r.Image.Architecture != "s390x" || r.OSName != "debian" {
		t.Fatalf("fallback result = %#v os=%s", r.Image, r.OSName)
	}
	if !strings.Contains(strings.Join(msgs, "\n"), "scanning the only image manifest") {
		t.Fatalf("fallback should be reported: %v", msgs)
	}
	if _, err := Archive(p, Options{Now: time.Unix(1, 0), Platform: "linux/amd64"}); err == nil || !strings.Contains(err.Error(), "available: linux/s390x") {
		t.Fatalf("explicit platform must not fall back: %v", err)
	}
}

func TestDockerArchiveDiffIDMismatch(t *testing.T) {
	layer := buildTar(t, []tarEntry{{name: "var/lib/dpkg/status", data: []byte("Package: libc6\nStatus: install ok installed\nVersion: 2.39-1\nArchitecture: amd64\n\n")}})
	cfg := mustJSON(t, map[string]any{
		"architecture": "arm64", "os": "linux", "variant": "v8", "created": "2023-05-06T07:08:09Z",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + strings.Repeat("cd", 32)}},
	})
	manifest := mustJSON(t, []dockerManifest{{Config: "cfg.json", RepoTags: []string{"t:1"}, Layers: []string{"l1/layer.tar"}}})
	outer := buildTar(t, []tarEntry{{name: "manifest.json", data: manifest}, {name: "cfg.json", data: cfg}, {name: "l1/layer.tar", data: layer}})
	p := writeTemp(t, "image.tar", outer)
	_, err := Archive(p, Options{Now: time.Unix(1, 0)})
	if err == nil || !strings.Contains(err.Error(), "diff_id mismatch") {
		t.Fatalf("expected diff_id mismatch, got %v", err)
	}
	r, err := Archive(p, Options{Now: time.Unix(1, 0), AllowDigestMismatch: true})
	if err != nil {
		t.Fatal(err)
	}
	img := r.Image
	if img == nil || img.Verified() || img.Architecture != "arm64" || img.Variant != "v8" || img.Created != "2023-05-06T07:08:09Z" || img.ID != digestOf(cfg) {
		t.Fatalf("image = %#v", img)
	}
	if img.Layers[0].DiffID != digestOf(layer) || img.Layers[0].Digest != digestOf(layer) || r.Layers[0].SHA256 != strings.TrimPrefix(digestOf(layer), "sha256:") {
		t.Fatalf("layer = %#v file=%#v", img.Layers[0], r.Layers[0])
	}
	if got := packageVersions(r); got["libc6"] != "2.39-1" {
		t.Fatalf("packages = %v", got)
	}
}

// Verified reports whether every layer verified (test helper).
func (img *ImageMetadata) Verified() bool {
	for _, l := range img.Layers {
		if !l.Verified {
			return false
		}
	}
	return true
}

func TestDockerArchiveMatchingDiffIDsAndBlobPaths(t *testing.T) {
	layer := buildTar(t, []tarEntry{{name: "lib/apk/db/installed", data: []byte(apkDB)}})
	cfg := mustJSON(t, map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{digestOf(layer)}}})
	manifest := mustJSON(t, []dockerManifest{
		{Config: digestPath(digestOf(cfg)), RepoTags: []string{"alpine:3.20"}, Layers: []string{digestPath(digestOf(layer))},
			LayerSources: map[string]ociDescriptor{digestOf(layer): {MediaType: mediaTypeOCILayer, Digest: digestOf(layer), Size: int64(len(layer))}}},
		{Config: "other.json", RepoTags: []string{"other:1"}, Layers: []string{"missing.tar"}},
	})
	manifestRaw := mustJSON(t, ociManifest{MediaType: mediaTypeOCIManifest, Config: ociDescriptor{Digest: digestOf(cfg)}, Layers: []ociDescriptor{{Digest: digestOf(layer)}}})
	manifestDesc := ociDescriptor{MediaType: mediaTypeOCIManifest, Digest: digestOf(manifestRaw), Size: int64(len(manifestRaw))}
	outer := buildTar(t, []tarEntry{
		{name: "manifest.json", data: manifest},
		{name: "index.json", data: mustJSON(t, ociIndex{Manifests: []ociDescriptor{manifestDesc}})},
		{name: digestPath(manifestDesc.Digest), data: manifestRaw},
		{name: digestPath(digestOf(cfg)), data: cfg},
		{name: digestPath(digestOf(layer)), data: layer},
	})
	var msgs []string
	r, err := Archive(writeTemp(t, "image.tar", outer), Options{Now: time.Unix(1, 0), Progress: func(e Progress) { msgs = append(msgs, e.Message) }})
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceType != "docker-archive" || !r.Image.Verified() || r.Image.Digest != manifestDesc.Digest || r.Image.ID != digestOf(cfg) {
		t.Fatalf("image = %#v", r.Image)
	}
	if r.Image.Layers[0].MediaType != mediaTypeOCILayer || len(r.Image.Tags) != 1 {
		t.Fatalf("layer = %#v tags=%v", r.Image.Layers[0], r.Image.Tags)
	}
	if !strings.Contains(strings.Join(msgs, "\n"), "lists 2 images") {
		t.Fatalf("multi-image manifest should be reported: %v", msgs)
	}
	// A tampered layer blob under the declared path must be rejected.
	tampered := appendTarEntry(t, buildTar(t, []tarEntry{
		{name: "manifest.json", data: manifest},
		{name: digestPath(digestOf(cfg)), data: cfg},
	}), tarEntry{name: digestPath(digestOf(layer)), data: buildTar(t, []tarEntry{{name: "evil", data: []byte("x")}})})
	_, err = Archive(writeTemp(t, "tampered.tar", tampered), Options{Now: time.Unix(1, 0)})
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected mismatch, got %v", err)
	}
}

func TestHardlinkCopiesTarget(t *testing.T) {
	busybox := []byte("#!/bin/sh\necho busybox\n")
	layer := buildTar(t, []tarEntry{
		{name: "bin/busybox", data: busybox, mode: 0o755},
		{name: "bin/sh", typeflag: tar.TypeLink, link: "bin/busybox"},
		{name: "bin/dangling", typeflag: tar.TypeLink, link: "bin/nope"},
		{name: "etc/os-release", data: []byte("ID=alpine\n")},
	})
	r, err := Archive(writeTemp(t, "rootfs.tar", layer), Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	files := filesByPath(r)
	sh, ok := files["bin/sh"]
	if !ok {
		t.Fatal("hard link bin/sh missing")
	}
	if sh.Size != int64(len(busybox)) || sh.SHA256 != files["bin/busybox"].SHA256 || sh.SHA256 != strings.TrimPrefix(digestOf(busybox), "sha256:") {
		t.Fatalf("hard link record = %#v", sh)
	}
	if _, ok := files["bin/dangling"]; ok {
		t.Fatal("dangling hard link must be skipped")
	}
}

func TestSymlinkedOSReleaseResolved(t *testing.T) {
	// etc/ sorts before usr/ so the symlink precedes its target in the tar.
	layer := buildTar(t, []tarEntry{
		{name: "etc/os-release", typeflag: tar.TypeSymlink, link: "../usr/lib/os-release"},
		{name: "etc/escape", typeflag: tar.TypeSymlink, link: "../../outside"},
		{name: "usr/lib/os-release", data: []byte("ID=debian\nVERSION_ID=\"13\"\n")},
	})
	r, err := Archive(writeTemp(t, "rootfs.tar", layer), Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := filesByPath(r)["etc/os-release"]
	if !ok || f.SHA256 != filesByPath(r)["usr/lib/os-release"].SHA256 {
		t.Fatalf("symlinked os-release not resolved: %#v", r.Files)
	}
	if r.OSName != "debian" || r.OSVersion != "13" {
		t.Fatalf("os = %s %s", r.OSName, r.OSVersion)
	}
	if resolveLink("etc/escape", "../../outside") != "" || resolveLink("etc/x", "/usr/lib/x") != "usr/lib/x" || resolveLink("a/b/c", "../d") != "a/d" {
		t.Fatal("resolveLink semantics")
	}
}

func dockerArchive(t *testing.T, layers ...[]byte) []byte {
	t.Helper()
	var names []string
	entries := []tarEntry{}
	var diffIDs []string
	for i, l := range layers {
		name := fmt.Sprintf("l%d/layer.tar", i)
		names = append(names, name)
		entries = append(entries, tarEntry{name: name, data: l})
		diffIDs = append(diffIDs, digestOf(l))
	}
	cfg := mustJSON(t, map[string]any{"os": "linux", "architecture": "amd64", "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}})
	entries = append(entries,
		tarEntry{name: "manifest.json", data: mustJSON(t, []dockerManifest{{Config: "config.json", Layers: names}})},
		tarEntry{name: "config.json", data: cfg})
	return buildTar(t, entries)
}

func TestOpaqueWhiteoutOnlyHidesLowerLayers(t *testing.T) {
	layer1 := buildTar(t, []tarEntry{
		{name: "app/old.txt", data: []byte("old")},
		{name: "app/sub/deep.txt", data: []byte("deep")},
		{name: "etc/keep", data: []byte("k")},
		{name: "gone.txt", data: []byte("g")},
		{name: "dir/a", data: []byte("a")},
	})
	layer2 := buildTar(t, []tarEntry{
		{name: "app/new.txt", data: []byte("new")},    // added before the opaque marker
		{name: "app/.wh..wh..opq", data: nil},         // hides app/* from layer1 only
		{name: "app/later.txt", data: []byte("late")}, // added after the marker
		{name: ".wh.gone.txt", data: nil},
		{name: ".wh.dir", data: nil},
		{name: "dir/b", data: []byte("b")}, // same-layer sibling of a whiteout survives
	})
	r, err := Archive(writeTemp(t, "image.tar", dockerArchive(t, layer1, layer2)), Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	files := filesByPath(r)
	for _, want := range []string{"app/new.txt", "app/later.txt", "etc/keep", "dir/b"} {
		if _, ok := files[want]; !ok {
			t.Errorf("%s should survive", want)
		}
	}
	for _, gone := range []string{"app/old.txt", "app/sub/deep.txt", "gone.txt", "dir/a"} {
		if _, ok := files[gone]; ok {
			t.Errorf("%s should be hidden", gone)
		}
	}
	if !r.Image.Verified() || len(r.Image.Layers) != 2 {
		t.Fatalf("layers = %#v", r.Image.Layers)
	}
}

func TestAbsolutePathEntries(t *testing.T) {
	layer := buildTar(t, []tarEntry{
		{name: "/var/lib/dpkg/status", data: []byte("Package: bash\nStatus: install ok installed\nVersion: 5.2-1\n\n")},
		{name: "//etc/os-release", data: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
		{name: "/", typeflag: tar.TypeDir},
		{name: "../escape", data: []byte("x")},
		{name: "./ok/../usr/bin/tool", data: []byte("t")},
	})
	r, err := Archive(writeTemp(t, "rootfs.tar", layer), Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	files := filesByPath(r)
	if _, ok := files["var/lib/dpkg/status"]; !ok {
		t.Fatalf("absolute path not normalized: %v", r.Files)
	}
	if _, ok := files["usr/bin/tool"]; !ok {
		t.Fatalf("dot path not normalized: %v", r.Files)
	}
	if _, ok := files["escape"]; ok {
		t.Fatal("../ entry must be dropped")
	}
	if got := packageVersions(r); got["bash"] != "5.2-1" || r.OSName != "debian" {
		t.Fatalf("packages=%v os=%s", got, r.OSName)
	}
	if clean("/") != "" || clean("./") != "" || clean("a\\b") != "a/b" || clean("/a/./b/") != "a/b" || clean("../x") != "../x" {
		t.Fatal("clean semantics")
	}
}

func TestGzipRootfsWithoutExtension(t *testing.T) {
	layer := buildTar(t, []tarEntry{{name: "lib/apk/db/installed", data: []byte(apkDB)}})
	p := writeTemp(t, "rootfs", gzipBytes(t, layer))
	r, err := Archive(p, Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceType != "archive" || len(r.Packages) != 2 || r.SourceHash != strings.TrimPrefix(digestOf(gzipBytes(t, layer)), "sha256:") {
		t.Fatalf("result = %s %d %s", r.SourceType, len(r.Packages), r.SourceHash)
	}
	// A misleading .gz extension on a plain tar must not break detection either.
	r, err = Archive(writeTemp(t, "rootfs.tar.gz", layer), Options{Now: time.Unix(1, 0)})
	if err != nil || len(r.Packages) != 2 {
		t.Fatalf("plain tar with .gz suffix: %v (%d packages)", err, len(r.Packages))
	}
}

func TestEmptyAndUnrecognizedArchivesRejected(t *testing.T) {
	empty := buildTar(t, nil)
	_, err := Archive(writeTemp(t, "empty.tar", empty), Options{Now: time.Unix(1, 0)})
	if err == nil || !strings.Contains(err.Error(), "no image manifest or root filesystem found") {
		t.Fatalf("empty tar: %v", err)
	}
	junk := buildTar(t, []tarEntry{{name: "README", data: []byte("hi")}, {name: "data/x.bin", data: []byte{1, 2}}})
	_, err = Archive(writeTemp(t, "junk.tar", junk), Options{Now: time.Unix(1, 0)})
	if err == nil || !strings.Contains(err.Error(), "no image manifest or root filesystem found") {
		t.Fatalf("junk tar: %v", err)
	}
	// A source tree with lockfiles is still accepted.
	src := buildTar(t, []tarEntry{{name: "project/go.mod", data: []byte("module x\nrequire example.com/m v1.0.0\n")}})
	r, err := Archive(writeTemp(t, "src.tar", src), Options{Now: time.Unix(1, 0)})
	if err != nil || len(r.Packages) != 1 {
		t.Fatalf("source tar: %v (%d packages)", err, len(r.Packages))
	}
	if _, err := Archive(writeTemp(t, "zero", make([]byte, 0)), Options{Now: time.Unix(1, 0)}); err == nil {
		t.Fatal("zero-byte file must fail")
	}
	if _, err := Archive(writeTemp(t, "garbage", []byte("this is not a tar file at all, just text")), Options{Now: time.Unix(1, 0)}); err == nil {
		t.Fatal("garbage must fail")
	}
}

func TestInvalidZstdRejected(t *testing.T) {
	zstd := []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0}
	_, err := Archive(writeTemp(t, "image.tar.zst", zstd), Options{Now: time.Unix(1, 0)})
	if err == nil {
		t.Fatalf("outer zstd: %v", err)
	}
	// zstd layer inside an OCI layout: detected via media type and via magic.
	entries := map[string][]byte{}
	desc := ociBlobs(t, entries, ociImage{layers: [][]byte{zstd}, diffIDs: []string{"sha256:" + strings.Repeat("11", 32)}}, nil)
	p := writeTemp(t, "zstd-layer.tar", ociLayoutTar(t, entries, ociIndex{Manifests: []ociDescriptor{desc}}))
	_, err = Archive(p, Options{Now: time.Unix(1, 0)})
	if err == nil {
		t.Fatalf("zstd layer by magic: %v", err)
	}
	u := newUnpacker(context.Background(), Options{})
	_, err = u.applyLayer(bytes.NewReader(buildTar(t, nil)), 0, layerCheck{name: "x", mediaType: "application/vnd.oci.image.layer.v1.tar+zstd"})
	if err == nil {
		t.Fatalf("zstd layer by media type: %v", err)
	}
}

func TestDockerReferenceValidation(t *testing.T) {
	ctx := context.Background()
	for _, target := range []string{"docker://-x", "docker://--help", "container://-rm", "docker://", "container://a b", "docker://.hidden"} {
		_, err := Target(ctx, target, Options{})
		if err == nil || !(strings.Contains(err.Error(), "invalid reference") || strings.Contains(err.Error(), "empty Docker reference")) {
			t.Errorf("%s: expected rejection, got %v", target, err)
		}
	}
	for _, ref := range []string{"alpine:3.20", "ghcr.io/org/app@sha256:" + strings.Repeat("0", 64), "127.0.0.1:5000/x/y:z", "9f3c", "my_container-1"} {
		if err := validateDockerRef(ref); err != nil {
			t.Errorf("%s: unexpected rejection: %v", ref, err)
		}
	}
}

func TestGoBinaryHook(t *testing.T) {
	var calls []string
	orig := extractGoBinary
	extractGoBinary = func(r io.ReaderAt, size int64, source, layer string) []Package {
		calls = append(calls, source)
		head := make([]byte, 4)
		r.ReadAt(head, 0)
		if !isELF(head) {
			t.Errorf("hook received non-ELF data for %s", source)
		}
		if strings.Contains(source, "removed") {
			return []Package{{Name: "example.com/removed", Version: "v0.0.1", Type: "golang", Source: source, Layer: layer}}
		}
		return []Package{{Name: "example.com/dep", Version: "v1.2.3", Type: "golang", Source: source, Layer: layer}}
	}
	defer func() { extractGoBinary = orig }()
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0}, 60)...)
	layer1 := buildTar(t, []tarEntry{
		{name: "usr/bin/app", data: elf, mode: 0o755},       // exec bit
		{name: "opt/tool", data: elf, mode: 0o644},          // no extension
		{name: "usr/lib/libx.so.1", data: elf, mode: 0o644}, // extension, no exec bit: skipped
		{name: "etc/notelf", data: []byte("plain"), mode: 0o755},
		{name: "usr/bin/removed", data: elf, mode: 0o755},
		{name: "etc/os-release", data: []byte("ID=alpine\n")},
	})
	layer2 := buildTar(t, []tarEntry{{name: "usr/bin/.wh.removed", data: nil}})
	r, err := Archive(writeTemp(t, "image.tar", dockerArchive(t, layer1, layer2)), Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"usr/bin/app": true, "opt/tool": true, "usr/bin/removed": true}
	if len(calls) != len(want) {
		t.Fatalf("hook calls = %v", calls)
	}
	for _, c := range calls {
		if !want[c] {
			t.Errorf("unexpected hook call for %s", c)
		}
	}
	got := packageVersions(r)
	if got["example.com/dep"] != "v1.2.3" && got["dep"] != "v1.2.3" {
		t.Fatalf("go packages not merged: %v", got)
	}
	if _, ok := got["example.com/removed"]; ok {
		t.Fatal("packages from a whited-out binary must not be reported")
	}
	if _, ok := got["removed"]; ok {
		t.Fatal("packages from a whited-out binary must not be reported")
	}
	if f := filesByPath(r)["usr/bin/app"]; f.Data != nil || f.SHA256 != strings.TrimPrefix(digestOf(elf), "sha256:") {
		t.Fatalf("binary record = %#v", f)
	}
}

func TestArchiveHonoursContextCancellation(t *testing.T) {
	layer := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=alpine\n")}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := archiveContext(ctx, writeTemp(t, "rootfs.tar", layer), Options{Now: time.Unix(1, 0)})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	_, err = Target(ctx, "docker://alpine:3.20", Options{})
	if err == nil {
		t.Fatal("cancelled docker target must fail")
	}
}

func TestPlatformMatching(t *testing.T) {
	p, err := parsePlatform("Linux/aarch64")
	if err != nil || p.os != "linux" || p.arch != "arm64" {
		t.Fatalf("parsePlatform = %#v %v", p, err)
	}
	if !p.matches(&ociPlatform{OS: "linux", Architecture: "arm64", Variant: "v8"}) {
		t.Fatal("variant-less request must match any variant")
	}
	p, _ = parsePlatform("linux/arm/v7")
	if p.matches(&ociPlatform{OS: "linux", Architecture: "arm", Variant: "v6"}) || !p.matches(&ociPlatform{OS: "linux", Architecture: "arm", Variant: "v7"}) {
		t.Fatal("variant must be honoured when requested")
	}
	if p.matches(nil) {
		t.Fatal("nil platform never matches explicitly")
	}
}

// fakeDocker installs a docker shell script ahead of PATH that logs its
// arguments and serves prepared archives, then returns the log path.
func fakeDocker(t *testing.T, imageTar, exportTar []byte) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "args.log")
	imagePath := filepath.Join(dir, "image.tar")
	exportPath := filepath.Join(dir, "export.tar")
	os.WriteFile(imagePath, imageTar, 0o644)
	os.WriteFile(exportPath, exportTar, 0o644)
	script := `#!/bin/sh
printf '%s\n' "$@" >> "$FAKE_DOCKER_LOG"
printf '<<END>>\n' >> "$FAKE_DOCKER_LOG"
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
case "$1 $2" in
  "image save") cp "$FAKE_DOCKER_IMAGE" "$out" ;;
  "export "*) cp "$FAKE_DOCKER_EXPORT" "$out" ;;
  "container inspect")
    last=""; for a in "$@"; do last="$a"; done
    if [ "$last" = "missing" ]; then echo "Error response from daemon: No such container: missing" >&2; exit 1; fi
    printf 'abcdef0123456789|sha256:%s|/%s|running\n' "$(printf '%064d' 7)" "$last" ;;
  "image inspect")
    printf '{"Id":"sha256:%s","RepoTags":["alpine:3.20"],"RepoDigests":["alpine@sha256:%s"],"Created":"2024-01-01T00:00:00Z","Os":"linux","Architecture":"amd64"}\n' "$(printf '%064d' 7)" "$(printf '%064d' 9)" ;;
  *) echo "unexpected: $*" >&2; exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_LOG", log)
	t.Setenv("FAKE_DOCKER_IMAGE", imagePath)
	t.Setenv("FAKE_DOCKER_EXPORT", exportPath)
	return log
}

func readLog(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	for _, call := range strings.Split(strings.TrimSpace(string(b)), "<<END>>") {
		if call = strings.ReplaceAll(strings.TrimSpace(call), "\n", " "); call != "" {
			calls = append(calls, call)
		}
	}
	return calls
}

func TestDockerImageTargetUsesSeparator(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake")
	}
	layer := buildTar(t, []tarEntry{{name: "lib/apk/db/installed", data: []byte(apkDB)}, {name: "etc/os-release", data: []byte("ID=alpine\nVERSION_ID=3.20.3\n")}})
	log := fakeDocker(t, dockerArchive(t, layer), nil)
	var msgs []string
	r, err := Target(context.Background(), "docker://alpine:3.20", Options{Progress: func(e Progress) { msgs = append(msgs, e.Stage+": "+e.Message) }})
	if err != nil {
		t.Fatal(err)
	}
	calls := readLog(t, log)
	if len(calls) != 2 {
		t.Fatalf("calls = %q", calls)
	}
	if !strings.HasPrefix(calls[0], "image save -o ") || !strings.HasSuffix(calls[0], " -- alpine:3.20") {
		t.Fatalf("image save call = %q", calls[0])
	}
	if calls[1] != "image inspect --format {{json .}} -- alpine:3.20" {
		t.Fatalf("image inspect call = %q", calls[1])
	}
	if r.SourceType != "docker-image" || r.Source != "docker://alpine:3.20" || r.Name != "alpine:3.20" || r.SourceHash != "" {
		t.Fatalf("result = %s %s %s hash=%q", r.SourceType, r.Source, r.Name, r.SourceHash)
	}
	if len(r.Packages) != 2 || r.OSName != "alpine" {
		t.Fatalf("packages=%d os=%s", len(r.Packages), r.OSName)
	}
	img := r.Image
	if img == nil || img.ID == "" || len(img.RepoDigests) != 1 || len(img.Tags) != 1 || img.Tags[0] != "alpine:3.20" || img.OS != "linux" || !img.Verified() {
		t.Fatalf("image = %#v", img)
	}
	for _, m := range msgs {
		if strings.Contains(m, "calculating source archive SHA-256") {
			t.Fatal("docker temp tar must not be hashed")
		}
	}
	tmps, _ := filepath.Glob(filepath.Join(os.TempDir(), "bongsu-image-*.tar"))
	for _, tmp := range tmps {
		if st, err := os.Stat(tmp); err == nil && time.Since(st.ModTime()) < time.Minute {
			t.Fatalf("temp file left behind: %s", tmp)
		}
	}
}

func TestContainerTargetUsesExport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake")
	}
	// docker export output: flat rootfs including the writable layer (curl).
	export := buildTar(t, []tarEntry{
		{name: ".dockerenv", data: nil},
		{name: "lib/apk/db/installed", data: []byte(apkDB)},
		{name: "etc/os-release", data: []byte("ID=alpine\nVERSION_ID=3.20.3\n")},
	})
	log := fakeDocker(t, nil, export)
	r, err := Target(context.Background(), "container://bscan-1d", Options{})
	if err != nil {
		t.Fatal(err)
	}
	calls := readLog(t, log)
	if len(calls) != 3 {
		t.Fatalf("calls = %q", calls)
	}
	if calls[0] != "container inspect --format {{.Id}}|{{.Image}}|{{.Name}}|{{.State.Status}} -- bscan-1d" {
		t.Fatalf("inspect call = %q", calls[0])
	}
	if !strings.HasPrefix(calls[1], "export -o ") || !strings.HasSuffix(calls[1], " -- abcdef0123456789") {
		t.Fatalf("export call = %q", calls[1])
	}
	if !strings.HasPrefix(calls[2], "image inspect --format {{json .}} -- sha256:") {
		t.Fatalf("image inspect call = %q", calls[2])
	}
	if r.SourceType != "container" || r.Source != "container://bscan-1d" || r.SourceHash != "" || r.Layers != nil {
		t.Fatalf("result = %s %s hash=%q layers=%v", r.SourceType, r.Source, r.SourceHash, r.Layers)
	}
	if got := packageVersions(r); got["curl"] != "8.9.0-r0" {
		t.Fatalf("writable-layer package missing: %v", got)
	}
	img := r.Image
	if img == nil || img.ContainerID != "abcdef0123456789" || !strings.HasPrefix(img.ID, "sha256:") || img.Layers != nil || img.OS != "linux" || len(img.Tags) != 1 {
		t.Fatalf("image = %#v", img)
	}
	_, err = Target(context.Background(), "container://missing", Options{})
	if err == nil || !strings.Contains(err.Error(), "No such container: missing") {
		t.Fatalf("daemon error must be surfaced: %v", err)
	}
	tmps, _ := filepath.Glob(filepath.Join(os.TempDir(), "bongsu-container-*.tar"))
	for _, tmp := range tmps {
		if st, err := os.Stat(tmp); err == nil && time.Since(st.ModTime()) < time.Minute {
			t.Fatalf("temp file left behind: %s", tmp)
		}
	}
}

func TestSeekableOuterOffsets(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 3000)
	outer := buildTar(t, []tarEntry{
		{name: "a", data: []byte("aaa")},
		{name: "dir/", typeflag: tar.TypeDir},
		{name: "b", data: big},
		{name: "c", typeflag: tar.TypeLink, link: "a"},
		{name: "d", data: nil},
	})
	p := writeTemp(t, "outer.tar", outer)
	a, err := indexOuter(context.Background(), p, formatTar, false, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if !a.seekable || len(a.entries) != 4 {
		t.Fatalf("entries = %#v", a.entries)
	}
	for name, want := range map[string][]byte{"a": []byte("aaa"), "b": big, "c": []byte("aaa"), "d": {}} {
		got, err := a.bytes(name)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s = %q (%v)", name, got, err)
		}
	}
}

func TestCompressedOuterArchiveSpillsLargeBlobsToDisk(t *testing.T) {
	// A layer above maxMetadata inside a gzip-compressed outer archive must be
	// buffered through a temp file (the outer stream is not seekable).
	big := bytes.Repeat([]byte{0}, maxMetadata+4096)
	layer := buildTar(t, []tarEntry{{name: "usr/share/blob.bin", data: big}, {name: "etc/os-release", data: []byte("ID=alpine\n")}})
	p := writeTemp(t, "big.tgz", gzipBytes(t, dockerArchive(t, layer)))
	r, err := Archive(p, Options{Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if f := filesByPath(r)["usr/share/blob.bin"]; f.Size != int64(len(big)) || f.SHA256 != strings.TrimPrefix(digestOf(big), "sha256:") {
		t.Fatalf("large entry = %#v", f)
	}
	if !r.Image.Verified() || r.OSName != "alpine" {
		t.Fatalf("image = %#v os=%s", r.Image, r.OSName)
	}
	leftovers, _ := filepath.Glob(filepath.Join(os.TempDir(), "bongsu-archive-*"))
	for _, d := range leftovers {
		if st, err := os.Stat(d); err == nil && time.Since(st.ModTime()) < time.Minute {
			t.Fatalf("temp dir left behind: %s", d)
		}
	}
}

func TestBinaryHardlinkKeepsOwnAttribution(t *testing.T) {
	u := newUnpacker(context.Background(), Options{})
	u.fs["bin/original"] = File{Path: "bin/original"}
	u.binaries["bin/original"] = []Package{{Name: "stdlib", Type: "golang", Version: "1.25.0", Source: "bin/original", Layer: "base"}}
	data := buildTar(t, []tarEntry{{name: "bin/alias", typeflag: tar.TypeLink, link: "bin/original"}})
	if err := u.applyTar(bytes.NewReader(data), "upper"); err != nil {
		t.Fatal(err)
	}
	if got := u.binaries["bin/alias"][0]; got.Source != "bin/alias" || got.Layer != "upper" {
		t.Fatalf("alias attribution: %+v", got)
	}
	if got := u.binaries["bin/original"][0]; got.Source != "bin/original" || got.Layer != "base" {
		t.Fatalf("original attribution changed: %+v", got)
	}
}

func TestArchiveMetadataAliasesRestoreArbitraryTargets(t *testing.T) {
	osData := []byte("ID=alpine\nVERSION_ID=3.20.3\n")
	base := buildTar(t, []tarEntry{
		{name: "payload/os.txt", data: osData},
		{name: "payload/packages.txt", data: []byte(apkDB)},
	})
	links := []tarEntry{
		{name: "etc/os-release", typeflag: tar.TypeSymlink, link: "../aliases/os"},
		{name: "aliases/os", typeflag: tar.TypeSymlink, link: "../payload/os.txt"},
		{name: "lib/apk/db/installed", typeflag: tar.TypeLink, link: "payload/packages.txt"},
		// A hard link must preserve its original inode when its target changes.
		{name: "payload/packages.txt", data: []byte("replacement without package records")},
	}
	upper := buildTar(t, links)
	root := buildTar(t, append([]tarEntry{
		// Symlink order is independent of the target's position in the tar.
		{name: "etc/os-release", typeflag: tar.TypeSymlink, link: "../aliases/os"},
		{name: "payload/os.txt", data: osData},
		{name: "payload/packages.txt", data: []byte(apkDB)},
	}, links...))
	entries := map[string][]byte{}
	desc := ociBlobs(t, entries, ociImage{
		layers:  [][]byte{gzipBytes(t, base), gzipBytes(t, upper)},
		diffIDs: []string{digestOf(base), digestOf(upper)},
	}, nil)
	oci := ociLayoutTar(t, entries, ociIndex{MediaType: mediaTypeOCIIndex, Manifests: []ociDescriptor{desc}})
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"root.tar", root},
		{"root.tar.gz", gzipBytes(t, root)},
		{"docker.tar", dockerArchive(t, base, upper)},
		{"docker.tar.gz", gzipBytes(t, dockerArchive(t, base, upper))},
		{"oci.tar", oci},
		{"oci.tar.gz", gzipBytes(t, oci)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Archive(writeTemp(t, tc.name, tc.data), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if r.OSName != "alpine" || r.OSVersion != "3.20.3" {
				t.Fatalf("OS = %s %s", r.OSName, r.OSVersion)
			}
			if got := packageVersions(r)["musl"]; got != "1.2.5-r0" {
				t.Fatalf("linked package DB lost: musl=%q", got)
			}
			files := filesByPath(r)
			if !bytes.Equal(files["etc/os-release"].Data, osData) || string(files["lib/apk/db/installed"].Data) != apkDB {
				t.Fatal("metadata alias contents missing")
			}
			if files["payload/os.txt"].Data != nil || files["payload/packages.txt"].Data != nil {
				t.Fatal("non-metadata target contents unnecessarily retained")
			}
		})
	}
}

func TestMetadataAliasRespectsFinalLayerTargets(t *testing.T) {
	base := buildTar(t, []tarEntry{
		{name: "payload/os.txt", data: []byte("ID=old\n")},
		{name: "etc/os-release", typeflag: tar.TypeSymlink, link: "../payload/os.txt"},
		{name: "payload/db.txt", data: []byte(apkDB)},
		{name: "lib/apk/db/installed", typeflag: tar.TypeLink, link: "payload/db.txt"},
	})
	for _, tc := range []struct {
		name             string
		upper            []tarEntry
		wantOS, wantMusl string
	}{
		{"replace-target", []tarEntry{{name: "payload/os.txt", data: []byte("ID=new\n")}, {name: "payload/.wh.db.txt"}}, "new", "1.2.5-r0"},
		{"remove-alias", []tarEntry{{name: "lib/apk/db/.wh.installed"}, {name: "payload/.wh.os.txt"}}, "", ""},
		{"replace-alias", []tarEntry{{name: "etc/os-release", data: []byte("ID=direct\n")}, {name: "lib/apk/db/installed", data: []byte("P:other\nV:1\n\n")}}, "direct", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Archive(writeTemp(t, "image.tar", dockerArchive(t, base, buildTar(t, tc.upper))), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if r.OSName != tc.wantOS || packageVersions(r)["musl"] != tc.wantMusl {
				t.Fatalf("OS=%q packages=%v", r.OSName, packageVersions(r))
			}
		})
	}
}

func TestMetadataAliasRereadIsLazyAndChecksOriginalContent(t *testing.T) {
	original := buildTar(t, []tarEntry{{name: "payload/data.txt", data: []byte("ID=alpine\n")}})
	for _, withAlias := range []bool{false, true} {
		t.Run(fmt.Sprintf("alias=%t", withAlias), func(t *testing.T) {
			u := newUnpacker(context.Background(), Options{})
			reopened := 0
			reopen := func() (io.Reader, func(), error) {
				reopened++
				// A modified rootfs source must not supply unchecked new bytes.
				changed := buildTar(t, []tarEntry{{name: "payload/data.txt", data: []byte("ID=debian\n")}})
				return bytes.NewReader(changed), func() {}, nil
			}
			if err := u.applyTarSource(bytes.NewReader(original), "", reopen); err != nil {
				t.Fatal(err)
			}
			if u.fs["payload/data.txt"].Data != nil {
				t.Fatal("ordinary file retained in memory")
			}
			if withAlias {
				u.symlinks["etc/os-release"] = symlinkRec{target: "payload/data.txt"}
			}
			err := u.finish()
			if withAlias {
				if err == nil || !strings.Contains(err.Error(), "source content for etc/os-release changed") || reopened != 1 {
					t.Fatalf("reread=%d err=%v", reopened, err)
				}
			} else if err != nil || reopened != 0 {
				t.Fatalf("unneeded reread=%d err=%v", reopened, err)
			}
		})
	}
}
