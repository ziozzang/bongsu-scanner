package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/purl"
)

// fuzzTar writes entries in order; typeflag zero is a regular file whose
// size is len(data). Errors cannot happen for in-memory writes.
func fuzzTar(entries []tarEntry) []byte {
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
		if tw.WriteHeader(h) != nil {
			continue
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write(e.data)
		}
	}
	_ = tw.Close()
	return b.Bytes()
}

func fuzzGzip(data []byte) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	_, _ = gz.Write(data)
	_ = gz.Close()
	return b.Bytes()
}

func fuzzJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// fuzzRawTarHeader forges one 512-byte ustar header with arbitrary size and
// type fields so tar readers see values a writer would never produce.
func fuzzRawTarHeader(name, size string, typeflag byte, link string) []byte {
	h := make([]byte, 512)
	copy(h[0:], name)
	copy(h[100:], "0000644")
	copy(h[108:], "0000000")
	copy(h[116:], "0000000")
	copy(h[124:], size)
	copy(h[136:], "00000000000")
	copy(h[148:], "        ")
	h[156] = typeflag
	copy(h[157:], link)
	copy(h[257:], "ustar\x00")
	copy(h[263:], "00")
	var sum int
	for _, c := range h {
		sum += int(c)
	}
	copy(h[148:], fmt.Sprintf("%06o\x00 ", sum))
	return h
}

const fuzzDpkgStatus = "Package: curl\nStatus: install ok installed\nVersion: 8.14.1-2\nArchitecture: amd64\n\n"

func fuzzLayerSeeds() [][]byte {
	base := fuzzTar([]tarEntry{
		{name: "etc/", typeflag: tar.TypeDir},
		{name: "etc/os-release", data: []byte("ID=debian\nVERSION_ID=\"13\"\n")},
		{name: "var/lib/dpkg/status", data: []byte(fuzzDpkgStatus)},
		{name: "usr/lib/os-release", data: []byte("ID=other\n")},
		{name: "etc/alias-release", typeflag: tar.TypeSymlink, link: "../usr/lib/os-release"},
		{name: "var/lib/dpkg/status-link", typeflag: tar.TypeLink, link: "var/lib/dpkg/status"},
		{name: "app/node_modules/lodash/package.json", data: []byte(`{"name":"lodash","version":"4.17.21"}`)},
		{name: "usr/bin/tool", mode: 0o755, data: []byte("\x7fELF\x02\x01\x01garbage")},
	})
	whiteouts := fuzzTar([]tarEntry{
		{name: "var/lib/dpkg/.wh.status"},
		{name: "etc/.wh..wh..opq"},
		{name: ".wh..wh..opq"},
		{name: "../escape", data: []byte("x")},
		{name: "/abs/etc/os-release", data: []byte("ID=alpine\n")},
		{name: "loop", typeflag: tar.TypeSymlink, link: "loop"},
		{name: "a", typeflag: tar.TypeSymlink, link: "b"},
		{name: "b", typeflag: tar.TypeSymlink, link: "a"},
		{name: "etc/os-release", typeflag: tar.TypeSymlink, link: "/../../x"},
		{name: "var/lib/rpm/Packages", data: rpmTestBDB(rpmTestHeader(0), binary.LittleEndian, false)},
		{name: "lib/x.jar", data: fuzzZip(map[string][]byte{"META-INF/MANIFEST.MF": []byte("Implementation-Version: 1\r\n")}, []string{"META-INF/MANIFEST.MF"})},
		{name: "dir-then-file", typeflag: tar.TypeDir},
		{name: "dir-then-file/child", data: []byte("x")},
		{name: "dir-then-file", data: []byte("now a file")},
	})
	pax := fuzzTar([]tarEntry{
		{name: strings.Repeat("longdir/", 40) + "etc/os-release", data: []byte("ID=debian\n")},
		{name: "etc/os-release", typeflag: tar.TypeSymlink, link: strings.Repeat("../", 3) + "usr/lib/os-release"},
	})
	// Declared sizes that exceed the archive, negative sizes and odd types.
	truncated := append(fuzzRawTarHeader("var/lib/dpkg/status", "00000001000", tar.TypeReg, ""), []byte(fuzzDpkgStatus)...)
	negative := append(fuzzRawTarHeader("etc/os-release", "-0000000100", tar.TypeReg, ""), make([]byte, 1024)...)
	weird := bytes.Join([][]byte{
		fuzzRawTarHeader("etc/os-release", "00000000005", tar.TypeChar, ""), fuzzRawTarHeader("fifo", "00000000000", tar.TypeFifo, ""),
		fuzzRawTarHeader("hard", "00000000000", tar.TypeLink, "missing"), fuzzRawTarHeader("etc/os-release", "00000000012", 0, ""), append([]byte("ID=debian\n\n"), make([]byte, 500)...),
		make([]byte, 1024),
	}, nil)
	return [][]byte{base, whiteouts, pax, truncated, negative, weird, {}}
}

func fuzzCheckPackages(t *testing.T, pkgs []Package) {
	t.Helper()
	for _, p := range pkgs {
		if strings.TrimSpace(p.Name) == "" || p.PURL == "" {
			t.Fatalf("package without identity: %+v", p)
		}
		if _, err := purl.Parse(p.PURL); err != nil {
			t.Fatalf("purl %q: %v", p.PURL, err)
		}
	}
}

func FuzzApplyTar(f *testing.F) {
	for _, seed := range fuzzLayerSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		u := newUnpacker(context.Background(), Options{})
		defer u.Close()
		reopen := func() (io.Reader, func(), error) { return bytes.NewReader(data), func() {}, nil }
		if err := u.applyTarSource(bytes.NewReader(data), "layer0", reopen); err != nil {
			return
		}
		// A second application of the same bytes exercises whiteouts and
		// replacement of every path kind against a populated filesystem.
		_ = u.applyTarSource(bytes.NewReader(data), "layer1", reopen)
		for name, rec := range u.fs {
			if unsafePath(name) || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
				t.Fatalf("unsafe path %q retained", name)
			}
			if rec.Path != name {
				t.Fatalf("record path %q under key %q", rec.Path, name)
			}
			if rec.Data != nil && int64(len(rec.Data)) != rec.Size {
				t.Fatalf("%s: retained %d bytes for declared size %d", name, len(rec.Data), rec.Size)
			}
		}
		for name := range u.symlinks {
			if unsafePath(name) || unsafePath(u.symlinks[name].target) {
				t.Fatalf("unsafe symlink %q -> %q", name, u.symlinks[name].target)
			}
		}
		// Every retained path is registered in kinds, and the child index
		// mirrors kinds exactly in both directions.
		for _, m := range []map[string]bool{fuzzKeys(u.fs), fuzzKeys(u.symlinks), fuzzKeys(u.binaries)} {
			for name := range m {
				if _, ok := u.kinds[name]; !ok {
					t.Fatalf("%q retained without a kind", name)
				}
			}
		}
		for name := range u.kinds {
			if _, ok := u.children[parentDir(name)][name]; !ok {
				t.Fatalf("%q missing from its parent's child index", name)
			}
		}
		for dir, set := range u.children {
			for child := range set {
				if _, ok := u.kinds[child]; !ok || parentDir(child) != dir {
					t.Fatalf("stale child %q under %q", child, dir)
				}
			}
		}
		if err := u.finish(); err != nil {
			return
		}
		r := assembleRPMResult("fuzz", "fuzz", "archive", u.fs, nil, nil, u.extraPackages(), time.Time{}, Options{}, u.rpmFiles)
		fuzzCheckPackages(t, r.Packages)
	})
}

func fuzzKeys[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func fuzzArchiveSeeds() [][]byte {
	layer := fuzzTar([]tarEntry{
		{name: "etc/os-release", data: []byte("ID=alpine\nVERSION_ID=3.20.3\n")},
		{name: "lib/apk/db/installed", data: []byte(apkDB)},
	})
	blob := fuzzGzip(layer)
	// Docker save layout.
	cfg := fuzzJSON(map[string]any{"os": "linux", "architecture": "amd64", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{digestOf(layer)}}})
	docker := fuzzTar([]tarEntry{
		{name: "manifest.json", data: fuzzJSON([]dockerManifest{{Config: "config.json", Layers: []string{"l0/layer.tar"}, RepoTags: []string{"alpine:3.20"}}})},
		{name: "config.json", data: cfg},
		{name: "l0/layer.tar", data: layer},
	})
	// OCI layout with a nested index and an attestation manifest.
	entries := map[string][]byte{}
	cfgDigest := digestOf(cfg)
	entries[digestPath(cfgDigest)] = cfg
	entries[digestPath(digestOf(blob))] = blob
	manifest := fuzzJSON(ociManifest{MediaType: mediaTypeOCIManifest,
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: cfgDigest, Size: int64(len(cfg))},
		Layers: []ociDescriptor{{MediaType: mediaTypeOCILayerGzip, Digest: digestOf(blob), Size: int64(len(blob))}}})
	entries[digestPath(digestOf(manifest))] = manifest
	nested := fuzzJSON(ociIndex{MediaType: mediaTypeOCIIndex, Manifests: []ociDescriptor{
		{MediaType: mediaTypeOCIManifest, Digest: digestOf(manifest), Size: int64(len(manifest)), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"}},
		{MediaType: mediaTypeOCIManifest, Digest: digestOf(manifest), Size: int64(len(manifest)), Platform: &ociPlatform{OS: "unknown", Architecture: "unknown"}, Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"}},
	}})
	entries[digestPath(digestOf(nested))] = nested
	entries["oci-layout"] = []byte(`{"imageLayoutVersion":"1.0.0"}`)
	entries["index.json"] = fuzzJSON(ociIndex{MediaType: mediaTypeOCIIndex, Manifests: []ociDescriptor{{MediaType: mediaTypeOCIIndex, Digest: digestOf(nested), Size: int64(len(nested)), Annotations: map[string]string{"org.opencontainers.image.ref.name": "alpine:3.20"}}}})
	var list []tarEntry
	for name, data := range entries {
		list = append(list, tarEntry{name: name, data: data})
	}
	oci := fuzzTar(list)
	// Manifest pointing at a missing config and a manifest.json that is not JSON.
	broken := fuzzTar([]tarEntry{{name: "manifest.json", data: []byte(`[{"Config":"missing.json","Layers":["nope"]}]`)}})
	notJSON := fuzzTar([]tarEntry{{name: "index.json", data: []byte("{")}, {name: "manifest.json", data: []byte("[")}})
	return [][]byte{docker, fuzzGzip(docker), oci, layer, fuzzGzip(layer), broken, notJSON, fuzzGzip([]byte("not a tar")), {0x28, 0xb5, 0x2f, 0xfd, 0, 0}, []byte("BZh9garbage"), {}}
}

func FuzzArchive(f *testing.F) {
	for _, seed := range fuzzArchiveSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		file := filepath.Join(dir, "image.tar")
		if err := os.WriteFile(file, data, 0o644); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		for _, opts := range []Options{{skipSourceHash: true}, {skipSourceHash: true, AllowDigestMismatch: true, Platform: "linux/amd64"}} {
			r, err := archiveContext(ctx, file, opts)
			if err != nil {
				continue
			}
			fuzzCheckPackages(t, r.Packages)
			if r.Image != nil {
				for _, l := range r.Image.Layers {
					if l.Digest == "" {
						t.Fatalf("layer without digest: %+v", l)
					}
				}
			}
		}
		if r, err := rootfsArchive(ctx, file, Options{skipSourceHash: true}); err == nil {
			fuzzCheckPackages(t, r.Packages)
		}
	})
}

func FuzzPlatformAndDigests(f *testing.F) {
	f.Add("linux/amd64", "sha256:abc", "blobs/sha256/"+strings.Repeat("a", 64))
	f.Add("LINUX/x86_64/v8", "", strings.Repeat("0", 64)+".json")
	f.Add("//", ":", "")
	f.Fuzz(func(t *testing.T, platform, digest, name string) {
		p, err := parsePlatform(platform)
		if err == nil && (p.os == "" || p.arch == "") {
			t.Fatalf("parsePlatform(%q) accepted empty component: %+v", platform, p)
		}
		_ = p.String()
		_ = p.matches(&ociPlatform{OS: p.os, Architecture: p.arch})
		_ = digestPath(digest)
		_ = blobDigestFromPath(name)
		_ = dockerConfigDigest(name)
		_ = clean(name)
		_ = resolveLink(name, digest)
		if target := resolveLink(name, digest); target != "" && unsafePath(target) {
			t.Fatalf("resolveLink(%q, %q) = %q escapes root", name, digest, target)
		}
	})
}

// TestImageLayerReferenceLimits pins the bound on repeated layer and
// manifest references: a small archive must not be able to request the same
// blob to be decompressed hundreds of thousands of times.
func TestImageLayerReferenceLimits(t *testing.T) {
	layer := fuzzTar([]tarEntry{{name: "etc/os-release", data: []byte("ID=alpine\n")}})
	refs := make([]string, maxImageLayers+1)
	for i := range refs {
		refs[i] = "l0/layer.tar"
	}
	docker := fuzzTar([]tarEntry{
		{name: "manifest.json", data: fuzzJSON([]dockerManifest{{Layers: refs}})},
		{name: "l0/layer.tar", data: layer},
	})
	file := filepath.Join(t.TempDir(), "docker.tar")
	if err := os.WriteFile(file, docker, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := archiveContext(context.Background(), file, Options{skipSourceHash: true}); err == nil || !strings.Contains(err.Error(), "layers") {
		t.Fatalf("docker archive with %d layer references accepted: %v", len(refs), err)
	}
	// OCI: an index listing too many manifests and a manifest listing too many layers.
	cfg := fuzzJSON(map[string]any{"os": "linux", "architecture": "amd64"})
	blob := fuzzGzip(layer)
	layers := make([]ociDescriptor, maxImageLayers+1)
	for i := range layers {
		layers[i] = ociDescriptor{MediaType: mediaTypeOCILayerGzip, Digest: digestOf(blob), Size: int64(len(blob))}
	}
	manifest := fuzzJSON(ociManifest{MediaType: mediaTypeOCIManifest, Config: ociDescriptor{Digest: digestOf(cfg), Size: int64(len(cfg))}, Layers: layers})
	desc := ociDescriptor{MediaType: mediaTypeOCIManifest, Digest: digestOf(manifest), Size: int64(len(manifest)), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"}}
	entries := map[string][]byte{digestPath(digestOf(cfg)): cfg, digestPath(digestOf(blob)): blob, digestPath(digestOf(manifest)): manifest}
	for name, want := range map[string]ociIndex{
		"layers": {Manifests: []ociDescriptor{desc}},
		"manifests": {Manifests: func() []ociDescriptor {
			out := make([]ociDescriptor, maxIndexManifests+1)
			for i := range out {
				out[i] = desc
			}
			return out
		}()},
	} {
		entries["index.json"] = fuzzJSON(want)
		var list []tarEntry
		for n, d := range entries {
			list = append(list, tarEntry{name: n, data: d})
		}
		file := filepath.Join(t.TempDir(), name+".tar")
		if err := os.WriteFile(file, fuzzTar(list), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := archiveContext(context.Background(), file, Options{skipSourceHash: true, Platform: "linux/amd64"}); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("OCI archive with excess %s accepted: %v", name, err)
		}
	}
}

// TestWhiteoutCostIsSubtreeBound builds one layer with many files and as
// many opaque whiteouts on distinct directories. Before the child index each
// whiteout rescanned every retained path, making such a layer quadratic.
func TestWhiteoutCostIsSubtreeBound(t *testing.T) {
	n := 20000
	if testing.Short() {
		n = 128
	}
	var lower, upper []tarEntry
	for i := 0; i < n; i++ {
		dir := fmt.Sprintf("d%d", i)
		lower = append(lower, tarEntry{name: dir + "/lower", data: []byte("x")})
		upper = append(upper, tarEntry{name: dir + "/.wh..wh..opq"}, tarEntry{name: dir + "/upper", data: []byte("y")})
	}
	u := newUnpacker(context.Background(), Options{})
	defer u.Close()
	start := time.Now()
	if err := u.applyTar(bytes.NewReader(fuzzTar(lower)), "l0"); err != nil {
		t.Fatal(err)
	}
	if err := u.applyTar(bytes.NewReader(fuzzTar(upper)), "l1"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("applying %d whiteouts took %s", n, d)
	}
	if len(u.fs) != n {
		t.Fatalf("expected %d upper files, found %d", n, len(u.fs))
	}
	for name := range u.fs {
		if !strings.HasSuffix(name, "/upper") {
			t.Fatalf("lower-layer file %s survived its opaque whiteout", name)
		}
	}
	// The index must track removals exactly: no stale child entries remain.
	for dir, set := range u.children {
		for child := range set {
			if _, ok := u.kinds[child]; !ok {
				t.Fatalf("stale child %s under %q", child, dir)
			}
		}
	}
	for name := range u.kinds {
		if _, ok := u.children[parentDir(name)][name]; !ok {
			t.Fatalf("%s missing from its parent's child index", name)
		}
	}
}
