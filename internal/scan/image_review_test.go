package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImageReviewOuterRetention(t *testing.T) {
	blob := bytes.Repeat([]byte{0}, 8<<20)
	var entries []tarEntry
	for i := 0; i < 12; i++ {
		entries = append(entries, tarEntry{name: fmt.Sprintf("blobs/sha256/%064x", i), data: blob})
	}
	layer := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=alpine\n")}})
	entries = append(entries, tarEntry{name: "layer.tar", data: layer}, tarEntry{name: "config.json", data: []byte(`{"os":"linux","architecture":"amd64"}`)}, tarEntry{name: "manifest.json", data: mustJSON(t, []dockerManifest{{Config: "config.json", Layers: []string{"layer.tar"}}})})
	p := writeTemp(t, "outer.gz", gzipBytes(t, buildTar(t, entries)))
	a, err := indexOuter(context.Background(), p, formatGzip, true, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// Exercise retention separately from the cumulative decompression limit.
	a.budget = 128
	u := newUnpacker(context.Background(), Options{})
	if _, _, err := u.unpackDockerArchive(a); err != nil {
		t.Fatal(err)
	}
	var retained int
	for name, e := range a.entries {
		retained += len(e.data)
		if strings.HasPrefix(name, "blobs/") && (e.data != nil || e.temp != "") {
			t.Errorf("unreferenced blob retained: %s", name)
		}
	}
	if retained > 128 {
		t.Fatalf("retained %d bytes, budget 128", retained)
	}
	if a.entries["layer.tar"].temp == "" {
		t.Fatal("selected layer exceeding budget was not spilled")
	}
	if string(u.fs["etc/os-release"].Data) != "ID=alpine\n" {
		t.Fatal("selected layer lost")
	}
}

func TestImageReviewDockerConfigDigest(t *testing.T) {
	cfg := []byte(`{"os":"linux","architecture":"amd64"}`)
	name := digestPath("sha256:" + strings.Repeat("0", 64))
	p := writeTemp(t, "config.tar", buildTar(t, []tarEntry{{name: "manifest.json", data: mustJSON(t, []dockerManifest{{Config: name}})}, {name: name, data: cfg}}))
	if _, err := Archive(p, Options{}); err == nil || !strings.Contains(err.Error(), "config") || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered config: %v", err)
	}
	var msgs []string
	r, err := Archive(p, Options{AllowDigestMismatch: true, Progress: func(e Progress) { msgs = append(msgs, e.Message) }})
	if err != nil || r.Image.ID != digestOf(cfg) || !strings.Contains(strings.Join(msgs, "\n"), "verified=false") {
		t.Fatalf("allowed mismatch: result=%+v messages=%v err=%v", r.Image, msgs, err)
	}
}

func TestImageReviewDockerIndexDigest(t *testing.T) {
	cfg := []byte(`{"os":"linux","architecture":"amd64"}`)
	manifestRaw := mustJSON(t, ociManifest{Config: ociDescriptor{Digest: digestOf(cfg)}})
	for _, tc := range []struct {
		name     string
		body     []byte
		present  bool
		verified bool
	}{
		{"missing", nil, false, false}, {"tampered", []byte(`{}`), true, false}, {"valid", manifestRaw, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ociDescriptor{MediaType: mediaTypeOCIManifest, Digest: digestOf(manifestRaw)}
			entries := []tarEntry{{name: "config.json", data: cfg}, {name: "manifest.json", data: mustJSON(t, []dockerManifest{{Config: "config.json"}})}, {name: "index.json", data: mustJSON(t, ociIndex{Manifests: []ociDescriptor{d}})}}
			if tc.present {
				entries = append(entries, tarEntry{name: digestPath(d.Digest), data: tc.body})
			}
			var msgs []string
			r, err := Archive(writeTemp(t, "index.tar", buildTar(t, entries)), Options{Progress: func(e Progress) { msgs = append(msgs, e.Message) }})
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if tc.verified {
				want = d.Digest
			}
			if r.Image.Digest != want || !strings.Contains(strings.Join(msgs, "\n"), fmt.Sprintf("verified=%t", tc.verified)) {
				t.Fatalf("digest=%q messages=%v", r.Image.Digest, msgs)
			}
		})
	}
}

func TestImageReviewMissingTMPDIR(t *testing.T) {
	p := writeTemp(t, "outer.gz", gzipBytes(t, dockerArchive(t, buildTar(t, nil))))
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing", "temp"))
	if _, err := Archive(p, Options{}); err == nil {
		t.Fatal("expected temporary directory error")
	}
}

type imageCancelReader struct {
	rd        io.Reader
	cancel    context.CancelFunc
	remaining int
	read      int
}

func (r *imageCancelReader) Read(p []byte) (int, error) {
	if r.remaining > 0 && len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.rd.Read(p)
	r.read += n
	r.remaining -= n
	if r.remaining <= 0 {
		r.cancel()
	}
	return n, err
}

func TestImageReviewCancellation(t *testing.T) {
	for _, mode := range []string{"file-hash", "layer-tail", "archive-return"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			u := newUnpacker(ctx, Options{})
			var err error
			if mode == "archive-return" {
				p := writeTemp(t, "root.tar", buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=alpine\n")}}))
				_, err = archiveContext(ctx, p, Options{Progress: func(e Progress) {
					if strings.Contains(e.Message, "catalog complete") {
						cancel()
					}
				}})
			} else {
				data := bytes.Repeat([]byte{0}, 4<<20)
				if mode == "layer-tail" {
					data = append(buildTar(t, nil), data...)
				}
				rd := &imageCancelReader{rd: bytes.NewReader(data), cancel: cancel, remaining: 2 << 20}
				if mode == "file-hash" {
					_, err = u.readEntry("large.bin", rd, &tar.Header{Size: int64(len(data))}, "")
				} else {
					_, err = u.applyLayer(rd, int64(len(data)), layerCheck{name: "tail"})
				}
				if rd.read > 3<<20 {
					t.Errorf("read past cancellation: %d", rd.read)
				}
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation ignored: %v", err)
			}
		})
	}
}

func TestImageReviewEntryTypeReplacement(t *testing.T) {
	base := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=old\n")}, {name: "tree/", typeflag: tar.TypeDir}, {name: "tree/child", data: []byte("old")}, {name: "implicit/child", data: []byte("old")}})
	for _, kind := range []byte{tar.TypeReg, tar.TypeLink, tar.TypeSymlink} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			upper := buildTar(t, []tarEntry{{name: "etc/os-release/", typeflag: tar.TypeDir}, {name: "target", data: []byte("new")}, {name: "tree", typeflag: kind, link: "target"}, {name: "implicit", typeflag: kind, link: "target"}})
			r, err := Archive(writeTemp(t, "types.tar", dockerArchive(t, base, upper)), Options{})
			if err != nil {
				t.Fatal(err)
			}
			files := filesByPath(r)
			for _, name := range []string{"etc/os-release", "tree/child", "implicit/child"} {
				if _, ok := files[name]; ok {
					t.Errorf("stale record: %s", name)
				}
			}
			if r.OSName != "" {
				t.Fatalf("stale OS: %s", r.OSName)
			}
		})
	}
}

func TestImageReviewPlatformlessConfig(t *testing.T) {
	for _, found := range []*ociPlatform{{OS: "windows", Architecture: "amd64"}, {OS: "linux", Architecture: "arm64"}, {OS: "linux", Architecture: "arm", Variant: "v6"}} {
		t.Run(found.String(), func(t *testing.T) {
			entries := map[string][]byte{}
			d := ociBlobs(t, entries, ociImage{platform: found}, nil)
			d.Platform = nil
			want := "linux/amd64"
			if found.Architecture == "arm" {
				want = "linux/arm/v7"
			}
			_, err := Archive(writeTemp(t, "platform.tar", ociLayoutTar(t, entries, ociIndex{Manifests: []ociDescriptor{d}})), Options{Platform: want})
			if err == nil || !strings.Contains(err.Error(), found.String()) || !strings.Contains(err.Error(), want) {
				t.Fatalf("platform mismatch: %v", err)
			}
		})
	}
	// The first platform-less candidate may mismatch while a later one matches.
	entries := map[string][]byte{}
	a := ociBlobs(t, entries, ociImage{platform: &ociPlatform{OS: "linux", Architecture: "arm64"}}, nil)
	a.Platform = nil
	b := ociBlobs(t, entries, ociImage{platform: &ociPlatform{OS: "linux", Architecture: "amd64"}}, nil)
	b.Platform = nil
	r, err := Archive(writeTemp(t, "matches.tar", ociLayoutTar(t, entries, ociIndex{Manifests: []ociDescriptor{a, b}})), Options{Platform: "linux/amd64"})
	if err != nil || r.Image.Architecture != "amd64" {
		t.Fatalf("matching config not selected: %+v %v", r.Image, err)
	}
}

func TestImageReviewLayerTarMagic(t *testing.T) {
	layer := buildTar(t, []tarEntry{{name: "BZh-not-compressed.txt", data: []byte("ID=alpine\n")}, {name: "etc/os-release", typeflag: tar.TypeSymlink, link: "../BZh-not-compressed.txt"}})
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprint(compressed), func(t *testing.T) {
			data := dockerArchive(t, layer)
			if compressed {
				data = gzipBytes(t, data)
			}
			r, err := Archive(writeTemp(t, "magic.tar", data), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if r.OSName != "alpine" {
				t.Fatalf("reopened tar metadata lost: %s", r.OSName)
			}
		})
	}
}

func TestImageReviewOversizedLayerFile(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: "huge.bin", Mode: 0600, Size: (16 << 30) + 1}); err != nil {
		t.Fatal(err)
	}
	u := newUnpacker(context.Background(), Options{})
	_, err := u.applyLayer(bytes.NewReader(gzipBytes(t, b.Bytes())), 0, layerCheck{name: "oversized"})
	if err == nil || !strings.Contains(err.Error(), "decompression limit exceeded") {
		t.Fatalf("oversized layer: %v", err)
	}
}

func TestImageReviewLayerSourceTarMagic(t *testing.T) {
	// A valid ustar filename can even begin with gzip's two magic bytes.
	// Construct that header directly because tar.Writer rejects non-UTF-8 names.
	data := buildTar(t, []tarEntry{{name: "xx-file", data: []byte("payload")}})
	data[0], data[1] = 0x1f, 0x8b
	for i := 148; i < 156; i++ {
		data[i] = ' '
	}
	var sum int
	for _, b := range data[:512] {
		sum += int(b)
	}
	copy(data[148:156], fmt.Sprintf("%06o\x00 ", sum))
	a := &outerArchive{entries: map[string]outerEntry{"layer": {data: data, Size: int64(len(data))}}}
	rd, done, err := layerSource(a, "layer")()
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	got, err := io.ReadAll(rd)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("ustar falsely decompressed on reopen: %v", err)
	}
}

func TestImageReviewUnwritableTMPDIR(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	p := writeTemp(t, "outer.gz", gzipBytes(t, dockerArchive(t, buildTar(t, nil))))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	t.Setenv("TMPDIR", dir)
	if _, err := Archive(p, Options{}); err == nil {
		t.Fatal("expected temporary directory permission error")
	}
}

func TestImageReviewDecompressionBudget(t *testing.T) {
	// Exercise the production counting reader at a small budget: individually
	// small files and trailing tar padding must count towards the same limit.
	for _, tc := range []struct {
		name    string
		data    []byte
		limit   int64
		exceeds bool
	}{
		{"exact", buildTar(t, nil), 1024, false},
		{"tail", append(buildTar(t, nil), make([]byte, 1024)...), 1024, true},
		{"aggregate", buildTar(t, []tarEntry{{name: "a.bin", data: make([]byte, 600)}, {name: "b.bin", data: make([]byte, 600)}}), 2048, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gz, err := gzip.NewReader(bytes.NewReader(gzipBytes(t, tc.data)))
			if err != nil {
				t.Fatal(err)
			}
			defer gz.Close()
			rd := &decompressionReader{rd: gz, remaining: tc.limit}
			u := newUnpacker(context.Background(), Options{})
			_, err = u.applyLayer(rd, 0, layerCheck{name: tc.name})
			if tc.exceeds {
				if err == nil || !strings.Contains(err.Error(), "decompression limit exceeded") {
					t.Fatalf("budget ignored: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestImageReviewOuterSmallBlobBudget(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1<<20)
	p := writeTemp(t, "small.gz", gzipBytes(t, buildTar(t, []tarEntry{{name: "a", data: data}, {name: "b", data: data}, {name: "c", data: data}})))
	a, err := indexOuter(context.Background(), p, formatGzip, true, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.budget = 1500 << 10
	for _, name := range []string{"a", "b", "c"} {
		rd, done, err := a.open(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rd)
		done()
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%s contents: %v", name, err)
		}
	}
	if a.entries["a"].data == nil || a.entries["b"].temp == "" || a.entries["c"].temp == "" {
		t.Fatal("small entries did not share retention budget")
	}
}
