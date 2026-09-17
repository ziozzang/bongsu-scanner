package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func zstdBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	enc, err := zstd.NewWriter(&b, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zstdSkip(data []byte, id byte) []byte {
	frame := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint32(frame, 0x184d2a50+uint32(id))
	binary.LittleEndian.PutUint32(frame[4:], uint32(len(data)))
	copy(frame[8:], data)
	return frame
}

func zstdOCI(t *testing.T, blob []byte, diffID, mediaType, declared string) []byte {
	t.Helper()
	entries := map[string][]byte{}
	d := ociBlobs(t, entries, ociImage{layers: [][]byte{blob}, diffIDs: []string{diffID}}, nil)
	var m ociManifest
	if err := json.Unmarshal(entries[digestPath(d.Digest)], &m); err != nil {
		t.Fatal(err)
	}
	m.Layers[0].MediaType = mediaType
	if declared != "" {
		m.Layers[0].Digest = declared
		entries[digestPath(declared)] = blob
	}
	raw := mustJSON(t, m)
	d.Digest, d.Size = digestOf(raw), int64(len(raw))
	entries[digestPath(d.Digest)] = raw
	return ociLayoutTar(t, entries, ociIndex{Manifests: []ociDescriptor{d}})
}

func TestZstdOCIAndOuterArchives(t *testing.T) {
	// Linked metadata forces a second streaming decode of the original layer.
	raw := buildTar(t, []tarEntry{
		{name: "payload", data: []byte(apkDB)},
		{name: "lib/apk/db/installed", typeflag: tar.TypeLink, link: "payload"},
		{name: "etc/os-release", data: []byte("ID=alpine\n")},
	})
	for _, skip := range []bool{false, true} {
		blob := zstdBytes(t, raw)
		if skip {
			// A leading frame larger than the 512-byte probe, and trailing frames,
			// must count toward the compressed digest but not the diff_id.
			blob = append(zstdSkip(make([]byte, 1024), 0), blob...)
			blob = append(blob, zstdSkip([]byte("tail"), 15)...)
		}
		for _, mt := range []string{"application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar.zstd", ""} {
			for _, outer := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/skip=%t/outer=%t", mt, skip, outer), func(t *testing.T) {
					data := zstdOCI(t, blob, digestOf(raw), mt, "")
					budget := int64(len(data))
					if outer {
						data = zstdBytes(t, data)
						if skip {
							data = append(zstdSkip([]byte("outer"), 7), data...)
						}
					}
					r, err := Archive(writeTemp(t, "image", data), Options{MaxTotalBytes: budget})
					if err != nil {
						t.Fatal(err)
					}
					if len(r.Image.Layers) != 1 {
						t.Fatalf("layers: %+v", r.Image)
					}
					li := r.Image.Layers[0]
					if !li.Verified || li.Digest != digestOf(blob) || li.DiffID != digestOf(raw) || li.Size != int64(len(blob)) {
						t.Fatalf("layer: %+v", li)
					}
					wantMedia := mt
					if wantMedia == "" {
						wantMedia = "application/vnd.oci.image.layer.v1.tar+zstd"
					}
					if li.MediaType != wantMedia {
						t.Fatalf("media type: %s", li.MediaType)
					}
					if got := packageVersions(r); got["musl"] != "1.2.5-r0" || got["curl"] != "8.9.0-r0" {
						t.Fatalf("packages: %v", got)
					}
					if r.SourceHash != strings.TrimPrefix(digestOf(data), "sha256:") {
						t.Fatal("compressed source digest mismatch")
					}
				})
			}
		}
	}
}

func TestZstdDigestMismatch(t *testing.T) {
	raw := buildTar(t, nil)
	blob := zstdBytes(t, raw)
	for _, kind := range []string{"digest", "diff_id"} {
		t.Run(kind, func(t *testing.T) {
			declared, diffID := "", digestOf(raw)
			bad := "sha256:" + strings.Repeat("ab", 32)
			if kind == "digest" {
				declared = bad
			} else {
				diffID = bad
			}
			p := writeTemp(t, "image", zstdOCI(t, blob, diffID, "application/vnd.oci.image.layer.v1.tar+zstd", declared))
			if _, err := Archive(p, Options{}); err == nil || !strings.Contains(err.Error(), kind+" mismatch") {
				t.Fatalf("mismatch: %v", err)
			}
			r, err := Archive(p, Options{AllowDigestMismatch: true})
			if err != nil {
				t.Fatal(err)
			}
			if r.Image.Layers[0].Verified {
				t.Fatal("mismatch marked verified")
			}
		})
	}
}

func TestZstdDockerAndRootfsReopen(t *testing.T) {
	raw := buildTar(t, []tarEntry{{name: "payload", data: []byte(apkDB)}, {name: "lib/apk/db/installed", typeflag: tar.TypeSymlink, link: "../../../payload"}})
	for _, kind := range []string{"docker", "rootfs", "rootfs-direct"} {
		t.Run(kind, func(t *testing.T) {
			data := zstdBytes(t, raw)
			if kind == "docker" {
				cfg := imageConfig{OS: "linux", Architecture: "amd64"}
				cfg.RootFS.Type, cfg.RootFS.DiffIDs = "layers", []string{digestOf(raw)}
				manifest := dockerManifest{Config: "config.json", Layers: []string{"layer.zst"}, LayerSources: map[string]ociDescriptor{
					digestOf(raw): {MediaType: "application/vnd.docker.image.rootfs.diff.tar.zstd", Digest: digestOf(data)},
				}}
				data = zstdBytes(t, buildTar(t, []tarEntry{
					{name: "layer.zst", data: data},
					{name: "config.json", data: mustJSON(t, cfg)},
					{name: "manifest.json", data: mustJSON(t, []dockerManifest{manifest})},
				}))
			}
			p := writeTemp(t, "image", data)
			var r Result
			var err error
			if kind == "rootfs-direct" {
				r, err = rootfsArchive(context.Background(), p, Options{})
			} else {
				r, err = Archive(p, Options{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "docker" && !r.Image.Layers[0].Verified {
				t.Fatal("Docker zstd layer not verified")
			}
			if len(r.Packages) != 2 {
				t.Fatalf("packages: %v", r.Packages)
			}
		})
	}
}

func TestZstdDecompressionBomb(t *testing.T) {
	setTestLimit(t, &maxLayerBytes, 4<<20)
	testZstdDecompressionBomb(t)
}

func testZstdDecompressionBomb(t *testing.T) {
	// Concatenated 1 MiB frames exceed the budget without allocating it, either
	// during fixture generation or decoding. The outer budget must stop early,
	// including when the entire expansion is padding after tar EOF.
	frame := zstdBytes(t, make([]byte, 1<<20))
	expanded := maxLayerBytes + maxLayerBytes/4
	bomb := bytes.Repeat(frame, int(expanded/(1<<20)))
	for _, padding := range []bool{false, true} {
		var prefix []byte
		if padding {
			prefix = buildTar(t, nil)
		} else {
			var b bytes.Buffer
			tw := tar.NewWriter(&b)
			if err := tw.WriteHeader(&tar.Header{Name: "unused", Mode: 0600, Size: maxLayerBytes / 2}); err != nil {
				t.Fatal(err)
			}
			prefix = b.Bytes()
		}
		data := append(zstdBytes(t, prefix), bomb...)
		p := writeTemp(t, "bomb", data)
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		_, err := Archive(p, Options{MaxTotalBytes: 2 << 20})
		if err == nil || !strings.Contains(err.Error(), "decompression limit exceeded") {
			t.Fatalf("padding=%t: %v", padding, err)
		}
		if entries, err := os.ReadDir(tmp); err != nil || len(entries) != 0 {
			t.Fatalf("failed decompression leaked temporary files: %v, %v", entries, err)
		}
	}
	// A layer's full stream cap also covers concatenated frames after tar EOF.
	// This decodes through the configured cap, retaining only a small window.
	_, err := newUnpacker(context.Background(), Options{}).applyLayer(bytes.NewReader(bomb), int64(len(bomb)), layerCheck{name: "padding-bomb"})
	if err == nil || !strings.Contains(err.Error(), "decompression limit exceeded") {
		t.Fatalf("layer stream cap: %v", err)
	}
	// An oversized file is also rejected by the per-layer cap, before its
	// payload is hashed or retained.
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: "huge", Mode: 0600, Size: expanded}); err != nil {
		t.Fatal(err)
	}
	rd := io.MultiReader(bytes.NewReader(zstdBytes(t, b.Bytes())), bytes.NewReader(bomb))
	_, err = newUnpacker(context.Background(), Options{}).applyLayer(rd, 0, layerCheck{name: "bomb"})
	if err == nil || !strings.Contains(err.Error(), "decompression limit exceeded") {
		t.Fatalf("layer cap: %v", err)
	}
}

func TestZstdWindowLimit(t *testing.T) {
	// Non-single-segment frame with a 512 MiB window descriptor. No payload is
	// needed: the decoder must reject the window before allocating it.
	blob := []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 19 << 3}
	_, err := newUnpacker(context.Background(), Options{}).applyLayer(bytes.NewReader(blob), int64(len(blob)), layerCheck{name: "window"})
	if !errors.Is(err, zstd.ErrWindowSizeExceeded) && !errors.Is(err, zstd.ErrDecoderSizeExceeded) {
		t.Fatalf("window limit: %v", err)
	}
}

func TestZstdTrailingChecksum(t *testing.T) {
	raw := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=alpine\n")}})
	// Put the corrupted checksum in a second frame, after the tar end marker.
	blob := append(zstdBytes(t, raw), zstdBytes(t, make([]byte, 1024))...)
	blob[len(blob)-1] ^= 1
	t.Run("layer", func(t *testing.T) {
		_, err := newUnpacker(context.Background(), Options{}).applyLayer(bytes.NewReader(blob), int64(len(blob)), layerCheck{name: "crc"})
		if !errors.Is(err, zstd.ErrCRCMismatch) {
			t.Fatalf("trailing layer checksum: %v", err)
		}
	})
	t.Run("outer", func(t *testing.T) {
		_, err := Archive(writeTemp(t, "crc", blob), Options{})
		if !errors.Is(err, zstd.ErrCRCMismatch) {
			t.Fatalf("trailing outer checksum: %v", err)
		}
	})
}
