package scan

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestImageSecondReviewOuterDecompressionBudget(t *testing.T) {
	layer := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=alpine\n")}})
	raw := buildTar(t, []tarEntry{
		{name: "unused-a", data: make([]byte, 8<<10)},
		{name: "unused-b", data: make([]byte, 8<<10)},
		{name: "layer.tar", data: layer},
		{name: "manifest.json", data: mustJSON(t, []dockerManifest{{Layers: []string{"layer.tar"}}})},
	})
	for _, tc := range []struct {
		name    string
		data    []byte
		limit   int64
		exceeds bool
	}{
		{"aggregate", raw, 16 << 10, true},
		{"exact", raw, int64(len(raw)), false},
		{"trailing-padding", append(append([]byte(nil), raw...), make([]byte, 1024)...), int64(len(raw)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTemp(t, "outer.gz", gzipBytes(t, tc.data))
			r, err := Archive(p, Options{MaxTotalBytes: tc.limit})
			if tc.exceeds {
				if err == nil || !strings.Contains(err.Error(), "decompression limit exceeded") {
					t.Fatalf("budget ignored: %v", err)
				}
			} else if err != nil || r.OSName != "alpine" {
				t.Fatalf("exact budget: os=%s err=%v", r.OSName, err)
			}
		})
	}
}

func TestImageSecondReviewOuterSinglePass(t *testing.T) {
	layer := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=alpine\n")}})
	// The manifest follows its referenced layer; neither order may require another decompression pass.
	raw := buildTar(t, []tarEntry{{name: "layer.tar", data: layer}, {name: "manifest.json", data: mustJSON(t, []dockerManifest{{Layers: []string{"layer.tar"}}})}})
	for _, budget := range []int64{1, 1 << 20} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			p := writeTemp(t, "once.gz", gzipBytes(t, raw))
			a, err := indexOuter(context.Background(), p, formatGzip, true, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			a.budget = budget
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			u := newUnpacker(context.Background(), Options{})
			if _, _, err := u.unpackDockerArchive(a); err != nil {
				t.Fatalf("reopened compressed outer: %v", err)
			}
			for i := 0; i < 3; i++ {
				rd, done, err := a.open("layer.tar")
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(rd)
				done()
				if err != nil || string(got) != string(layer) {
					t.Fatalf("cached layer: %v", err)
				}
			}
		})
	}
}

func TestImageSecondReviewDockerIndexIdentity(t *testing.T) {
	cfg := []byte(`{"os":"linux","architecture":"amd64"}`)
	first := buildTar(t, []tarEntry{{name: "first", data: []byte("one")}})
	second := buildTar(t, []tarEntry{{name: "second", data: []byte("two")}})
	compressed := gzipBytes(t, first)
	for _, tc := range []struct {
		name, config string
		layers       []string
		valid        bool
		reason       string
	}{
		{"matching-digests", digestOf(cfg), []string{digestOf(compressed), digestOf(second)}, true, ""},
		{"matching-diff-id", digestOf(cfg), []string{digestOf(first), digestOf(second)}, true, ""},
		{"other-config", digestOf([]byte(`{"os":"windows","architecture":"arm64"}`)), []string{digestOf(compressed), digestOf(second)}, false, "config"},
		{"other-layer", digestOf(cfg), []string{digestOf([]byte("other")), digestOf(second)}, false, "layer"},
		{"reordered", digestOf(cfg), []string{digestOf(second), digestOf(compressed)}, false, "layer"},
		{"missing-layer", digestOf(cfg), []string{digestOf(compressed)}, false, "layer"},
		{"missing-config", "", []string{digestOf(compressed), digestOf(second)}, false, "config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := ociManifest{Config: ociDescriptor{Digest: tc.config}}
			for _, d := range tc.layers {
				m.Layers = append(m.Layers, ociDescriptor{Digest: d})
			}
			body := mustJSON(t, m)
			d := digestOf(body)
			raw := buildTar(t, []tarEntry{
				{name: "manifest.json", data: mustJSON(t, []dockerManifest{{Config: "config.json", Layers: []string{"first.tar.gz", "second.tar"}}})},
				{name: "config.json", data: cfg}, {name: "first.tar.gz", data: compressed}, {name: "second.tar", data: second},
				{name: "index.json", data: mustJSON(t, ociIndex{Manifests: []ociDescriptor{{MediaType: mediaTypeOCIManifest, Digest: d}}})},
				{name: digestPath(d), data: body},
			})
			var messages []string
			r, err := Archive(writeTemp(t, "identity.tar", raw), Options{Progress: func(p Progress) { messages = append(messages, p.Message) }})
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if tc.valid {
				want = d
			}
			if r.Image.Digest != want {
				t.Fatalf("digest=%q want=%q", r.Image.Digest, want)
			}
			if !tc.valid {
				found := false
				for _, msg := range messages {
					if strings.Contains(msg, "Docker index manifest") && strings.Contains(msg, tc.reason) {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing mismatch explanation: %v", messages)
				}
			}
		})
	}
}

func TestImageSecondReviewLegacyConfigDigest(t *testing.T) {
	cfg := []byte(`{"os":"linux","architecture":"amd64"}`)
	for _, valid := range []bool{false, true} {
		for _, allow := range []bool{false, true} {
			t.Run(fmt.Sprintf("valid=%t/allow=%t", valid, allow), func(t *testing.T) {
				name := strings.Repeat("0", 64) + ".json"
				if valid {
					name = strings.TrimPrefix(digestOf(cfg), "sha256:") + ".json"
				}
				var messages []string
				r, err := Archive(writeTemp(t, "legacy.tar", buildTar(t, []tarEntry{{name: "manifest.json", data: mustJSON(t, []dockerManifest{{Config: name}})}, {name: name, data: cfg}})), Options{AllowDigestMismatch: allow, Progress: func(p Progress) { messages = append(messages, p.Message) }})
				if !valid && !allow {
					if err == nil || !strings.Contains(err.Error(), "config") || !strings.Contains(err.Error(), "digest mismatch") {
						t.Fatalf("accepted tampered legacy config: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if r.Image.ID != digestOf(cfg) || !strings.Contains(strings.Join(messages, "\n"), fmt.Sprintf("verified=%t", valid)) {
					t.Fatalf("id=%s messages=%v", r.Image.ID, messages)
				}
			})
		}
	}
}

func TestImageSecondReviewDefaultPlatformlessConfig(t *testing.T) {
	for _, mode := range []string{"prefer-match", "single-fallback", "no-match"} {
		t.Run(mode, func(t *testing.T) {
			entries := map[string][]byte{}
			wrong := ociBlobs(t, entries, ociImage{platform: &ociPlatform{OS: "windows", Architecture: "arm64"}}, nil)
			wrong.Platform = nil
			candidates := []ociDescriptor{wrong}
			if mode != "single-fallback" {
				platform := &ociPlatform{OS: "linux", Architecture: runtime.GOARCH}
				if mode == "no-match" {
					platform.OS = "darwin"
				}
				d := ociBlobs(t, entries, ociImage{platform: platform}, nil)
				d.Platform = nil
				candidates = append(candidates, d)
			}
			var messages []string
			r, err := Archive(writeTemp(t, "platform.tar", ociLayoutTar(t, entries, ociIndex{Manifests: candidates})), Options{Progress: func(p Progress) { messages = append(messages, p.Message) }})
			if mode == "no-match" {
				if err == nil || !strings.Contains(err.Error(), "no image manifest for platform linux/"+runtime.GOARCH) {
					t.Fatalf("unexpected platform result: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "prefer-match" && (r.Image.OS != "linux" || r.Image.Architecture != runtime.GOARCH) {
				t.Fatalf("wrong default platform: %+v", r.Image)
			}
			if mode == "single-fallback" && !strings.Contains(strings.Join(messages, "\n"), "scanning the only image manifest (windows/arm64)") {
				t.Fatalf("missing fallback warning: %v", messages)
			}
		})
	}
}

func TestImageSecondReviewSpecialReplacement(t *testing.T) {
	for _, kind := range []byte{tar.TypeFifo, tar.TypeChar, tar.TypeBlock, tar.TypeLink} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			base := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=old\n")}, {name: "tree/", typeflag: tar.TypeDir}, {name: "tree/child", data: []byte("old")}, {name: "implicit/child", data: []byte("old")}})
			upper := buildTar(t, []tarEntry{{name: "etc/os-release", typeflag: kind, link: "missing"}, {name: "tree", typeflag: kind, link: "missing"}, {name: "implicit", typeflag: kind, link: "missing"}})
			r, err := Archive(writeTemp(t, "special.tar", dockerArchive(t, base, upper)), Options{})
			if err != nil {
				t.Fatal(err)
			}
			files := filesByPath(r)
			for _, name := range []string{"etc/os-release", "tree", "tree/child", "implicit", "implicit/child"} {
				if _, ok := files[name]; ok {
					t.Errorf("stale/special record: %s", name)
				}
			}
			if r.OSName != "" {
				t.Fatalf("stale OS: %s", r.OSName)
			}
		})
	}
}

// Removing the source as soon as indexing starts detects a second index pass
// as well as later metadata/layer/rootfs reopens of the compressed stream.
func TestImageSecondReviewArchiveSingleDecompression(t *testing.T) {
	root := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=alpine\n")}})
	entries := map[string][]byte{}
	d := ociBlobs(t, entries, ociImage{layers: [][]byte{root}}, nil)
	oci := ociLayoutTar(t, entries, ociIndex{Manifests: []ociDescriptor{d}})
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"docker", dockerArchive(t, root)}, {"oci", oci}, {"rootfs", root},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTemp(t, "single.gz", gzipBytes(t, tc.raw))
			removed := false
			r, err := Archive(p, Options{Verbose: true, MaxTotalBytes: int64(len(tc.raw)), Progress: func(e Progress) {
				if e.Stage == "archive-entry" && !removed {
					if err := os.Remove(p); err != nil {
						t.Fatal(err)
					}
					removed = true
				}
			}})
			if err != nil {
				t.Fatalf("compressed outer reopened: %v", err)
			}
			if !removed || r.OSName != "alpine" {
				t.Fatalf("removed=%t os=%s", removed, r.OSName)
			}
		})
	}
}

func TestImageSecondReviewOuterSpoolCleanup(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	raw := buildTar(t, []tarEntry{{name: "unused", data: make([]byte, 4096)}})
	p := writeTemp(t, "cleanup.gz", gzipBytes(t, raw))
	if _, err := indexOuter(context.Background(), p, formatGzip, true, Options{MaxTotalBytes: 1024}); err == nil {
		t.Fatal("expected decompression limit error")
	}
	files, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("spool leaked after failure: %v", files)
	}
	a, err := indexOuter(context.Background(), p, formatGzip, true, Options{})
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	files, err = os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("spool leaked after close: %v", files)
	}
}
