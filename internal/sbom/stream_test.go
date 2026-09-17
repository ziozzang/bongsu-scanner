package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

// Frozen pre-streaming renderers: keep document construction here as the
// independent byte-for-byte oracle for the production writers.

func legacyCycloneDX(r scan.Result) ([]byte, error) {
	hash := stableHash(r)
	root := cdxComponent{Type: componentType(r.SourceType), BOMRef: "root-" + hash[:16], Name: r.Name}
	if r.Image != nil {
		root.Version = imageTag(firstTag(r.Image))
	}
	switch {
	case r.SourceHash != "":
		root.Hashes = []cdxHash{{Alg: "SHA-256", Content: r.SourceHash}}
	case r.Image != nil && imageIDHex(r.Image.ID) != "":
		root.Hashes = []cdxHash{{Alg: "SHA-256", Content: imageIDHex(r.Image.ID)}}
	}
	root.Properties = rootProperties(r)

	doc := cdxDoc{BOMFormat: "CycloneDX", SpecVersion: "1.6", Serial: "urn:uuid:" + uuidFromHash(hash), Version: 1,
		Metadata: cdxMetadata{
			Timestamp: timestampSeconds(r.ScannedAt),
			Tools:     cdxTools{Components: []cdxComponent{{Type: "application", Name: "bscan", Version: ToolVersion}}},
			Component: root,
		}}
	refs := make([]string, 0, len(r.Packages)+1)
	if r.OS != nil && r.OS.ID != "" {
		c := osComponent(*r.OS)
		doc.Components = append(doc.Components, c)
		refs = append(refs, c.BOMRef)
	}
	for i, ref := range packageRefs(r.Packages) {
		c := packageComponent(r.Packages[i], ref)
		doc.Components = append(doc.Components, c)
		refs = append(refs, ref)
	}
	doc.Dependencies = append(doc.Dependencies, cdxDependency{Ref: root.BOMRef, DependsOn: refs})
	for _, ref := range refs {
		doc.Dependencies = append(doc.Dependencies, cdxDependency{Ref: ref, DependsOn: []string{}})
	}
	return marshalIndent(doc)
}

func legacySPDX(r scan.Result) ([]byte, error) {
	hash := stableHash(r)
	created := timestampSeconds(r.ScannedAt)
	doc := spdxDoc{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name: r.Name, DocumentNamespace: "https://bongsu.local/spdx/" + hash,
		CreationInfo:  spdxCreationInfo{Created: created, Creators: []string{"Tool: bscan-" + ToolVersion}},
		Relationships: []relationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: spdxRootID}}}
	rp, err := rootPackage(r, created)
	if err != nil {
		return nil, err
	}
	doc.Packages = append(doc.Packages, rp)
	if r.OS != nil && r.OS.ID != "" {
		doc.Packages = append(doc.Packages, osPackage(*r.OS))
		doc.Relationships = append(doc.Relationships, relationship{SPDXElementID: spdxRootID, RelationshipType: "CONTAINS", RelatedSPDXElement: spdxOSID})
	}
	used := map[string]bool{spdxRootID: true, spdxOSID: true, "SPDXRef-DOCUMENT": true}
	for _, p := range r.Packages {
		id := uniqueSPDXID("SPDXRef-Package-"+safeID(packageIdentity(p)), used)
		doc.Packages = append(doc.Packages, spdxPackageFor(p, id))
		doc.Relationships = append(doc.Relationships, relationship{SPDXElementID: spdxRootID, RelationshipType: "CONTAINS", RelatedSPDXElement: id})
		if !p.Indirect && !isOSPackage(p.Type) {
			doc.Relationships = append(doc.Relationships, relationship{SPDXElementID: spdxRootID, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: id})
		}
	}
	for i, f := range r.Files {
		id := fmt.Sprintf("SPDXRef-File-%d", i)
		doc.Files = append(doc.Files, spdxFile{SPDXID: id, FileName: "./" + f.Path,
			Checksums: []checksum{{Algorithm: "SHA256", Value: f.SHA256}}, LicenseConcluded: noAssert, CopyrightText: noAssert})
		doc.Relationships = append(doc.Relationships, relationship{SPDXElementID: spdxRootID, RelationshipType: "CONTAINS", RelatedSPDXElement: id})
	}
	return marshalIndent(doc)
}

func largeResult(n int) scan.Result {
	r := fixture()
	base := r.Packages
	r.Packages = make([]scan.Package, n)
	for i := range r.Packages {
		p := base[i%len(base)]
		p.Name = fmt.Sprintf("package-%06d", i)
		if p.PURL != "" {
			p.PURL = fmt.Sprintf("pkg:%s/%s@%s?a=1&b=<한글>", p.Type, p.Name, p.Version)
		}
		r.Packages[i] = p
	}
	return r
}

func TestStreamingByteIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("large fixture or external integration; run without -short")
	}
	escaped := fixture()
	escaped.Name = "<tag>&\"\n\t한글\u2028\u2029\xff"
	escaped.Host = &scan.HostMetadata{Hostname: escaped.Name}
	escaped.Packages = append(escaped.Packages,
		scan.Package{Name: "collision", PURL: "pkg:cargo/serde@1.0.0#1"},
		scan.Package{Name: "a/b"}, scan.Package{Name: "a?b"}, scan.Package{Name: "a-b-2"})
	for i := 0; i < 70; i++ {
		escaped.Scan.SkippedPaths = append(escaped.Scan.SkippedPaths, fmt.Sprint(i))
	}
	cases := []struct {
		name   string
		result scan.Result
	}{
		{"empty", scan.Result{}}, {"fixture", fixture()}, {"escaped-collisions-caps", escaped},
		{"empty-os", scan.Result{OS: &scan.OSRelease{}}}, {"large-50000", largeResult(50000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkRenderIdentity(t, tc.name, tc.result) })
	}
}

func checkRenderIdentity(t *testing.T, name string, r scan.Result) {
	t.Helper()
	dir := t.TempDir()
	if retained := os.Getenv("P4_IDENTITY_DIR"); retained != "" {
		dir = filepath.Join(retained, name)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []struct {
		name           string
		oracle, render func(scan.Result) ([]byte, error)
	}{{"cyclonedx", legacyCycloneDX, CycloneDX}, {"spdx", legacySPDX, SPDX}} {
		want, err := f.oracle(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := f.render(r)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s memory renderer differs", f.name)
		}
		path := filepath.Join(dir, f.name+".json")
		if err := Write(path, f.name, r); err != nil {
			t.Fatal(err)
		}
		got, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, '\n')
		if err := os.WriteFile(path+".oracle", want, 0644); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s file renderer differs: got %d bytes, want %d", f.name, len(got), len(want))
		}
	}
}

// Optional integration check renders both implementations from exactly one
// real Result; independent CLI scans have different timestamps and host state.
func TestRealResultByteIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("large fixture or external integration; run without -short")
	}
	target := os.Getenv("P4_REAL_TARGET")
	if target == "" {
		t.Skip("set P4_REAL_TARGET to compare a real scan")
	}
	r, err := scan.Target(context.Background(), target, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("real result: %d packages, %d files", len(r.Packages), len(r.Files))
	checkRenderIdentity(t, "real", r)
}

func BenchmarkCycloneDX(b *testing.B) { benchmarkRender(b, "cyclonedx", CycloneDX) }
func BenchmarkSPDX(b *testing.B)      { benchmarkRender(b, "spdx", SPDX) }
func benchmarkRender(b *testing.B, format string, render func(scan.Result) ([]byte, error)) {
	r := largeResult(50000)
	b.Run("Memory", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := render(r); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Write", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := Write(os.DevNull, format, r); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Exercise failures in the header, array bodies and final document delimiter.
// The writer must stop after the first failure and preserve its error.
func TestStreamingWriteErrors(t *testing.T) {
	sentinel := errors.New("injected write failure")
	for _, tc := range []struct {
		name   string
		render func(io.Writer, scan.Result) error
		oracle func(scan.Result) ([]byte, error)
	}{{"cyclonedx", writeCycloneDX, legacyCycloneDX}, {"spdx", writeSPDX, legacySPDX}} {
		t.Run(tc.name, func(t *testing.T) {
			r := fixture()
			want, err := tc.oracle(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, limit := range []int{0, 1, 64, len(want) / 2, len(want) - 1} {
				for _, injected := range []error{sentinel, nil} {
					w := &limitedJSONWriter{remaining: limit, err: injected}
					err := tc.render(w, r)
					expected := injected
					if expected == nil {
						expected = io.ErrShortWrite
					}
					if !errors.Is(err, expected) {
						t.Fatalf("limit %d: got %v, want %v", limit, err, expected)
					}
					if w.writesAfterFailure != 0 {
						t.Fatalf("continued writing after failure at %d", limit)
					}
					if !bytes.Equal(w.buf.Bytes(), want[:limit]) {
						t.Fatalf("incorrect prefix at %d", limit)
					}
				}
			}
		})
	}
}

type limitedJSONWriter struct {
	remaining          int
	err                error
	failed             bool
	writesAfterFailure int
	buf                bytes.Buffer
}

func (w *limitedJSONWriter) Write(p []byte) (int, error) {
	if w.failed {
		w.writesAfterFailure++
		return 0, w.err
	}
	if len(p) > w.remaining {
		n, _ := w.buf.Write(p[:w.remaining])
		w.remaining = 0
		w.failed = true
		return n, w.err
	}
	w.remaining -= len(p)
	return w.buf.Write(p)
}

func TestWriteFormatsAndFileErrors(t *testing.T) {
	r := fixture()
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.json")
	for _, format := range []string{"spdx", "SPDX-JSON", "cyclonedx", "CDX", "cyclonedx-json"} {
		var want []byte
		var err error
		if format == "spdx" || format == "SPDX-JSON" {
			want, err = legacySPDX(r)
		} else {
			want, err = legacyCycloneDX(r)
		}
		if err != nil {
			t.Fatal(err)
		}
		// Existing file modes and truncation must match os.WriteFile.
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 100000), 0600); err != nil {
			t.Fatal(err)
		}
		if err := Write(path, format, r); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, append(want, '\n')) {
			t.Fatalf("%s: wrong output or trailing newline", format)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s: changed existing mode to %v", format, info.Mode())
		}
		if err := Write(dir, format, r); err == nil {
			t.Fatalf("%s: ignored open failure", format)
		}
		if _, err := os.Stat("/dev/full"); err == nil {
			// Small results fail during Flush; large ones during buffered rendering.
			for _, result := range []scan.Result{r, largeResult(200)} {
				if err := Write("/dev/full", format, result); err == nil {
					t.Fatalf("%s: ignored full device", format)
				}
			}
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, "unknown", r); err == nil {
		t.Fatal("accepted invalid format")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("invalid format truncated existing file")
	}
}
