package sbom

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

const (
	fixtureImageID = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fixtureLayer1  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	fixtureLayer2  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fixture is a docker image scan exercising every field the writers read:
// os-release, two layers (one unverified), a partial scan, and packages
// covering OS/upstream qualifiers, npm scopes, a Go stdlib CPE, free-form
// license text, dev and indirect flags, duplicated purls and no purl at all.
func fixture() scan.Result {
	return scan.Result{
		Name: "registry.example.com:5000/team/app:1.2.3", Source: "docker://registry.example.com:5000/team/app:1.2.3",
		SourceType: "docker-image", ScannedAt: time.Date(2026, 9, 10, 12, 34, 56, 789, time.UTC),
		OS: &scan.OSRelease{ID: "debian", IDLike: "", VersionID: "12", Codename: "bookworm", PrettyName: "Debian GNU/Linux 12 (bookworm)"},
		Image: &scan.ImageMetadata{ID: fixtureImageID, Digest: "sha256:aaaa", Tags: []string{"registry.example.com:5000/team/app:1.2.3", "team/app:latest"},
			RepoDigests: []string{"registry.example.com:5000/team/app@sha256:aaaa"}, OS: "linux", Architecture: "amd64", Created: "2026-09-01T00:00:00Z",
			Layers: []scan.LayerInfo{{Digest: fixtureLayer1, DiffID: "sha256:d1", Size: 10, Verified: true}, {Digest: fixtureLayer2, Verified: false}}},
		Scan: &scan.ScanMetadata{Partial: true, EUID: 1000, PermissionDenied: 3, SkippedErrors: 1, FilesVisited: 4242,
			SkippedPaths: []string{"/root/.ssh", "/proc"}, Excluded: []string{"/var/cache"}},
		Packages: []scan.Package{
			{Name: "libssl3", Version: "3.0.11-1~deb12u2", Type: "deb", Namespace: "debian", Arch: "amd64", Distro: "debian-12",
				SourceName: "openssl", SourceVersion: "3.0.11-1~deb12u2", Source: "var/lib/dpkg/status", Layer: fixtureLayer1,
				PURL: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl%403.0.11-1~deb12u2"},
			{Name: "core", Namespace: "@babel", Version: "7.24.0", Type: "npm", License: "MIT", Source: "app/package-lock.json",
				PURL: "pkg:npm/%40babel/core@7.24.0"},
			{Name: "stdlib", Version: "1.22.4", Type: "golang", Source: "usr/local/bin/app", Layer: fixtureLayer2,
				CPE: "cpe:2.3:a:golang:go:1.22.4:*:*:*:*:*:*:*", PURL: "pkg:golang/stdlib@1.22.4"},
			{Name: "logrus", Namespace: "github.com/sirupsen", Version: "v1.9.3", Type: "golang", Indirect: true,
				Source: "app/go.mod;usr/local/bin/app", PURL: "pkg:golang/github.com/sirupsen/logrus@v1.9.3"},
			{Name: "requests", Version: "2.31.0", Type: "pypi", Source: "usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA",
				License: "Apache License 2.0\n\n                           Apache License\n                     Version 2.0, January 2004\n",
				PURL:    "pkg:pypi/requests@2.31.0"},
			{Name: "jest", Version: "29.0.0", Type: "npm", Dev: true, License: "MIT", Source: "app/package-lock.json", PURL: "pkg:npm/jest@29.0.0"},
			{Name: "serde", Version: "1.0.0", Type: "cargo", Source: "svc-a/Cargo.lock", License: "MIT OR Apache-2.0", PURL: "pkg:cargo/serde@1.0.0"},
			{Name: "serde", Version: "1.0.0", Type: "cargo", Source: "svc-b/Cargo.lock", License: "MIT OR Apache-2.0", PURL: "pkg:cargo/serde@1.0.0"},
			{Name: "mystery thing", Version: "0", Source: "opt/mystery/VERSION"},
		},
		Files: []scan.File{{Path: "usr/local/bin/app", SHA256: strings.Repeat("ab", 32), Layer: fixtureLayer2}},
	}
}

func mustCDX(t *testing.T, r scan.Result) (cdxDoc, []byte) {
	t.Helper()
	b, err := CycloneDX(r)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatalf("invalid JSON: %s", b)
	}
	var doc cdxDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, b
}

func mustSPDX(t *testing.T, r scan.Result) (spdxDoc, []byte) {
	t.Helper()
	b, err := SPDX(r)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatalf("invalid JSON: %s", b)
	}
	var doc spdxDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, b
}

func findComponent(doc cdxDoc, name string) (cdxComponent, bool) {
	for _, c := range doc.Components {
		if c.Name == name {
			return c, true
		}
	}
	return cdxComponent{}, false
}

func findPackage(doc spdxDoc, name string) (spdxPackage, bool) {
	for _, p := range doc.Packages {
		if p.Name == name {
			return p, true
		}
	}
	return spdxPackage{}, false
}

func property(c cdxComponent, name string) (string, bool) {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

func TestDocumentsAreValidJSONWithComponents(t *testing.T) {
	r := scan.Result{Name: "image", SourceType: "docker-image", SourceHash: "abc", ScannedAt: time.Unix(1, 0).UTC(),
		Packages: []scan.Package{{Name: "libc", Version: "1.0", Type: "apk", PURL: "pkg:apk/libc@1.0"}},
		Files:    []scan.File{{Path: "bin/x", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	for name, fn := range map[string]func(scan.Result) ([]byte, error){"spdx": SPDX, "cdx": CycloneDX} {
		b, err := fn(r)
		if err != nil || !json.Valid(b) {
			t.Fatalf("%s: %v %s", name, err, b)
		}
		var doc map[string]any
		json.Unmarshal(b, &doc)
		if name == "spdx" && doc["spdxVersion"] != "SPDX-2.3" {
			t.Fatal("wrong SPDX version")
		}
		if name == "cdx" && doc["specVersion"] != "1.6" {
			t.Fatal("wrong CycloneDX version")
		}
	}
}

func TestHostMetadataIncludedInBothFormats(t *testing.T) {
	r := scan.Result{Name: "host", SourceType: "host", ScannedAt: time.Unix(1, 0).UTC(),
		Host: &scan.HostMetadata{Hostname: "build-host", OperatingSystem: "linux", OSVersion: "42",
			Kernel: "6.1-test", Architecture: "amd64", CPUModel: "Test CPU", CPUCount: 8,
			MemoryBytes: 17179869184, IPAddresses: []string{"10.0.0.2", "2001:db8::2"}},
		Packages: []scan.Package{{Name: "local-module", Version: "1", Type: "golang", Source: "/home/foo/app/go.mod"}}}
	for name, fn := range map[string]func(scan.Result) ([]byte, error){"spdx": SPDX, "cdx": CycloneDX} {
		b, err := fn(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"build-host", "Test CPU", "17179869184", "10.0.0.2", "/home/foo/app/go.mod"} {
			if !strings.Contains(string(b), value) {
				t.Errorf("%s missing host metadata %q", name, value)
			}
		}
	}
	cdx, _ := mustCDX(t, r)
	if cdx.Metadata.Component.Type != "application" {
		t.Errorf("host root type = %q, want application", cdx.Metadata.Component.Type)
	}
	spdx, _ := mustSPDX(t, r)
	if spdx.Packages[0].PrimaryPackagePurpose != "DEVICE" {
		t.Errorf("host root purpose = %q, want DEVICE", spdx.Packages[0].PrimaryPackagePurpose)
	}
}

func TestCycloneDXRootDescribesImage(t *testing.T) {
	doc, _ := mustCDX(t, fixture())
	root := doc.Metadata.Component
	if root.Type != "container" || root.Version != "1.2.3" || root.BOMRef == "" {
		t.Errorf("root = %+v", root)
	}
	if len(root.Hashes) != 1 || root.Hashes[0].Alg != "SHA-256" || root.Hashes[0].Content != strings.TrimPrefix(fixtureImageID, "sha256:") {
		t.Errorf("root hashes = %+v", root.Hashes)
	}
	if doc.Metadata.Timestamp != "2026-09-10T12:34:56Z" {
		t.Errorf("timestamp = %q", doc.Metadata.Timestamp)
	}
	if tool := doc.Metadata.Tools.Components[0]; tool.Name != "bscan" || tool.Version != ToolVersion || tool.Type != "application" {
		t.Errorf("tool = %+v", tool)
	}
	want := map[string]string{
		"bscan:image:id":           fixtureImageID,
		"bscan:image:tags":         "registry.example.com:5000/team/app:1.2.3,team/app:latest",
		"bscan:image:architecture": "amd64",
		"bscan:image:layer:0":      fixtureLayer1 + " diff_id=sha256:d1 verified=true",
		"bscan:image:layer:1":      fixtureLayer2 + " verified=false",
		"bscan:scan:partial":       "true",
		"bscan:scan:euid":          "1000",
		"bscan:scan:skipped-paths": "/root/.ssh;/proc",
		"bscan:scan:excluded":      "/var/cache",
		"bscan:scan:files-visited": "4242",
		"bscan:os:codename":        "bookworm",
		"bscan:os:pretty-name":     "Debian GNU/Linux 12 (bookworm)",
	}
	for k, v := range want {
		if got, ok := property(root, k); !ok || got != v {
			t.Errorf("root property %s = %q (present=%v), want %q", k, got, ok, v)
		}
	}
	if _, ok := property(root, "bscan:os:id-like"); ok {
		t.Error("empty id-like must be omitted")
	}
}

func TestCycloneDXOperatingSystemComponent(t *testing.T) {
	doc, _ := mustCDX(t, fixture())
	if len(doc.Components) == 0 {
		t.Fatal("no components")
	}
	os := doc.Components[0]
	if os.Type != "operating-system" || os.Name != "debian" || os.Version != "12" || os.BOMRef != "os-debian-12" {
		t.Errorf("os component = %+v", os)
	}
	if os.CPE != "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*" {
		t.Errorf("os cpe = %q", os.CPE)
	}
	if os.Description != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("os description = %q", os.Description)
	}
	if v, _ := property(os, "bscan:os:codename"); v != "bookworm" {
		t.Errorf("os codename property = %q", v)
	}
	cpeForm := regexp.MustCompile(`^cpe:2\.3:o:[^:]+:[^:]+:[^:]+(:\*){7}$`)
	if !cpeForm.MatchString(os.CPE) {
		t.Errorf("cpe %q does not match the 2.3 formatted string layout", os.CPE)
	}
	r := fixture()
	r.OS = nil
	doc, _ = mustCDX(t, r)
	if doc.Components[0].Type == "operating-system" {
		t.Error("os component emitted without os-release")
	}
}

func TestCycloneDXBOMRefsAreUniqueAndPURLBased(t *testing.T) {
	doc, _ := mustCDX(t, fixture())
	seen := map[string]bool{doc.Metadata.Component.BOMRef: true}
	for _, c := range doc.Components {
		if c.BOMRef == "" {
			t.Errorf("component %s has no bom-ref", c.Name)
		}
		if seen[c.BOMRef] {
			t.Errorf("duplicate bom-ref %q", c.BOMRef)
		}
		seen[c.BOMRef] = true
	}
	var serde []cdxComponent
	for _, c := range doc.Components {
		switch {
		case c.Name == "serde":
			serde = append(serde, c)
		case c.PURL != "" && c.BOMRef != c.PURL:
			t.Errorf("unique purl %q got bom-ref %q", c.PURL, c.BOMRef)
		}
	}
	if len(serde) != 2 || serde[0].BOMRef != "pkg:cargo/serde@1.0.0#1" || serde[1].BOMRef != "pkg:cargo/serde@1.0.0#2" {
		t.Errorf("duplicate purl refs = %+v", serde)
	}
	mystery, ok := findComponent(doc, "mystery thing")
	if !ok || !strings.HasPrefix(mystery.BOMRef, "pkg-") || mystery.PURL != "" {
		t.Errorf("purl-less component = %+v", mystery)
	}
}

func TestCycloneDXBOMRefsReservePURLSubpaths(t *testing.T) {
	r := fixture()
	r.Packages = []scan.Package{
		{Name: "x", PURL: "pkg:generic/x@1"},
		{Name: "x", PURL: "pkg:generic/x@1"},
		{Name: "x", PURL: "pkg:generic/x@1#1"},
		{Name: "x", PURL: "pkg:generic/x@1#2"},
	}
	doc, _ := mustCDX(t, r)
	seen := map[string]bool{doc.Metadata.Component.BOMRef: true}
	for _, c := range doc.Components {
		if seen[c.BOMRef] {
			t.Fatalf("duplicate bom-ref %q", c.BOMRef)
		}
		seen[c.BOMRef] = true
		if strings.Contains(c.PURL, "#") && c.BOMRef != c.PURL {
			t.Errorf("unique subpath purl lost stable reference: %+v", c)
		}
	}
	for _, dep := range doc.Dependencies {
		if !seen[dep.Ref] {
			t.Errorf("dependency references missing component %q", dep.Ref)
		}
	}
}

func TestCycloneDXDependencyGraphCoversEveryComponent(t *testing.T) {
	doc, _ := mustCDX(t, fixture())
	if len(doc.Dependencies) != len(doc.Components)+1 {
		t.Fatalf("dependencies = %d, want %d", len(doc.Dependencies), len(doc.Components)+1)
	}
	root := doc.Dependencies[0]
	if root.Ref != doc.Metadata.Component.BOMRef {
		t.Errorf("first dependency ref = %q, want root", root.Ref)
	}
	on := map[string]bool{}
	for _, ref := range root.DependsOn {
		on[ref] = true
	}
	for _, c := range doc.Components {
		if !on[c.BOMRef] {
			t.Errorf("root does not depend on %q", c.BOMRef)
		}
	}
	for _, d := range doc.Dependencies[1:] {
		if d.DependsOn == nil {
			t.Errorf("dependency %q has null dependsOn", d.Ref)
		}
	}
}

func TestCycloneDXPackageComponents(t *testing.T) {
	doc, raw := mustCDX(t, fixture())
	deb, _ := findComponent(doc, "libssl3")
	for k, v := range map[string]string{"bscan:upstream": "openssl@3.0.11-1~deb12u2", "bscan:distro": "debian-12", "bscan:arch": "amd64",
		"bscan:layer": fixtureLayer1, "bscan:source": "var/lib/dpkg/status"} {
		if got, _ := property(deb, k); got != v {
			t.Errorf("deb %s = %q, want %q", k, got, v)
		}
	}
	if deb.Group != "" || deb.Scope != "required" || deb.Licenses != nil {
		t.Errorf("deb component = %+v", deb)
	}
	babel, _ := findComponent(doc, "core")
	if babel.Group != "@babel" || len(babel.Licenses) != 1 || babel.Licenses[0].Expression != "MIT" || babel.Licenses[0].License != nil {
		t.Errorf("scoped npm = %+v", babel)
	}
	stdlib, _ := findComponent(doc, "stdlib")
	if stdlib.Type != "library" || stdlib.CPE != "cpe:2.3:a:golang:go:1.22.4:*:*:*:*:*:*:*" {
		t.Errorf("stdlib = %+v", stdlib)
	}
	if v, _ := property(stdlib, "bscan:source-kind"); v != "binary" {
		t.Errorf("stdlib source-kind = %q", v)
	}
	logrus, _ := findComponent(doc, "logrus")
	if logrus.Group != "github.com/sirupsen" {
		t.Errorf("logrus group = %q", logrus.Group)
	}
	if v, _ := property(logrus, "bscan:indirect"); v != "true" {
		t.Error("indirect flag missing")
	}
	if v, _ := property(logrus, "bscan:source-kind"); v != "binary" {
		t.Errorf("merged go.mod+binary source-kind = %q", v)
	}
	requests, _ := findComponent(doc, "requests")
	if len(requests.Licenses) != 1 || requests.Licenses[0].Expression != "" || requests.Licenses[0].License == nil ||
		requests.Licenses[0].License.Name != "Apache License 2.0" {
		t.Errorf("free-form license = %+v", requests.Licenses)
	}
	jest, _ := findComponent(doc, "jest")
	if jest.Scope != "optional" {
		t.Errorf("dev scope = %q", jest.Scope)
	}
	if v, _ := property(jest, "bscan:dev"); v != "true" {
		t.Error("dev flag missing")
	}
	serde, _ := findComponent(doc, "serde")
	if serde.Licenses[0].Expression != "MIT OR Apache-2.0" {
		t.Errorf("serde license = %+v", serde.Licenses)
	}
	if bytes.Contains(raw, []byte("January 2004")) {
		t.Error("multi-line license text leaked into the document")
	}
}

func TestSPDXCreationInfoAndRoot(t *testing.T) {
	doc, _ := mustSPDX(t, fixture())
	created := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	if !created.MatchString(doc.CreationInfo.Created) {
		t.Errorf("created = %q", doc.CreationInfo.Created)
	}
	if doc.CreationInfo.Created != "2026-09-10T12:34:56Z" {
		t.Errorf("created = %q, nanoseconds must be dropped", doc.CreationInfo.Created)
	}
	if len(doc.CreationInfo.Creators) != 1 || doc.CreationInfo.Creators[0] != "Tool: bscan-"+ToolVersion {
		t.Errorf("creators = %v", doc.CreationInfo.Creators)
	}
	root := doc.Packages[0]
	if root.SPDXID != "SPDXRef-Root" || root.PrimaryPackagePurpose != "CONTAINER" || root.VersionInfo != "1.2.3" {
		t.Errorf("root = %+v", root)
	}
	if len(root.Checksums) != 1 || root.Checksums[0].Algorithm != "SHA256" || root.Checksums[0].Value != strings.TrimPrefix(fixtureImageID, "sha256:") {
		t.Errorf("root checksums = %+v", root.Checksums)
	}
	wantPURL := "pkg:oci/app@sha256%3A" + strings.TrimPrefix(fixtureImageID, "sha256:") + "?tag=1.2.3"
	if len(root.ExternalRefs) != 1 || root.ExternalRefs[0].ReferenceType != "purl" || root.ExternalRefs[0].ReferenceLocator != wantPURL {
		t.Errorf("root externalRefs = %+v, want %s", root.ExternalRefs, wantPURL)
	}
	if len(root.Annotations) != 2 {
		t.Fatalf("annotations = %+v", root.Annotations)
	}
	for _, a := range root.Annotations {
		if a.AnnotationType != "OTHER" || a.Annotator != "Tool: bscan" || !created.MatchString(a.AnnotationDate) {
			t.Errorf("annotation = %+v", a)
		}
		body := a.Comment[strings.Index(a.Comment, ": ")+2:]
		if !json.Valid([]byte(body)) || strings.Contains(body, "\n") {
			t.Errorf("annotation comment is not one-line JSON: %q", a.Comment)
		}
	}
	if !strings.Contains(root.Annotations[0].Comment, "bscan image metadata") || !strings.Contains(root.Annotations[0].Comment, fixtureImageID) {
		t.Errorf("image annotation = %q", root.Annotations[0].Comment)
	}
	if !strings.Contains(root.Annotations[1].Comment, "bscan scan metadata") || !strings.Contains(root.Annotations[1].Comment, `"partial":true`) {
		t.Errorf("scan annotation = %q", root.Annotations[1].Comment)
	}
	dir := scan.Result{Name: "src", SourceType: "directory", ScannedAt: time.Unix(1, 0)}
	if d, _ := mustSPDX(t, dir); d.Packages[0].PrimaryPackagePurpose != "APPLICATION" || d.Packages[0].Annotations != nil {
		t.Errorf("directory root = %+v", d.Packages[0])
	}
}

func TestSPDXOperatingSystemPackage(t *testing.T) {
	doc, _ := mustSPDX(t, fixture())
	os, ok := findPackage(doc, "debian")
	if !ok || os.SPDXID != "SPDXRef-OperatingSystem" || os.VersionInfo != "12" || os.PrimaryPackagePurpose != "OPERATING_SYSTEM" {
		t.Fatalf("os package = %+v", os)
	}
	if os.Summary != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("summary = %q", os.Summary)
	}
	if len(os.ExternalRefs) != 1 || os.ExternalRefs[0].ReferenceCategory != "SECURITY" || os.ExternalRefs[0].ReferenceType != "cpe23Type" ||
		os.ExternalRefs[0].ReferenceLocator != "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*" {
		t.Errorf("os externalRefs = %+v", os.ExternalRefs)
	}
	found := false
	for _, rel := range doc.Relationships {
		if rel.SPDXElementID == "SPDXRef-Root" && rel.RelationshipType == "CONTAINS" && rel.RelatedSPDXElement == "SPDXRef-OperatingSystem" {
			found = true
		}
	}
	if !found {
		t.Error("Root CONTAINS OperatingSystem relationship missing")
	}
}

func TestSPDXPackageLicensesAndRefs(t *testing.T) {
	doc, _ := mustSPDX(t, fixture())
	requests, _ := findPackage(doc, "requests")
	if requests.LicenseDeclared != "NOASSERTION" {
		t.Errorf("free-form licenseDeclared = %q", requests.LicenseDeclared)
	}
	if !strings.Contains(requests.LicenseComments, "Apache License 2.0") || strings.Contains(requests.LicenseComments, "\n") {
		t.Errorf("licenseComments = %q", requests.LicenseComments)
	}
	babel, _ := findPackage(doc, "core")
	if babel.LicenseDeclared != "MIT" || babel.LicenseComments != "" || babel.PrimaryPackagePurpose != "LIBRARY" {
		t.Errorf("npm package = %+v", babel)
	}
	if babel.SourceInfo != "found in app/package-lock.json" {
		t.Errorf("sourceInfo = %q", babel.SourceInfo)
	}
	stdlib, _ := findPackage(doc, "stdlib")
	var purl, cpe string
	for _, ref := range stdlib.ExternalRefs {
		switch ref.ReferenceType {
		case "purl":
			purl = ref.ReferenceLocator
		case "cpe23Type":
			cpe = ref.ReferenceLocator
			if ref.ReferenceCategory != "SECURITY" {
				t.Errorf("cpe category = %q", ref.ReferenceCategory)
			}
		}
	}
	if purl != "pkg:golang/stdlib@1.22.4" || cpe != "cpe:2.3:a:golang:go:1.22.4:*:*:*:*:*:*:*" {
		t.Errorf("stdlib refs purl=%q cpe=%q", purl, cpe)
	}
	deb, _ := findPackage(doc, "libssl3")
	if deb.LicenseDeclared != "NOASSERTION" || deb.LicenseComments != "" {
		t.Errorf("deb without license = %+v", deb)
	}
	logrus, _ := findPackage(doc, "logrus")
	if logrus.SourceInfo != "found in app/go.mod;usr/local/bin/app" || !strings.Contains(logrus.PackageComment, "indirect=true") {
		t.Errorf("logrus = %+v", logrus)
	}
}

func TestSPDXIdentifiersUniqueAndWellFormed(t *testing.T) {
	doc, _ := mustSPDX(t, fixture())
	idForm := regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]+$`)
	seen := map[string]bool{}
	for _, p := range doc.Packages {
		if !idForm.MatchString(p.SPDXID) {
			t.Errorf("malformed SPDXID %q", p.SPDXID)
		}
		if seen[p.SPDXID] {
			t.Errorf("duplicate SPDXID %q", p.SPDXID)
		}
		seen[p.SPDXID] = true
	}
	for _, f := range doc.Files {
		if !idForm.MatchString(f.SPDXID) || seen[f.SPDXID] {
			t.Errorf("bad file SPDXID %q", f.SPDXID)
		}
		seen[f.SPDXID] = true
	}
	for _, rel := range doc.Relationships {
		if rel.SPDXElementID != "SPDXRef-DOCUMENT" && !seen[rel.SPDXElementID] {
			t.Errorf("relationship from unknown element %q", rel.SPDXElementID)
		}
		if !seen[rel.RelatedSPDXElement] {
			t.Errorf("relationship to unknown element %q", rel.RelatedSPDXElement)
		}
	}
	babel, _ := findPackage(doc, "core")
	if babel.SPDXID != "SPDXRef-Package-pkg-npm-40babel-core-7.24.0" {
		t.Errorf("purl-derived id = %q", babel.SPDXID)
	}
	var serde []string
	for _, p := range doc.Packages {
		if p.Name == "serde" {
			serde = append(serde, p.SPDXID)
		}
	}
	if len(serde) != 2 || serde[0] != "SPDXRef-Package-pkg-cargo-serde-1.0.0" || serde[1] != "SPDXRef-Package-pkg-cargo-serde-1.0.0-2" {
		t.Errorf("duplicate purl ids = %v", serde)
	}
	mystery, _ := findPackage(doc, "mystery thing")
	if mystery.SPDXID != "SPDXRef-Package-mystery-thing-0" {
		t.Errorf("purl-less id = %q", mystery.SPDXID)
	}
}

func TestSPDXRelationships(t *testing.T) {
	doc, _ := mustSPDX(t, fixture())
	ids := map[string]string{}
	for _, p := range doc.Packages {
		ids[p.SPDXID] = p.Name
	}
	contains, depends := map[string]bool{}, map[string]bool{}
	for _, rel := range doc.Relationships {
		if rel.SPDXElementID != "SPDXRef-Root" {
			continue
		}
		switch rel.RelationshipType {
		case "CONTAINS":
			contains[ids[rel.RelatedSPDXElement]] = true
		case "DEPENDS_ON":
			depends[ids[rel.RelatedSPDXElement]] = true
		}
	}
	for _, name := range []string{"debian", "libssl3", "core", "stdlib", "logrus", "requests", "jest", "serde", "mystery thing"} {
		if !contains[name] {
			t.Errorf("Root does not CONTAIN %q", name)
		}
	}
	for name, want := range map[string]bool{"core": true, "stdlib": true, "requests": true, "serde": true, "logrus": false, "libssl3": false, "debian": false} {
		if depends[name] != want {
			t.Errorf("Root DEPENDS_ON %q = %v, want %v", name, depends[name], want)
		}
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	for name, fn := range map[string]func(scan.Result) ([]byte, error){"spdx": SPDX, "cdx": CycloneDX} {
		a, err := fn(fixture())
		if err != nil {
			t.Fatal(err)
		}
		b, err := fn(fixture())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s output differs between runs", name)
		}
	}
}

func TestStableHashCoversImageOSAndPartial(t *testing.T) {
	base := fixture()
	h := stableHash(base)
	r := fixture()
	r.Image.ID = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if stableHash(r) == h {
		t.Error("image id not covered")
	}
	r = fixture()
	r.OS.VersionID = "13"
	if stableHash(r) == h {
		t.Error("os-release not covered")
	}
	r = fixture()
	r.Scan.Partial = false
	if stableHash(r) == h {
		t.Error("partial flag not covered")
	}
}

func TestLicenseExpression(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"MIT", "MIT", true},
		{"Apache-2.0 OR MIT", "Apache-2.0 OR MIT", true},
		{"GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0", true},
		{"(MIT AND BSD-3-Clause)", "(MIT AND BSD-3-Clause)", true},
		{"LicenseRef-foo", "", false},
		{"Proprietary", "", false},
		{"MIT WITH Fake-exception", "", false},
		{"Classpath-exception-2.0", "", false},
		{"MIT WITH Apache-2.0", "", false},
		{"mit and apache-2.0", "MIT AND Apache-2.0", true},
		{"GPL-2.0++", "", false},
		{"GPL-2.0+", "GPL-2.0+", true},
		{"  MIT   or\tApache-2.0 ", "MIT OR Apache-2.0", true},
		{"(MIT OR Apache-2.0) AND (BSD-2-Clause WITH LLVM-exception)", "(MIT OR Apache-2.0) AND (BSD-2-Clause WITH LLVM-exception)", true},
		{"Apache License 2.0", "", false},
		{"MIT AND", "", false},
		{"(MIT", "", false},
		{"MIT)", "", false},
		{"AND MIT", "", false},
		{"MIT WITH", "", false},
		{"MIT/Apache-2.0", "", false},
		{"", "", false},
		{"()", "", false},
		{"MIT BSD-3-Clause", "", false},
	}
	for _, c := range cases {
		got, ok := licenseExpression(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("licenseExpression(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
		if validLicenseExpression(c.in) != c.ok {
			t.Errorf("validLicenseExpression(%q) = %v", c.in, !c.ok)
		}
	}
}

func TestCPEEscapeAndVendorMapping(t *testing.T) {
	for in, want := range map[string]string{
		"12":            "12",
		"3.20.10":       "3.20.10",
		"2023.09-rc1":   "2023.09-rc1",
		"a:b":           `a\:b`,
		"1.0+build/2":   `1.0\+build\/2`,
		"star*quest?":   `star\*quest\?`,
		"rolling edge":  "rolling_edge",
		"back\\slash":   `back\\slash`,
		"café":          "caf_",
		"under_score_1": "under_score_1",
	} {
		if got := cpeEscape(in); got != want {
			t.Errorf("cpeEscape(%q) = %q, want %q", in, got, want)
		}
	}
	for _, c := range []struct{ id, version, want string }{
		{"ubuntu", "22.04", "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*"},
		{"alpine", "3.20.1", "cpe:2.3:o:alpinelinux:alpine_linux:3.20.1:*:*:*:*:*:*:*"},
		{"rocky", "9.4", "cpe:2.3:o:resf:rocky_linux:9.4:*:*:*:*:*:*:*"},
		{"rhel", "9.4", "cpe:2.3:o:redhat:enterprise_linux:9.4:*:*:*:*:*:*:*"},
		{"opensuse-leap", "15.6", "cpe:2.3:o:opensuse:leap:15.6:*:*:*:*:*:*:*"},
		{"amzn", "2023", "cpe:2.3:o:amazon:linux:2023:*:*:*:*:*:*:*"},
		{"Debian", "12", "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*"},
		{"nixos", "24.05", "cpe:2.3:o:nixos:nixos:24.05:*:*:*:*:*:*:*"},
		{"arch", "", "cpe:2.3:o:archlinux:arch_linux:*:*:*:*:*:*:*:*"},
		{"weird:id", "1:2", `cpe:2.3:o:weird\:id:weird\:id:1\:2:*:*:*:*:*:*:*`},
		{"", "1", ""},
	} {
		if got := osCPE(scan.OSRelease{ID: c.id, VersionID: c.version}); got != c.want {
			t.Errorf("osCPE(%q,%q) = %q, want %q", c.id, c.version, got, c.want)
		}
	}
}

func TestImageReferenceHelpers(t *testing.T) {
	for ref, want := range map[string][2]string{
		"nginx:1.25":                            {"1.25", "nginx"},
		"docker.io/library/nginx":               {"", "nginx"},
		"registry.example.com:5000/team/App:v2": {"v2", "app"},
		"registry.example.com:5000/team/app":    {"", "app"},
		"app:v2@sha256:0000":                    {"v2", "app"},
		"ghcr.io/org/app@sha256:0000":           {"", "app"},
	} {
		if got := imageTag(ref); got != want[0] {
			t.Errorf("imageTag(%q) = %q, want %q", ref, got, want[0])
		}
		if got := imageRepoName(ref); got != want[1] {
			t.Errorf("imageRepoName(%q) = %q, want %q", ref, got, want[1])
		}
	}
	if imageIDHex("sha256:"+strings.Repeat("a", 64)) != strings.Repeat("a", 64) {
		t.Error("sha256 id not extracted")
	}
	for _, bad := range []string{"", "sha512:" + strings.Repeat("a", 128), "sha256:short", "sha256:" + strings.Repeat("Z", 64)} {
		if imageIDHex(bad) != "" {
			t.Errorf("imageIDHex(%q) accepted", bad)
		}
	}
	r := fixture()
	r.Image.ID = ""
	r.Image.Tags = []string{"team/app"}
	cdx, _ := mustCDX(t, r)
	if cdx.Metadata.Component.Version != "" || cdx.Metadata.Component.Hashes != nil {
		t.Errorf("root without id/tag = %+v", cdx.Metadata.Component)
	}
	spdx, _ := mustSPDX(t, r)
	if spdx.Packages[0].Checksums != nil || spdx.Packages[0].ExternalRefs != nil {
		t.Errorf("spdx root without id = %+v", spdx.Packages[0])
	}
	r.SourceType, r.SourceHash = "docker-archive", strings.Repeat("c", 64)
	cdx, _ = mustCDX(t, r)
	if len(cdx.Metadata.Component.Hashes) != 1 || cdx.Metadata.Component.Hashes[0].Content != strings.Repeat("c", 64) {
		t.Errorf("archive root should carry SourceHash: %+v", cdx.Metadata.Component.Hashes)
	}
}

func TestScanPathListsAreCapped(t *testing.T) {
	r := fixture()
	for i := 0; i < maxListedPaths+10; i++ {
		r.Scan.SkippedPaths = append(r.Scan.SkippedPaths, "/p"+strings.Repeat("x", i%7))
	}
	doc, _ := mustCDX(t, r)
	v, _ := property(doc.Metadata.Component, "bscan:scan:skipped-paths")
	if n := len(strings.Split(v, ";")); n != maxListedPaths {
		t.Errorf("skipped-paths entries = %d, want %d", n, maxListedPaths)
	}
	if v, _ := property(doc.Metadata.Component, "bscan:scan:skipped-paths-count"); v != "62" {
		t.Errorf("skipped-paths-count = %q", v)
	}
	sp, _ := mustSPDX(t, r)
	var meta scan.ScanMetadata
	comment := sp.Packages[0].Annotations[1].Comment
	if err := json.Unmarshal([]byte(comment[strings.Index(comment, "{"):]), &meta); err != nil || len(meta.SkippedPaths) != maxListedPaths {
		t.Errorf("annotation skipped paths = %d (%v)", len(meta.SkippedPaths), err)
	}
}

func TestWriteSupportsAllFormatAliases(t *testing.T) {
	dir := t.TempDir()
	for _, format := range []string{"spdx", "SPDX-JSON", "cyclonedx", "cdx", "cyclonedx-json"} {
		path := dir + "/" + strings.ToLower(format) + ".json"
		if err := Write(path, format, fixture()); err != nil {
			t.Errorf("Write(%s): %v", format, err)
		}
	}
	if err := Write(dir+"/x", "xml", fixture()); err == nil {
		t.Error("unsupported format accepted")
	}
}

func TestUnknownLicenseIDsPreserveFreeformText(t *testing.T) {
	for _, license := range []string{"Proprietary", "LicenseRef-company", "MIT WITH Company-exception"} {
		r := fixture()
		r.Packages = []scan.Package{{Name: "custom", License: license}}
		cdx, _ := mustCDX(t, r)
		var component cdxComponent
		for _, c := range cdx.Components {
			if c.Name == "custom" {
				component = c
			}
		}
		if len(component.Licenses) != 1 || component.Licenses[0].Expression != "" || component.Licenses[0].License == nil || component.Licenses[0].License.Name != license {
			t.Fatalf("CycloneDX lost license text %q: %+v", license, component.Licenses)
		}
		raw, err := SPDX(r)
		if err != nil {
			t.Fatal(err)
		}
		var doc spdxDoc
		if err = json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		var pkg spdxPackage
		for _, p := range doc.Packages {
			if p.Name == "custom" {
				pkg = p
			}
		}
		if pkg.LicenseDeclared != noAssert || !strings.Contains(pkg.LicenseComments, license) {
			t.Fatalf("SPDX lost license text %q: %+v", license, pkg)
		}
	}
}
