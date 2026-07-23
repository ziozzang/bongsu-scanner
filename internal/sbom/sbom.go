package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

var invalidID = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

type checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}
type spdxPackage struct {
	SPDXID           string    `json:"SPDXID"`
	Name             string    `json:"name"`
	VersionInfo      string    `json:"versionInfo,omitempty"`
	DownloadLocation string    `json:"downloadLocation"`
	FilesAnalyzed    bool      `json:"filesAnalyzed"`
	LicenseConcluded string    `json:"licenseConcluded"`
	LicenseDeclared  string    `json:"licenseDeclared"`
	CopyrightText    string    `json:"copyrightText"`
	PackageComment   string    `json:"packageComment,omitempty"`
	ExternalRefs     []spdxRef `json:"externalRefs,omitempty"`
}
type spdxRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}
type spdxFile struct {
	SPDXID           string     `json:"SPDXID"`
	FileName         string     `json:"fileName"`
	Checksums        []checksum `json:"checksums"`
	LicenseConcluded string     `json:"licenseConcluded"`
	CopyrightText    string     `json:"copyrightText"`
}
type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}
type spdxDoc struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      any            `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages"`
	Files             []spdxFile     `json:"files,omitempty"`
	Relationships     []relationship `json:"relationships"`
}

func SPDX(r scan.Result) ([]byte, error) {
	hash := stableHash(r)
	doc := spdxDoc{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name: r.Name, DocumentNamespace: "https://bongsu.local/spdx/" + hash,
		CreationInfo:  map[string]any{"created": r.ScannedAt, "creators": []string{"Tool: bscan"}},
		Relationships: []relationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Root"}}}
	rp := spdxPackage{SPDXID: "SPDXRef-Root", Name: r.Name, DownloadLocation: "NOASSERTION",
		FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"}
	if r.Host != nil {
		hostJSON, err := json.Marshal(r.Host)
		if err != nil {
			return nil, err
		}
		rp.PackageComment = "bscan host metadata: " + string(hostJSON)
	}
	doc.Packages = append(doc.Packages, rp)
	for i, p := range r.Packages {
		id := fmt.Sprintf("SPDXRef-Package-%d-%s", i, safeID(p.Name))
		pkg := spdxPackage{SPDXID: id, Name: p.Name, VersionInfo: p.Version, DownloadLocation: "NOASSERTION",
			FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: license(p.License), CopyrightText: "NOASSERTION"}
		if p.Source != "" {
			pkg.PackageComment = "bscan detected package metadata at " + p.Source
		}
		if p.PURL != "" {
			pkg.ExternalRefs = []spdxRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: p.PURL}}
		}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, relationship{SPDXElementID: "SPDXRef-Root", RelationshipType: "CONTAINS", RelatedSPDXElement: id})
	}
	for i, f := range r.Files {
		id := fmt.Sprintf("SPDXRef-File-%d", i)
		doc.Files = append(doc.Files, spdxFile{SPDXID: id, FileName: "./" + f.Path,
			Checksums: []checksum{{Algorithm: "SHA256", Value: f.SHA256}}, LicenseConcluded: "NOASSERTION", CopyrightText: "NOASSERTION"})
		doc.Relationships = append(doc.Relationships, relationship{SPDXElementID: "SPDXRef-Root", RelationshipType: "CONTAINS", RelatedSPDXElement: id})
	}
	return json.MarshalIndent(doc, "", "  ")
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}
type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	Hashes     []cdxHash     `json:"hashes,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}
type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type cdxDoc struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Serial      string         `json:"serialNumber"`
	Version     int            `json:"version"`
	Metadata    any            `json:"metadata"`
	Components  []cdxComponent `json:"components,omitempty"`
}

func CycloneDX(r scan.Result) ([]byte, error) {
	hash := stableHash(r)
	root := cdxComponent{Type: componentType(r.SourceType), BOMRef: "root-" + hash[:16], Name: r.Name}
	if r.SourceHash != "" {
		root.Hashes = []cdxHash{{Alg: "SHA-256", Content: r.SourceHash}}
	}
	if r.Host != nil {
		root.Properties = hostProperties(*r.Host)
	}
	doc := cdxDoc{BOMFormat: "CycloneDX", SpecVersion: "1.6", Serial: "urn:uuid:" + uuidFromHash(hash), Version: 1,
		Metadata: map[string]any{"timestamp": r.ScannedAt, "tools": map[string]any{"components": []any{map[string]any{"type": "application", "name": "bscan"}}}, "component": root}}
	for i, p := range r.Packages {
		c := cdxComponent{Type: "library", BOMRef: fmt.Sprintf("pkg-%d-%s", i, safeID(p.Name)), Name: p.Name, Version: p.Version, PURL: p.PURL}
		if p.Source != "" {
			c.Properties = []cdxProperty{{Name: "bscan:source", Value: p.Source}}
		}
		doc.Components = append(doc.Components, c)
	}
	return json.MarshalIndent(doc, "", "  ")
}

func Write(path, format string, r scan.Result) error {
	var b []byte
	var err error
	switch strings.ToLower(format) {
	case "spdx", "spdx-json":
		b, err = SPDX(r)
	case "cyclonedx", "cdx", "cyclonedx-json":
		b, err = CycloneDX(r)
	default:
		return fmt.Errorf("unsupported SBOM format %q", format)
	}
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func safeID(s string) string {
	s = invalidID.ReplaceAllString(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}
func stableHash(r scan.Result) string {
	h := sha256.New()
	h.Write([]byte(r.Name + "\x00" + r.SourceHash + "\x00" + r.ScannedAt.UTC().Format("20060102T150405.000000000Z")))
	if r.Host != nil {
		b, _ := json.Marshal(r.Host)
		h.Write(append([]byte("\x00host\x00"), b...))
	}
	for _, f := range r.Files {
		h.Write([]byte("\x00" + f.Path + "\x00" + f.SHA256))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hostProperties(host scan.HostMetadata) []cdxProperty {
	values := [][2]string{
		{"bscan:host:hostname", host.Hostname},
		{"bscan:host:operating-system", host.OperatingSystem},
		{"bscan:host:os-version", host.OSVersion},
		{"bscan:host:kernel", host.Kernel},
		{"bscan:host:architecture", host.Architecture},
		{"bscan:host:cpu-model", host.CPUModel},
		{"bscan:host:cpu-count", fmt.Sprintf("%d", host.CPUCount)},
		{"bscan:host:memory-bytes", fmt.Sprintf("%d", host.MemoryBytes)},
		{"bscan:host:ip-addresses", strings.Join(host.IPAddresses, ",")},
	}
	out := make([]cdxProperty, 0, len(values))
	for _, value := range values {
		if value[1] != "" && value[1] != "0" {
			out = append(out, cdxProperty{Name: value[0], Value: value[1]})
		}
	}
	return out
}
func uuidFromHash(h string) string {
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}
func license(s string) string {
	if s == "" {
		return "NOASSERTION"
	}
	return s
}
func componentType(source string) string {
	if strings.Contains(source, "image") || strings.Contains(source, "archive") || source == "container" {
		return "container"
	}
	return "application"
}
