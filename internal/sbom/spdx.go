package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

type checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}
type spdxRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}
type spdxAnnotation struct {
	AnnotationDate string `json:"annotationDate"`
	AnnotationType string `json:"annotationType"`
	Annotator      string `json:"annotator"`
	Comment        string `json:"comment"`
}
type spdxPackage struct {
	SPDXID                string           `json:"SPDXID"`
	Name                  string           `json:"name"`
	VersionInfo           string           `json:"versionInfo,omitempty"`
	DownloadLocation      string           `json:"downloadLocation"`
	FilesAnalyzed         bool             `json:"filesAnalyzed"`
	Checksums             []checksum       `json:"checksums,omitempty"`
	LicenseConcluded      string           `json:"licenseConcluded"`
	LicenseDeclared       string           `json:"licenseDeclared"`
	LicenseComments       string           `json:"licenseComments,omitempty"`
	CopyrightText         string           `json:"copyrightText"`
	Summary               string           `json:"summary,omitempty"`
	SourceInfo            string           `json:"sourceInfo,omitempty"`
	PackageComment        string           `json:"comment,omitempty"`
	PrimaryPackagePurpose string           `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs          []spdxRef        `json:"externalRefs,omitempty"`
	Annotations           []spdxAnnotation `json:"annotations,omitempty"`
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
type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}
type spdxDoc struct {
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	SPDXID            string           `json:"SPDXID"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo `json:"creationInfo"`
	Packages          []spdxPackage    `json:"packages"`
	Files             []spdxFile       `json:"files,omitempty"`
	Relationships     []relationship   `json:"relationships"`
}

const (
	spdxRootID = "SPDXRef-Root"
	spdxOSID   = "SPDXRef-OperatingSystem"
	noAssert   = "NOASSERTION"
)

// SPDX renders r as an SPDX 2.3 JSON document.
//
// SPDXRef-Root describes the scanned target (purpose CONTAINER, APPLICATION
// or DEVICE). Image identity goes into versionInfo, checksums and a
// pkg:oci purl; scan and image metadata are attached as annotations and host
// metadata as comment. SPDXRef-OperatingSystem carries the
// distribution with a CPE. Package identifiers are derived from the purl so
// they are stable across runs; licenseDeclared is only ever a valid SPDX
// expression or NOASSERTION, with the raw text preserved in licenseComments.
func SPDX(r scan.Result) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeSPDX(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeSPDX(w io.Writer, r scan.Result) error {
	hash := stableHash(r)
	created := timestampSeconds(r.ScannedAt)
	rp, err := rootPackage(r, created)
	if err != nil {
		return err
	}
	s := newJSONStream(w)
	s.field("spdxVersion", "SPDX-2.3")
	s.field("dataLicense", "CC0-1.0")
	s.field("SPDXID", "SPDXRef-DOCUMENT")
	s.field("name", r.Name)
	s.field("documentNamespace", "https://bongsu.local/spdx/"+hash)
	s.field("creationInfo", spdxCreationInfo{Created: created, Creators: []string{"Tool: bscan-" + ToolVersion}})
	s.fieldName("packages")
	packages := s.array("    ")
	packages.add(rp)
	hasOS := r.OS != nil && r.OS.ID != ""
	if hasOS {
		packages.add(osPackage(*r.OS))
	}
	used := map[string]bool{spdxRootID: true, spdxOSID: true, "SPDXRef-DOCUMENT": true}
	// Only identifiers survive until relationships are written; transformed
	// packages and relationships never accumulate in document-sized slices.
	ids := make([]string, len(r.Packages))
	for i, p := range r.Packages {
		if s.err != nil {
			return s.err
		}
		id := uniqueSPDXID("SPDXRef-Package-"+safeID(packageIdentity(p)), used)
		ids[i] = id
		packages.add(spdxPackageFor(p, id))
	}
	packages.end()
	if len(r.Files) > 0 {
		s.fieldName("files")
		files := s.array("    ")
		for i, f := range r.Files {
			if s.err != nil {
				return s.err
			}
			files.add(spdxFile{SPDXID: fmt.Sprintf("SPDXRef-File-%d", i), FileName: "./" + f.Path,
				Checksums: []checksum{{Algorithm: "SHA256", Value: f.SHA256}}, LicenseConcluded: noAssert, CopyrightText: noAssert})
		}
		files.end()
	}
	s.fieldName("relationships")
	relationships := s.array("    ")
	relationships.add(relationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: spdxRootID})
	if hasOS {
		relationships.add(relationship{SPDXElementID: spdxRootID, RelationshipType: "CONTAINS", RelatedSPDXElement: spdxOSID})
	}
	for i, p := range r.Packages {
		if s.err != nil {
			return s.err
		}
		relationships.add(relationship{SPDXElementID: spdxRootID, RelationshipType: "CONTAINS", RelatedSPDXElement: ids[i]})
		if !p.Indirect && !isOSPackage(p.Type) {
			relationships.add(relationship{SPDXElementID: spdxRootID, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: ids[i]})
		}
	}
	for i := range r.Files {
		if s.err != nil {
			return s.err
		}
		relationships.add(relationship{SPDXElementID: spdxRootID, RelationshipType: "CONTAINS", RelatedSPDXElement: fmt.Sprintf("SPDXRef-File-%d", i)})
	}
	relationships.end()
	return s.end()
}

func rootPackage(r scan.Result, created string) (spdxPackage, error) {
	rp := spdxPackage{SPDXID: spdxRootID, Name: r.Name, DownloadLocation: noAssert, FilesAnalyzed: false,
		LicenseConcluded: noAssert, LicenseDeclared: noAssert, CopyrightText: noAssert, PrimaryPackagePurpose: packagePurpose(r.SourceType)}
	annotate := func(kind string, v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		rp.Annotations = append(rp.Annotations, spdxAnnotation{AnnotationDate: created, AnnotationType: "OTHER",
			Annotator: "Tool: bscan", Comment: "bscan " + kind + " metadata: " + string(b)})
		return nil
	}
	if r.Image != nil {
		tag := imageTag(firstTag(r.Image))
		rp.VersionInfo = tag
		if hexID := imageIDHex(r.Image.ID); hexID != "" {
			rp.Checksums = []checksum{{Algorithm: "SHA256", Value: hexID}}
			name := imageRepoName(firstTag(r.Image))
			if name == "" {
				name = imageRepoName(r.Name)
			}
			if purl := ociPURL(name, hexID, tag); purl != "" {
				rp.ExternalRefs = append(rp.ExternalRefs, spdxRef{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: purl})
			}
		}
		if err := annotate("image", r.Image); err != nil {
			return rp, err
		}
	}
	if r.Scan != nil {
		s := *r.Scan
		s.Excluded, _ = capList(s.Excluded, maxListedPaths)
		s.SkippedPaths, _ = capList(s.SkippedPaths, maxListedPaths)
		if err := annotate("scan", s); err != nil {
			return rp, err
		}
	}
	if r.Host != nil {
		hostJSON, err := json.Marshal(r.Host)
		if err != nil {
			return rp, err
		}
		rp.PackageComment = "bscan host metadata: " + string(hostJSON)
	}
	return rp, nil
}

func osPackage(o scan.OSRelease) spdxPackage {
	p := spdxPackage{SPDXID: spdxOSID, Name: o.ID, VersionInfo: o.VersionID, DownloadLocation: noAssert, FilesAnalyzed: false,
		LicenseConcluded: noAssert, LicenseDeclared: noAssert, CopyrightText: noAssert, Summary: o.PrettyName, PrimaryPackagePurpose: "OPERATING_SYSTEM"}
	if cpe := osCPE(o); cpe != "" {
		p.ExternalRefs = []spdxRef{{ReferenceCategory: "SECURITY", ReferenceType: "cpe23Type", ReferenceLocator: cpe}}
	}
	var notes []string
	if o.Codename != "" {
		notes = append(notes, "codename="+o.Codename)
	}
	if o.IDLike != "" {
		notes = append(notes, "id_like="+o.IDLike)
	}
	if len(notes) > 0 {
		p.PackageComment = "bscan os-release: " + strings.Join(notes, "; ")
	}
	return p
}

func spdxPackageFor(p scan.Package, id string) spdxPackage {
	pkg := spdxPackage{SPDXID: id, Name: p.Name, VersionInfo: p.Version, DownloadLocation: noAssert, FilesAnalyzed: false,
		LicenseConcluded: noAssert, LicenseDeclared: noAssert, CopyrightText: noAssert, PrimaryPackagePurpose: "LIBRARY"}
	if strings.TrimSpace(p.License) != "" {
		if expr, ok := licenseExpression(p.License); ok {
			pkg.LicenseDeclared = expr
		} else if raw := firstLine(p.License, maxLicenseText); raw != "" {
			pkg.LicenseComments = "declared license text is not an SPDX expression: " + raw
		}
	}
	if p.Source != "" {
		pkg.SourceInfo = "found in " + p.Source
	}
	if p.PURL != "" {
		pkg.ExternalRefs = append(pkg.ExternalRefs, spdxRef{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: p.PURL})
	}
	if p.CPE != "" {
		pkg.ExternalRefs = append(pkg.ExternalRefs, spdxRef{ReferenceCategory: "SECURITY", ReferenceType: "cpe23Type", ReferenceLocator: p.CPE})
	}
	var notes []string
	if p.VersionOriginal != "" {
		notes = append(notes, "bscan:version-original="+p.VersionOriginal)
	}
	if p.Evidence != "" {
		notes = append(notes, "evidence="+p.Evidence)
	}
	if isBinarySource(p) {
		notes = append(notes, "source-kind=binary")
	}
	if p.Layer != "" {
		notes = append(notes, "layer="+p.Layer)
	}
	if u := upstream(p); u != "" && p.PURL == "" {
		notes = append(notes, "upstream="+u)
	}
	if p.Indirect {
		notes = append(notes, "indirect=true")
	}
	if p.Dev {
		notes = append(notes, "dev=true")
	}
	if len(notes) > 0 {
		pkg.PackageComment = "bscan: " + strings.Join(notes, "; ")
	}
	return pkg
}

// packageIdentity is the raw material for a package's SPDX identifier: the
// purl when there is one, otherwise "type-name-version".
func packageIdentity(p scan.Package) string {
	if p.PURL != "" {
		return p.PURL
	}
	parts := []string{p.Type, p.Name, p.Version}
	out := parts[:0]
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, "-")
}

// uniqueSPDXID returns base or, if base is taken, the first free
// "base-<n>" with n counting from 2, and records the result in used.
func uniqueSPDXID(base string, used map[string]bool) string {
	id := base
	for n := 2; used[id]; n++ {
		id = base + "-" + strconv.Itoa(n)
	}
	used[id] = true
	return id
}

// packagePurpose maps Result.SourceType to an SPDX primaryPackagePurpose.
func packagePurpose(source string) string {
	switch {
	case isContainerSource(source):
		return "CONTAINER"
	case source == "host":
		return "DEVICE"
	}
	return "APPLICATION"
}
