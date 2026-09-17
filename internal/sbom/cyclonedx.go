package sbom

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}
type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type cdxLicenseName struct {
	Name string `json:"name"`
}

// cdxLicense is one entry of a component's licenses array: either a
// license object (free-form name) or an SPDX expression, never both.
type cdxLicense struct {
	License    *cdxLicenseName `json:"license,omitempty"`
	Expression string          `json:"expression,omitempty"`
}
type cdxComponent struct {
	Type        string        `json:"type"`
	BOMRef      string        `json:"bom-ref,omitempty"`
	Group       string        `json:"group,omitempty"`
	Name        string        `json:"name"`
	Version     string        `json:"version,omitempty"`
	Description string        `json:"description,omitempty"`
	Scope       string        `json:"scope,omitempty"`
	Hashes      []cdxHash     `json:"hashes,omitempty"`
	Licenses    []cdxLicense  `json:"licenses,omitempty"`
	CPE         string        `json:"cpe,omitempty"`
	PURL        string        `json:"purl,omitempty"`
	Properties  []cdxProperty `json:"properties,omitempty"`
}
type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}
type cdxTools struct {
	Components []cdxComponent `json:"components"`
}
type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     cdxTools     `json:"tools"`
	Component cdxComponent `json:"component"`
}
type cdxDoc struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Serial       string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components,omitempty"`
	Dependencies []cdxDependency `json:"dependencies"`
}

// CycloneDX renders r as a CycloneDX 1.6 JSON BOM.
//
// Layout: metadata.component is the scanned target (container for images
// and archives, application for directories and hosts) carrying image, scan,
// host and os-release facts as bscan:* properties. components[0] is an
// operating-system component with a CPE when os-release was found, so
// vulnerability matchers can pick the right distribution feed; every
// inventoried package follows as a library. The dependency graph is the
// minimal valid one: the root depends on every component.
func CycloneDX(r scan.Result) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCycloneDX(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCycloneDX(w io.Writer, r scan.Result) error {
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
	s := newJSONStream(w)
	s.field("bomFormat", doc.BOMFormat)
	s.field("specVersion", doc.SpecVersion)
	s.field("serialNumber", doc.Serial)
	s.field("version", doc.Version)
	s.field("metadata", doc.Metadata)
	refs := packageRefs(r.Packages)
	var osRef string
	if r.OS != nil && r.OS.ID != "" {
		osRef = osComponent(*r.OS).BOMRef
	}
	if osRef != "" || len(refs) > 0 {
		s.fieldName("components")
		components := s.array("    ")
		if osRef != "" {
			components.add(osComponent(*r.OS))
		}
		for i, ref := range refs {
			if s.err != nil {
				return s.err
			}
			components.add(packageComponent(r.Packages[i], ref))
		}
		components.end()
	}
	s.fieldName("dependencies")
	dependencies := s.array("    ")
	dependencies.next()
	s.text("{\n      \"ref\": ")
	s.value(root.BOMRef, "      ")
	s.text(",\n      \"dependsOn\": ")
	dependsOn := s.array("        ")
	if osRef != "" {
		dependsOn.add(osRef)
	}
	for _, ref := range refs {
		if s.err != nil {
			return s.err
		}
		dependsOn.add(ref)
	}
	dependsOn.end()
	s.text("\n    }")
	if osRef != "" {
		dependencies.add(cdxDependency{Ref: osRef, DependsOn: []string{}})
	}
	for _, ref := range refs {
		if s.err != nil {
			return s.err
		}
		dependencies.add(cdxDependency{Ref: ref, DependsOn: []string{}})
	}
	dependencies.end()
	return s.end()
}

// packageRefs assigns one bom-ref per package. A purl that occurs once is
// used verbatim; duplicated purls get "<purl>#<n>" with n counting the
// occurrences from 1, skipping references reserved by other purls;
// packages without a purl get "pkg-<index>-<name>".
// Purls always start with "pkg:" so the three forms never collide with each
// other or with the root/os refs.
func packageRefs(pkgs []scan.Package) []string {
	total := map[string]int{}
	for _, p := range pkgs {
		if p.PURL != "" {
			total[p.PURL]++
		}
	}
	seen := map[string]int{}
	used := map[string]bool{}
	for purl := range total {
		used[purl] = true
	}
	refs := make([]string, len(pkgs))
	for i, p := range pkgs {
		switch {
		case p.PURL == "":
			refs[i] = fmt.Sprintf("pkg-%d-%s", i, safeID(p.Name))
		case total[p.PURL] == 1:
			refs[i] = p.PURL
		default:
			for {
				seen[p.PURL]++
				ref := p.PURL + "#" + strconv.Itoa(seen[p.PURL])
				if !used[ref] {
					refs[i] = ref
					used[ref] = true
					break
				}
			}
		}
	}
	return refs
}

func osComponent(o scan.OSRelease) cdxComponent {
	ref := "os-" + safeID(strings.ToLower(o.ID))
	if o.VersionID != "" {
		ref += "-" + safeID(o.VersionID)
	}
	c := cdxComponent{Type: "operating-system", BOMRef: ref, Name: o.ID, Version: o.VersionID, Description: o.PrettyName, CPE: osCPE(o)}
	addProperty(&c.Properties, "bscan:os:codename", o.Codename)
	addProperty(&c.Properties, "bscan:os:id-like", o.IDLike)
	return c
}

func packageComponent(p scan.Package, ref string) cdxComponent {
	c := cdxComponent{Type: "library", BOMRef: ref, Name: p.Name, Version: p.Version, CPE: p.CPE, PURL: p.PURL, Scope: "required"}
	if p.Dev {
		c.Scope = "optional"
	}
	if !isOSPackage(p.Type) {
		c.Group = p.Namespace
	}
	c.Licenses = cdxLicenses(p.License)
	addProperty(&c.Properties, "bscan:source", p.Source)
	addProperty(&c.Properties, "bscan:evidence", p.Evidence)
	addProperty(&c.Properties, "bscan:version-original", p.VersionOriginal)
	if isBinarySource(p) {
		addProperty(&c.Properties, "bscan:source-kind", "binary")
	}
	addProperty(&c.Properties, "bscan:layer", p.Layer)
	addProperty(&c.Properties, "bscan:upstream", upstream(p))
	addProperty(&c.Properties, "bscan:distro", p.Distro)
	addProperty(&c.Properties, "bscan:arch", p.Arch)
	if p.Indirect {
		addProperty(&c.Properties, "bscan:indirect", "true")
	}
	if p.Dev {
		addProperty(&c.Properties, "bscan:dev", "true")
	}
	return c
}

// cdxLicenses turns a package's license field into a licenses array: an
// SPDX expression when it parses as one, otherwise a named license holding
// the first line of the text. Empty input yields nil so the key is omitted.
func cdxLicenses(s string) []cdxLicense {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if expr, ok := licenseExpression(s); ok {
		return []cdxLicense{{Expression: expr}}
	}
	name := firstLine(s, maxLicenseText)
	if name == "" {
		return nil
	}
	return []cdxLicense{{License: &cdxLicenseName{Name: name}}}
}

func addProperty(props *[]cdxProperty, name, value string) {
	if value == "" {
		return
	}
	*props = append(*props, cdxProperty{Name: name, Value: value})
}

func rootProperties(r scan.Result) []cdxProperty {
	var props []cdxProperty
	if r.Host != nil {
		props = append(props, hostProperties(*r.Host)...)
	}
	if r.Image != nil {
		props = append(props, imageProperties(*r.Image)...)
	}
	if r.Scan != nil {
		props = append(props, scanProperties(*r.Scan)...)
	}
	if r.OS != nil {
		addProperty(&props, "bscan:os:codename", r.OS.Codename)
		addProperty(&props, "bscan:os:id-like", r.OS.IDLike)
		addProperty(&props, "bscan:os:pretty-name", r.OS.PrettyName)
	}
	return props
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

func imageProperties(img scan.ImageMetadata) []cdxProperty {
	var props []cdxProperty
	addProperty(&props, "bscan:image:id", img.ID)
	addProperty(&props, "bscan:image:digest", img.Digest)
	addProperty(&props, "bscan:image:tags", strings.Join(img.Tags, ","))
	addProperty(&props, "bscan:image:repo-digests", strings.Join(img.RepoDigests, ","))
	addProperty(&props, "bscan:image:os", img.OS)
	addProperty(&props, "bscan:image:architecture", img.Architecture)
	addProperty(&props, "bscan:image:variant", img.Variant)
	addProperty(&props, "bscan:image:created", img.Created)
	addProperty(&props, "bscan:image:container-id", img.ContainerID)
	for i, l := range img.Layers {
		v := l.Digest
		if l.DiffID != "" {
			v += " diff_id=" + l.DiffID
		}
		v += " verified=" + strconv.FormatBool(l.Verified)
		addProperty(&props, "bscan:image:layer:"+strconv.Itoa(i), v)
	}
	return props
}

func scanProperties(s scan.ScanMetadata) []cdxProperty {
	var props []cdxProperty
	addProperty(&props, "bscan:scan:partial", strconv.FormatBool(s.Partial))
	addProperty(&props, "bscan:scan:euid", strconv.Itoa(s.EUID))
	if s.PermissionDenied > 0 {
		addProperty(&props, "bscan:scan:permission-denied", strconv.Itoa(s.PermissionDenied))
	}
	if s.SkippedErrors > 0 {
		addProperty(&props, "bscan:scan:skipped-errors", strconv.Itoa(s.SkippedErrors))
	}
	if s.MetadataSkipped > 0 {
		addProperty(&props, "bscan:scan:metadata-skipped", strconv.Itoa(s.MetadataSkipped))
	}
	if s.DeclaredSkipped > 0 {
		addProperty(&props, "bscan:scan:declared-skipped", strconv.Itoa(s.DeclaredSkipped))
	}
	if s.FilesVisited > 0 {
		addProperty(&props, "bscan:scan:files-visited", strconv.FormatInt(s.FilesVisited, 10))
	}
	if s.InContainer {
		addProperty(&props, "bscan:scan:in-container", "true")
	}
	addProperty(&props, "bscan:scan:limit-reached", s.LimitReached)
	if list, truncated := capList(s.Excluded, maxListedPaths); len(list) > 0 {
		addProperty(&props, "bscan:scan:excluded", strings.Join(list, ";"))
		total := s.ExcludedCount
		if total < len(s.Excluded) {
			total = len(s.Excluded)
		}
		if truncated || total > len(list) {
			addProperty(&props, "bscan:scan:excluded-count", strconv.Itoa(total))
		}
	}
	if list, truncated := capList(s.SkippedPaths, maxListedPaths); len(list) > 0 {
		addProperty(&props, "bscan:scan:skipped-paths", strings.Join(list, ";"))
		if truncated {
			addProperty(&props, "bscan:scan:skipped-paths-count", strconv.Itoa(len(s.SkippedPaths)))
		}
	}
	return props
}
