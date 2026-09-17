// Package match performs offline advisory matching against SBOM inventories.
package match

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/ziozzang/bongsu-scanner/internal/purl"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Subject struct {
	CPE             string `json:",omitempty"`
	Ref             string
	Name            string
	Version         string
	PURL            purl.PURL
	Type            string
	Ecosystem       string
	Release         string
	Upstream        string
	UpstreamVersion string
	Properties      map[string]string
}
type OSInfo struct {
	ID        string
	VersionID string
	Codename  string
}
type Context struct {
	OS      *OSInfo
	Root    string
	MixedOS bool
}
type Document struct {
	Subjects []Subject
	Context  Context
	// Raw is the editable BOM for Load. LoadFile retains only assessment metadata
	// here and reopens its verified source when writing CycloneDX.
	Raw    map[string]any
	Format string
	// File-backed documents retain only matching data. The digest prevents output
	// from silently attaching findings to an input modified after loading.
	sourcePath string
	sourceHash [sha256.Size]byte
}

func LoadFile(path string) (Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return Document{}, err
	}
	defer f.Close()
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Document{}, err
	}
	hash := sha256.New()
	d, err := loadStream(io.TeeReader(f, hash))
	if err != nil {
		return d, err
	}
	d.sourcePath = absolute
	copy(d.sourceHash[:], hash.Sum(nil))
	return d, nil
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func obj(v any) map[string]any              { m, _ := v.(map[string]any); return m }
func arr(v any) []any                       { a, _ := v.([]any); return a }
func props(v any) map[string]string {
	out := map[string]string{}
	for _, x := range arr(v) {
		m := obj(x)
		out[str(m, "name")] = str(m, "value")
	}
	return out
}
func Load(data []byte) (Document, error) {
	d := Document{}
	if e := json.Unmarshal(data, &d.Raw); e != nil {
		return d, e
	}
	return loadDocument(d)
}

func loadDocument(d Document) (Document, error) {
	var components []map[string]any
	switch {
	case str(d.Raw, "bomFormat") == "CycloneDX":
		d.Format = "cyclonedx"
		switch str(d.Raw, "specVersion") {
		case "1.4", "1.5", "1.6":
		default:
			return d, fmt.Errorf("unsupported CycloneDX version %q", str(d.Raw, "specVersion"))
		}
		var walk func([]any)
		walk = func(a []any) {
			for _, v := range a {
				m := obj(v)
				components = append(components, m)
				walk(arr(m["components"]))
			}
		}
		walk(arr(d.Raw["components"]))
		root := obj(obj(d.Raw["metadata"])["component"])
		d.Context.Root = str(root, "bom-ref")
		rp := props(root["properties"])
		if id := rp["bscan:host:operating-system"]; id != "" {
			d.Context.OS = &OSInfo{ID: strings.ToLower(id), VersionID: rp["bscan:host:os-version"], Codename: rp["bscan:os:codename"]}
		}
		if root != nil {
			walk([]any{root})
		}
		var componentOS *OSInfo
		for _, m := range components {
			if str(m, "type") == "operating-system" {
				candidate := &OSInfo{ID: strings.ToLower(str(m, "name")), VersionID: str(m, "version"), Codename: props(m["properties"])["bscan:os:codename"]}
				if componentOS == nil {
					componentOS = candidate
				} else if !sameOS(componentOS, candidate) {
					d.Context.MixedOS = true
				}
			}
		}
		if d.Context.OS != nil && componentOS != nil && conflictingOS(d.Context.OS, componentOS) {
			d.Context.MixedOS = true
		}
		if d.Context.MixedOS {
			d.Context.OS = nil
		} else if componentOS != nil {
			d.Context.OS = componentOS
		}
	case str(d.Raw, "spdxVersion") == "SPDX-2.2" || str(d.Raw, "spdxVersion") == "SPDX-2.3":
		d.Format = "spdx"
		var componentOS *OSInfo
		for _, v := range arr(d.Raw["packages"]) {
			m := obj(v)
			components = append(components, m)
			if str(m, "SPDXID") == "SPDXRef-Root" {
				d.Context.Root = "SPDXRef-Root"
			}
			if d.Context.OS == nil {
				comment := str(m, "packageComment")
				if strings.HasPrefix(comment, "bscan host metadata: ") {
					var host struct {
						ID      string `json:"operating_system"`
						Version string `json:"os_version"`
					}
					if json.Unmarshal([]byte(strings.TrimPrefix(comment, "bscan host metadata: ")), &host) == nil && host.ID != "" {
						d.Context.OS = &OSInfo{ID: strings.ToLower(host.ID), VersionID: host.Version}
					}
				}
			}
			if str(m, "primaryPackagePurpose") == "OPERATING-SYSTEM" {
				candidate := &OSInfo{ID: strings.ToLower(str(m, "name")), VersionID: str(m, "versionInfo")}
				if componentOS == nil {
					componentOS = candidate
				} else if !sameOS(componentOS, candidate) {
					d.Context.MixedOS = true
				}
			}
		}
		if d.Context.OS != nil && componentOS != nil && conflictingOS(d.Context.OS, componentOS) {
			d.Context.MixedOS = true
		}
		if d.Context.MixedOS {
			d.Context.OS = nil
		} else if componentOS != nil {
			d.Context.OS = componentOS
		}
	default:
		return d, fmt.Errorf("unsupported SBOM format (expected CycloneDX or SPDX JSON)")
	}
	d.Subjects = make([]Subject, 0, len(components))
	refs := make(map[string]int, len(components))
	for _, m := range components {
		s := Subject{CPE: str(m, "cpe"), Name: str(m, "name"), Version: str(m, "version"), Ref: str(m, "bom-ref"), Type: str(m, "type"), Properties: props(m["properties"])}
		ps := str(m, "purl")
		if d.Format == "spdx" {
			s.Version = str(m, "versionInfo")
			s.Ref = str(m, "SPDXID")
			for _, r := range arr(m["externalRefs"]) {
				r := obj(r)
				if str(r, "referenceType") == "purl" {
					ps = str(r, "referenceLocator")
				}
			}
		}
		if s.CPE == "" && (s.Type == "operating-system" || str(m, "primaryPackagePurpose") == "OPERATING-SYSTEM") {
			continue
		}
		if s.Ref == "" {
			s.Ref = fmt.Sprintf("bscan-subject-%d", len(d.Subjects)+1)
			if d.Format == "cyclonedx" {
				m["bom-ref"] = s.Ref
			}
		}
		refs[s.Ref]++
		if refs[s.Ref] > 1 {
			return d, fmt.Errorf("duplicate component reference %q", s.Ref)
		}
		if ps != "" {
			p, e := purl.Parse(ps)
			if e != nil {
				return d, fmt.Errorf("component %s: %w", s.Ref, e)
			}
			s.PURL = p
			s.Type = p.Type
			s.Ecosystem = vulndb.PURLTypeToEcosystem(p.Type, p.Namespace)
			if s.Version == "" {
				s.Version = p.Version
			}
			s.Name = p.FullName()
			distro := p.Qualifiers["distro"]
			if distro == "" {
				distro = s.Properties["bscan:distro"]
			}
			if distro != "" {
				s.Release = release(s.Ecosystem, distro)
			} else if d.Context.OS != nil && strings.EqualFold(d.Context.OS.ID, strings.ToLower(s.Ecosystem)) {
				osVersion := d.Context.OS.VersionID
				if osVersion == "" {
					osVersion = d.Context.OS.Codename
				}
				s.Release = release(s.Ecosystem, osVersion)
			}
			upstream := p.Qualifiers["upstream"]
			if upstream == "" {
				upstream = s.Properties["bscan:upstream"]
			}
			s.Upstream = upstream
			if i := strings.LastIndexByte(upstream, '@'); i > 0 {
				s.Upstream, s.UpstreamVersion = upstream[:i], upstream[i+1:]
			}
		}
		d.Subjects = append(d.Subjects, s)
	}
	return d, nil
}

// Missing metadata is not a conflict; compare only facts supplied by both
// the legacy host properties and the operating-system component.
func conflictingOS(a, b *OSInfo) bool {
	if !strings.EqualFold(strings.TrimSpace(a.ID), strings.TrimSpace(b.ID)) {
		return true
	}
	for _, pair := range [][2]string{{a.VersionID, b.VersionID}, {a.Codename, b.Codename}} {
		x, y := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if x != "" && y != "" && x != y {
			return true
		}
	}
	return false
}

func sameOS(a, b *OSInfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	return strings.EqualFold(strings.TrimSpace(a.ID), strings.TrimSpace(b.ID)) &&
		strings.TrimSpace(a.VersionID) == strings.TrimSpace(b.VersionID) &&
		strings.TrimSpace(a.Codename) == strings.TrimSpace(b.Codename)
}
func release(eco, v string) string {
	if eco == "Ubuntu" {
		return vulndb.NormalizeUbuntuRelease(v)
	}
	// OSV distribution suffixes are not uniform. Rocky/Alma use major
	// versions; openSUSE uses product names, and SUSE uses service packs.
	// Red Hat additionally requires repository/product metadata absent
	// from os-release, so a bare rhel-N must not invent a release scope.
	switch eco {
	case "Rocky Linux", "AlmaLinux", "openSUSE", "SUSE", "Red Hat":
		v = strings.TrimSpace(v)
		if suffix, ok := strings.CutPrefix(v, eco+":"); ok {
			return suffix
		}
		prefixes := map[string][]string{
			"Rocky Linux": {"rocky-linux-", "rockylinux-", "rocky-"},
			"AlmaLinux":   {"almalinux-", "alma-"},
			"openSUSE":    {"opensuse-leap-", "opensuse-"},
			"SUSE":        {"sles-", "suse-"},
		}
		if eco == "Red Hat" {
			return ""
		}
		if eco == "openSUSE" && (v == "opensuse-tumbleweed" || strings.HasPrefix(v, "opensuse-tumbleweed-")) {
			return "Tumbleweed"
		}
		for _, prefix := range prefixes[eco] {
			if strings.HasPrefix(v, prefix) {
				v = strings.TrimPrefix(v, prefix)
				break
			}
		}
		parts := strings.Split(v, ".")
		for _, part := range parts {
			if part == "" || strings.Trim(part, "0123456789") != "" {
				return ""
			}
		}
		switch eco {
		case "Rocky Linux", "AlmaLinux":
			return parts[0]
		case "openSUSE":
			if len(parts) >= 2 {
				return "Leap " + parts[0] + "." + parts[1]
			}
		case "SUSE":
			v = "Linux Enterprise Server " + parts[0]
			if len(parts) >= 2 && strings.Trim(parts[1], "0") != "" {
				v += " SP" + strings.TrimLeft(parts[1], "0")
			}
			return v
		}
		return ""
	}
	switch eco {
	case "Debian", "Alpine":
	default:
		return ""
	}
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), strings.ToLower(eco)+"-"))
	if eco == "Debian" {
		if numeric := map[string]string{"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14", "sid": "sid", "unstable": "sid"}[v]; numeric != "" {
			v = numeric
		}
	}
	if eco == "Alpine" {
		v = strings.TrimPrefix(v, "v")
		p := strings.Split(v, ".")
		if len(p) >= 2 && isDigits(p[0]) && isDigits(p[1]) {
			return "v" + p[0] + "." + p[1]
		}
		return ""
	}
	return v
}

func isDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// Retain the large component array as raw JSON after extracting subjects.
// This preserves Load's exact parsing behavior, including unusual JSON types
// and generated refs, while allowing its temporary object tree to be reclaimed.
func loadCompactFile(data []byte) (Document, error) {
	d, err := Load(data)
	if err != nil || d.Format != "cyclonedx" {
		return d, err
	}
	// Load inserts refs where absent. Re-encoding these objects retains those
	// inserted refs and the same JSON values as the editable-map representation.
	value, present := d.Raw["components"]
	if !present {
		return d, nil
	}
	components, err := json.Marshal(value)
	if err != nil {
		return d, err
	}
	d.Raw["components"] = json.RawMessage(components)
	return d, nil
}

// streamInventory holds only fields needed by matching, never the original BOM.
type streamInventory struct {
	blocks      []*[128]streamComponent
	count       int
	context     Context
	componentOS *OSInfo
	strings     map[string]string
	stringBytes int
}

type streamComponent struct {
	subject       streamSubject
	purl, purpose string
	packageInfo   *streamPackageInfo
}

type streamPackageInfo struct {
	comment         string
	annotations     []any
	externalPURL    string
	hasExternalPURL bool
}

// Keep the parse stage compact: parsed PURLs and derived matching fields are
// populated only after the final OS context is known.
type streamSubject struct {
	Ref, Name, Version, Type, CPE string
	Properties                    map[string]string
}

// Decoder.Token in older supported Go releases does not enforce Unmarshal's
// nesting limit across successive calls. Keep that validation explicitly.
type sbomDecoder struct {
	*json.Decoder
	depth int
}

func (dec *sbomDecoder) Token() (json.Token, error) {
	token, err := dec.Decoder.Token()
	if err != nil {
		return token, err
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{', '[':
			dec.depth++
			if dec.depth > 10000 {
				return nil, fmt.Errorf("SBOM exceeds maximum JSON depth")
			}
		case '}', ']':
			dec.depth--
		}
	}
	return token, nil
}

// skipJSON consumes one complete value, with Decoder enforcing JSON syntax and
// nesting limits even for fields the matcher does not use.
func skipJSON(dec *sbomDecoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	return skipJSONToken(dec, token)
}
func skipJSONToken(dec *sbomDecoder, token json.Token) error {
	if delim, ok := token.(json.Delim); ok && (delim == '{' || delim == '[') {
		for dec.More() {
			if err := skipJSON(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	return nil
}
func streamString(dec *sbomDecoder) (string, error) {
	token, err := dec.Token()
	if err != nil {
		return "", err
	}
	if err := skipJSONToken(dec, token); err != nil {
		return "", err
	}
	value, _ := token.(string)
	return value, nil
}

// streamPairs visits the two selected string fields of each array entry. It
// preserves legacy behavior for non-object entries and non-string values.
func streamPairs(dec *sbomDecoder, first, second string, visit func(string, string)) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('[') {
		return skipJSONToken(dec, token)
	}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		var a, b string
		if token == json.Delim('{') {
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				switch key {
				case first:
					a, err = streamString(dec)
				case second:
					b, err = streamString(dec)
				default:
					err = skipJSON(dec)
				}
				if err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		} else if err := skipJSONToken(dec, token); err != nil {
			return err
		}
		visit(a, b)
	}
	_, err = dec.Token()
	return err
}
func (inv *streamInventory) streamProperties(dec *sbomDecoder) (map[string]string, error) {
	properties := map[string]string{}
	err := streamPairs(dec, "name", "value", func(name, value string) { properties[inv.intern(name)] = inv.intern(value) })
	return properties, err
}

// Source paths and property names repeat across thousands of components. Only
// immutable strings are shared, with a bounded cache even for hostile inputs.
func (inv *streamInventory) intern(value string) string {
	if existing, ok := inv.strings[value]; ok {
		return existing
	}
	if len(inv.strings) < 8192 && inv.stringBytes+len(value) <= 1<<20 {
		if inv.strings == nil {
			inv.strings = make(map[string]string)
		}
		inv.strings[value] = value
		inv.stringBytes += len(value)
	}
	return value
}
func (inv *streamInventory) at(i int) *streamComponent { return &inv.blocks[i/128][i%128] }
func (inv *streamInventory) append(c streamComponent) {
	if inv.count == len(inv.blocks)*128 {
		inv.blocks = append(inv.blocks, new([128]streamComponent))
	}
	*inv.at(inv.count) = c
	inv.count++
}
func (inv *streamInventory) truncate(n int) {
	for i := n; i < inv.count; i++ {
		*inv.at(i) = streamComponent{}
	}
	inv.count = n
}
func (inv *streamInventory) os(candidate *OSInfo) {
	if inv.componentOS == nil {
		inv.componentOS = candidate
	} else if !sameOS(inv.componentOS, candidate) {
		inv.context.MixedOS = true
	}
}
func (inv *streamInventory) component(dec *sbomDecoder, spdx bool) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	return inv.componentToken(dec, spdx, token)
}
func (inv *streamInventory) componentToken(dec *sbomDecoder, spdx bool, token json.Token) error {
	if !spdx && token != json.Delim('{') {
		return fmt.Errorf("CycloneDX component must be an object")
	}
	c := streamComponent{subject: streamSubject{Properties: map[string]string{}}}
	if spdx {
		c.packageInfo = &streamPackageInfo{}
	}
	// Reserve the parent's position before visiting children, regardless of JSON
	// member order. OS entries are removed after context has been established.
	index := inv.count
	inv.append(streamComponent{})
	if token == json.Delim('{') {
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			var dst *string
			switch key {
			case "name":
				dst = &c.subject.Name
			case "type":
				dst = &c.subject.Type
			case "bom-ref":
				if !spdx {
					dst = &c.subject.Ref
				}
			case "version":
				if !spdx {
					dst = &c.subject.Version
				}
			case "cpe":
				dst = &c.subject.CPE
			case "purl":
				dst = &c.purl
			case "SPDXID":
				if spdx {
					dst = &c.subject.Ref
				}
			case "versionInfo":
				if spdx {
					dst = &c.subject.Version
				}
			case "primaryPackagePurpose":
				dst = &c.purpose
			case "packageComment":
				if spdx {
					dst = &c.packageInfo.comment
				}
			case "annotations":
				if spdx {
					c.packageInfo.annotations = nil
					err := streamPairs(dec, "comment", "comment", func(comment, _ string) {
						c.packageInfo.annotations = append(c.packageInfo.annotations, map[string]any{"comment": comment})
					})
					if err != nil {
						return err
					}
					continue
				}
			case "properties":
				c.subject.Properties, err = inv.streamProperties(dec)
				if err != nil {
					return err
				}
				continue
			case "components":
				if !spdx {
					// Duplicate members use their last value, like json.Unmarshal into maps.
					inv.truncate(index + 1)
					if err := inv.components(dec, false); err != nil {
						return err
					}
					continue
				}
			case "externalRefs":
				if spdx {
					c.packageInfo.externalPURL, c.packageInfo.hasExternalPURL = "", false
					err := streamPairs(dec, "referenceType", "referenceLocator", func(kind, locator string) {
						if kind == "purl" {
							c.packageInfo.externalPURL, c.packageInfo.hasExternalPURL = locator, true
						}
					})
					if err != nil {
						return err
					}
					continue
				}
			}
			if dst != nil {
				*dst, err = streamString(dec)
			} else {
				err = skipJSON(dec)
			}
			if err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
	} else if err := skipJSONToken(dec, token); err != nil {
		return err
	}
	if spdx && c.packageInfo.hasExternalPURL {
		c.purl = c.packageInfo.externalPURL
	}
	// Scanner BOMs commonly repeat the complete PURL as bom-ref. Share the
	// immutable string backing storage; maps remain independent and mutable.
	if c.purl == c.subject.Ref {
		c.purl = c.subject.Ref
	}
	if c.purl != "" && c.subject.Type != "operating-system" && c.purpose != "OPERATING-SYSTEM" {
		c.subject.Name = "" // PURL.FullName replaces it during normalization.
	}
	*inv.at(index) = c
	return nil
}
func (inv *streamInventory) components(dec *sbomDecoder, spdx bool) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('[') {
		return skipJSONToken(dec, token)
	}
	for dec.More() {
		if err := inv.component(dec, spdx); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}
func streamMetadata(dec *sbomDecoder) (streamInventory, error) {
	var root streamInventory
	token, err := dec.Token()
	if err != nil {
		return root, err
	}
	if token != json.Delim('{') {
		return root, skipJSONToken(dec, token)
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return root, err
		}
		if key == "component" {
			root = streamInventory{}
			// Unlike array entries, a non-object metadata.component is absent.
			token, err := dec.Token()
			if err != nil {
				return root, err
			}
			if token == json.Delim('{') {
				if err := root.componentToken(dec, false, token); err != nil {
					return root, err
				}
			} else if err := skipJSONToken(dec, token); err != nil {
				return root, err
			}
		} else if err := skipJSON(dec); err != nil {
			return root, err
		}
	}
	_, err = dec.Token()
	return root, err
}
func loadStream(reader io.Reader) (Document, error) {
	dec := &sbomDecoder{Decoder: json.NewDecoder(reader)}
	// Unknown numeric values still receive the same float64 range validation as
	// Load, rather than accepting numbers that legacy output could not encode.
	var cdx, spdx, root streamInventory
	var format, version, spdxVersion string
	token, err := dec.Token()
	if err != nil {
		return Document{}, err
	}
	if token != json.Delim('{') {
		return Document{}, fmt.Errorf("unsupported SBOM format (expected CycloneDX or SPDX JSON)")
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return Document{}, err
		}
		switch key {
		case "bomFormat":
			format, err = streamString(dec)
		case "specVersion":
			version, err = streamString(dec)
		case "spdxVersion":
			spdxVersion, err = streamString(dec)
		case "components":
			cdx = streamInventory{}
			err = cdx.components(dec, false)
		case "packages":
			spdx = streamInventory{}
			err = spdx.components(dec, true)
		case "metadata":
			root, err = streamMetadata(dec)
		default:
			err = skipJSON(dec)
		}
		if err != nil {
			return Document{}, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return Document{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("unexpected data after SBOM")
		}
		return Document{}, err
	}
	d := Document{}
	var inv *streamInventory
	if format == "CycloneDX" {
		d.Format = "cyclonedx"
		if version != "1.4" && version != "1.5" && version != "1.6" {
			return d, fmt.Errorf("unsupported CycloneDX version %q", version)
		}
		inv = &cdx
		if root.count > 0 {
			s := root.at(0).subject
			inv.context.Root = s.Ref
			// assessmentEnvironment still reads these few metadata fields from Raw.
			names := make([]string, 0, len(s.Properties))
			for name := range s.Properties {
				names = append(names, name)
			}
			sort.Strings(names)
			properties := make([]any, 0, len(names))
			for _, name := range names {
				properties = append(properties, map[string]any{"name": name, "value": s.Properties[name]})
			}
			d.Raw = map[string]any{"metadata": map[string]any{"component": map[string]any{"properties": properties}}}
			if id := s.Properties["bscan:host:operating-system"]; id != "" {
				inv.context.OS = &OSInfo{ID: strings.ToLower(id), VersionID: s.Properties["bscan:host:os-version"], Codename: s.Properties["bscan:os:codename"]}
			}
			for i := 0; i < root.count; i++ {
				inv.append(*root.at(i))
			}
		}
	} else if spdxVersion == "SPDX-2.2" || spdxVersion == "SPDX-2.3" {
		d.Format = "spdx"
		inv = &spdx
	} else {
		return d, fmt.Errorf("unsupported SBOM format (expected CycloneDX or SPDX JSON)")
	}
	for i := 0; i < inv.count; i++ {
		c := inv.at(i)
		s := c.subject
		if d.Format == "spdx" {
			if s.Ref == "SPDXRef-Root" {
				inv.context.Root = s.Ref
			}
			if inv.context.OS == nil && strings.HasPrefix(c.packageInfo.comment, "bscan host metadata: ") {
				var host struct {
					ID      string `json:"operating_system"`
					Version string `json:"os_version"`
				}
				if json.Unmarshal([]byte(strings.TrimPrefix(c.packageInfo.comment, "bscan host metadata: ")), &host) == nil && host.ID != "" {
					inv.context.OS = &OSInfo{ID: strings.ToLower(host.ID), VersionID: host.Version}
				}
			}
			if c.purpose == "OPERATING-SYSTEM" {
				inv.os(&OSInfo{ID: strings.ToLower(s.Name), VersionID: s.Version})
			}
		} else if s.Type == "operating-system" {
			inv.os(&OSInfo{ID: strings.ToLower(s.Name), VersionID: s.Version, Codename: s.Properties["bscan:os:codename"]})
		}
	}
	if inv.context.OS != nil && inv.componentOS != nil && conflictingOS(inv.context.OS, inv.componentOS) {
		inv.context.MixedOS = true
	}
	if inv.context.MixedOS {
		inv.context.OS = nil
	} else if inv.componentOS != nil {
		inv.context.OS = inv.componentOS
	}
	d.Context = inv.context
	if d.Format == "spdx" {
		var packages []any
		for i := 0; i < inv.count; i++ {
			c := inv.at(i)
			if c.subject.Ref == "SPDXRef-Root" || c.subject.Ref == d.Context.Root {
				packages = append(packages, map[string]any{"SPDXID": c.subject.Ref, "packageComment": c.packageInfo.comment, "annotations": c.packageInfo.annotations})
			}
		}
		d.Raw = map[string]any{"packages": packages}
	}
	inv.strings = nil
	refs := make(map[string]bool, inv.count)
	d.Subjects = make([]Subject, 0, inv.count)
	for i := 0; i < inv.count; i++ {
		c := inv.at(i)
		s := Subject{CPE: c.subject.CPE, Ref: c.subject.Ref, Name: c.subject.Name, Version: c.subject.Version, Type: c.subject.Type, Properties: c.subject.Properties}
		if s.CPE == "" && (s.Type == "operating-system" || c.purpose == "OPERATING-SYSTEM") {
			continue
		}
		if s.Ref == "" {
			s.Ref = fmt.Sprintf("bscan-subject-%d", len(d.Subjects)+1)
		}
		if refs[s.Ref] {
			return d, fmt.Errorf("duplicate component reference %q", s.Ref)
		}
		refs[s.Ref] = true
		if ps := c.purl; ps != "" {
			p, err := purl.Parse(ps)
			if err != nil {
				return d, fmt.Errorf("component %s: %w", s.Ref, err)
			}
			s.PURL, s.Type = p, p.Type
			s.Ecosystem = vulndb.PURLTypeToEcosystem(p.Type, p.Namespace)
			if s.Version == "" {
				s.Version = p.Version
			}
			s.Name = p.FullName()
			distro := p.Qualifiers["distro"]
			if distro == "" {
				distro = s.Properties["bscan:distro"]
			}
			if distro != "" {
				s.Release = release(s.Ecosystem, distro)
			} else if d.Context.OS != nil && strings.EqualFold(d.Context.OS.ID, strings.ToLower(s.Ecosystem)) {
				v := d.Context.OS.VersionID
				if v == "" {
					v = d.Context.OS.Codename
				}
				s.Release = release(s.Ecosystem, v)
			}
			s.Upstream = p.Qualifiers["upstream"]
			if s.Upstream == "" {
				s.Upstream = s.Properties["bscan:upstream"]
			}
			if i := strings.LastIndexByte(s.Upstream, '@'); i > 0 {
				s.Upstream, s.UpstreamVersion = s.Upstream[:i], s.Upstream[i+1:]
			}
		}
		d.Subjects = append(d.Subjects, s)
	}
	return d, nil
}
