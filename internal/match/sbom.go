// Package match performs offline advisory matching against SBOM inventories.
package match

import (
	"encoding/json"
	"fmt"
	"github.com/ziozzang/bongsu-scanner/internal/purl"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"os"
	"strings"
)

type Subject struct {
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
	Raw      map[string]any
	Format   string
}

func LoadFile(path string) (Document, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Document{}, e
	}
	return loadCompactFile(b)
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
		s := Subject{Name: str(m, "name"), Version: str(m, "version"), Ref: str(m, "bom-ref"), Type: str(m, "type"), Properties: props(m["properties"])}
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
		if s.Type == "operating-system" || str(m, "primaryPackagePurpose") == "OPERATING-SYSTEM" {
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
	v = strings.TrimPrefix(v, strings.ToLower(eco)+"-")
	if eco == "Debian" {
		if numeric := map[string]string{"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14", "sid": "sid", "unstable": "sid"}[v]; numeric != "" {
			v = numeric
		}
	}
	if eco == "Alpine" {
		v = strings.TrimPrefix(v, "v")
		p := strings.Split(v, ".")
		if len(p) >= 2 {
			return "v" + p[0] + "." + p[1]
		}
		return ""
	}
	return v
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
