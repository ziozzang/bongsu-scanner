package scan

import (
	"regexp"
	"sort"
	"strings"
)

// purlEncode percent-encodes a purl component. RFC 3986 unreserved characters
// and ':' pass through; delimiters such as '@', '+', '/', '#', and '?'
// are encoded. Both purl encoders use the same rules.
func purlEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '.', c == '_', c == '~', c == ':':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

// purlEncodeNamespace encodes each '/'-separated namespace segment on its own
// and keeps the separators, as required for golang and maven namespaces.
func purlEncodeNamespace(ns string) string {
	segs := strings.Split(ns, "/")
	out := segs[:0]
	for _, s := range segs {
		if s != "" {
			out = append(out, purlEncode(s))
		}
	}
	return strings.Join(out, "/")
}

var pep503Sep = regexp.MustCompile(`[-_.]+`)

// normalizePyPIName applies PEP 503 normalization: lowercase and collapse
// runs of '-', '_' and '.' into a single '-'.
func normalizePyPIName(name string) string {
	return pep503Sep.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// splitLast splits s at the last occurrence of sep. When sep is absent the
// namespace is empty and the whole string is the name.
func splitLast(s, sep string) (namespace, name string) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):]
	}
	return "", s
}

// purlParts returns the normalized namespace, name, version and qualifiers
// that make up the purl for p. It is separated from buildPURL so tests can
// inspect the components.
func purlParts(p Package) (typ, ns, name, version string, quals map[string]string) {
	typ = strings.ToLower(strings.TrimSpace(p.Type))
	ns, name, version = strings.TrimSpace(p.Namespace), strings.TrimSpace(p.Name), strings.TrimSpace(p.Version)
	quals = map[string]string{}
	upstream := func() {
		src, srcVer := strings.TrimSpace(p.SourceName), strings.TrimSpace(p.SourceVersion)
		if src == "" {
			return
		}
		if srcVer != "" && srcVer != version {
			quals["upstream"] = src + "@" + srcVer
			return
		}
		if src != name {
			quals["upstream"] = src
		}
	}
	switch typ {
	case "rpm":
		ns = strings.ToLower(ns)
		// RPM purls put epoch in a qualifier; Package.Version keeps the EVR
		// used by vulnerability comparisons. RPM names remain case-sensitive.
		if epoch, rest, ok := strings.Cut(version, ":"); ok && epoch != "" && strings.Trim(epoch, "0123456789") == "" {
			version = rest
			if epoch = strings.TrimLeft(epoch, "0"); epoch != "" {
				quals["epoch"] = epoch
			}
		}
		quals["arch"], quals["distro"] = p.Arch, p.Distro
		if src := strings.TrimSpace(p.SourceName); src != "" {
			quals["upstream"] = src
			if v := strings.TrimSpace(p.SourceVersion); v != "" && v != version {
				quals["upstream"] += "@" + v
			}
		}
	case "deb":
		name = strings.ToLower(name)
		if ns == "" {
			ns = "debian"
		}
		ns = strings.ToLower(ns)
		quals["arch"] = p.Arch
		quals["distro"] = p.Distro
		upstream()
	case "apk":
		name = strings.ToLower(name)
		if ns == "" {
			ns = "alpine"
		}
		ns = strings.ToLower(ns)
		quals["arch"] = p.Arch
		quals["distro"] = p.Distro
		upstream()
	case "npm":
		name = strings.ToLower(name)
		if ns == "" && strings.HasPrefix(name, "@") {
			ns, name = splitLast(name, "/")
		}
		ns = strings.ToLower(ns)
	case "pypi":
		name = normalizePyPIName(name)
		ns = ""
	case "golang":
		if ns == "" && name != "stdlib" {
			ns, name = splitLast(name, "/")
		}
	case "composer":
		name = strings.ToLower(name)
		if ns == "" {
			ns, name = splitLast(name, "/")
		}
		ns = strings.ToLower(ns)
	case "cargo", "gem", "nuget":
		ns = ""
	}
	for k, v := range quals {
		if strings.TrimSpace(v) == "" {
			delete(quals, k)
		}
	}
	return typ, ns, name, version, quals
}

// buildPURL renders a purl-spec compliant package URL for p:
//
//	pkg:<type>/<namespace>/<name>@<version>?<k>=<v>&...
//
// Namespace segments, name, version and qualifier values are percent-encoded
// with purlEncode; qualifier keys are emitted in sorted order and empty
// values are dropped. Type-specific normalization (lowercasing, PEP 503,
// default deb/apk namespaces, scoped npm split, golang module split) is
// applied by purlParts.
func buildPURL(p Package) string {
	typ, ns, name, version, quals := purlParts(p)
	if typ == "" || name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	b.WriteByte('/')
	if ns != "" {
		b.WriteString(purlEncodeNamespace(ns))
		b.WriteByte('/')
	}
	b.WriteString(purlEncode(name))
	if version != "" {
		b.WriteByte('@')
		b.WriteString(purlEncode(version))
	}
	if len(quals) > 0 {
		keys := make([]string, 0, len(quals))
		for k := range quals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('?')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(strings.ToLower(k))
			b.WriteByte('=')
			b.WriteString(purlEncode(quals[k]))
		}
	}
	return b.String()
}

// makePURL is kept for callers that only know type, name and version.
func makePURL(kind, name, version string) string {
	return buildPURL(Package{Type: kind, Name: name, Version: version})
}
