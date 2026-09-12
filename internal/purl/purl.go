// Package purl parses and renders Package URLs (https://github.com/package-url/purl-spec).
//
// The parser is deliberately lenient so it accepts every purl bscan has ever
// written as well as the canonical forms in the purl-spec test suite:
//
//   - a scoped npm name may appear as the canonical "%40scope/name" or as the
//     legacy "@scope%2Fname" (older bscan releases encoded the whole name);
//   - a golang module path may be split into namespace segments
//     ("golang/github.com/foo/bar") or encoded as one name
//     ("golang/github.com%2Ffoo%2Fbar");
//   - the "pkg:" scheme may be followed by any number of '/' characters;
//   - malformed percent-escapes are kept verbatim instead of rejected.
//
// String renders the canonical form using the same encoding rules as the
// scanner (RFC 3986 unreserved characters and ':' pass through unencoded),
// so Parse(p.String()) == p for every parsed purl.
package purl

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// PURL is a decoded Package URL.
type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

// ErrScheme is returned when the input does not start with "pkg:".
var ErrScheme = errors.New("purl: missing pkg: scheme")

// Parse decodes s into its components. The type is lowercased, qualifier
// keys are lowercased and qualifiers with empty values are dropped. Type
// specific rules from the purl spec are applied where they are defined as
// normalization (deb/apk/github/bitbucket lowercasing, PEP 503 for pypi).
func Parse(s string) (PURL, error) {
	var p PURL
	s = strings.TrimSpace(s)
	if len(s) < 4 || !strings.EqualFold(s[:4], "pkg:") {
		return p, ErrScheme
	}
	rest := s[4:]

	// Subpath: split once from the right on '#'.
	if i := strings.LastIndexByte(rest, '#'); i >= 0 {
		p.Subpath = parseSubpath(rest[i+1:])
		rest = rest[:i]
	}
	// Qualifiers: split once from the right on '?'.
	if i := strings.LastIndexByte(rest, '?'); i >= 0 {
		p.Qualifiers = parseQualifiers(rest[i+1:])
		rest = rest[:i]
	}
	rest = strings.TrimLeft(rest, "/")

	// Type: everything up to the first '/'.
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return p, fmt.Errorf("purl: missing type or name in %q", s)
	}
	p.Type = strings.ToLower(rest[:i])
	rest = strings.TrimLeft(rest[i+1:], "/")

	// Version: split once from the right on '@'. A leading '@' belongs to a
	// legacy scoped npm name ("@scope%2Fname") and never marks a version.
	if i := strings.LastIndexByte(rest, '@'); i > 0 {
		p.Version = decode(rest[i+1:])
		rest = rest[:i]
	}

	// Namespace and name: the last '/'-separated segment is the name.
	segs := splitNonEmpty(rest, '/')
	if len(segs) == 0 {
		return p, fmt.Errorf("purl: missing name in %q", s)
	}
	for i := range segs {
		segs[i] = decode(segs[i])
	}
	// Only legacy Go module paths and scoped npm names encode path separators.
	name := segs[len(segs)-1]
	ns := segs[:len(segs)-1]
	if strings.Contains(name, "/") && (p.Type == "golang" || (p.Type == "npm" && strings.HasPrefix(name, "@"))) {
		extra := splitNonEmpty(name, '/')
		if len(extra) > 0 {
			ns = append(ns, extra[:len(extra)-1]...)
			name = extra[len(extra)-1]
		}
	}
	p.Namespace = strings.Join(ns, "/")
	p.Name = name
	if p.Name == "" {
		return p, fmt.Errorf("purl: missing name in %q", s)
	}
	p.normalize()
	return p, nil
}

// normalize applies type-specific rules from the purl spec.
func (p *PURL) normalize() {
	switch p.Type {
	case "deb", "apk", "github", "bitbucket", "composer", "hex", "huggingface":
		p.Namespace = strings.ToLower(p.Namespace)
		p.Name = strings.ToLower(p.Name)
	case "npm":
		p.Namespace = strings.ToLower(p.Namespace)
		p.Name = strings.ToLower(p.Name)
	case "pypi":
		p.Namespace = ""
		p.Name = pep503(p.Name)
	case "oci", "cran", "cpan":
		// oci names are lowercase; leave the rest untouched
		if p.Type == "oci" {
			p.Namespace = ""
			p.Name = strings.ToLower(p.Name)
		}
	}
}

// pep503 lowercases and collapses runs of '-', '_' and '.' into '-'.
func pep503(name string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
			}
			prevSep = true
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return b.String()
}

func parseQualifiers(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, kv := range strings.Split(s, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = decode(v)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseSubpath(s string) string {
	var out []string
	for _, seg := range strings.Split(s, "/") {
		seg = decode(seg)
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		out = append(out, seg)
	}
	return strings.Join(out, "/")
}

func splitNonEmpty(s string, sep byte) []string {
	var out []string
	for _, seg := range strings.Split(s, string(sep)) {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// decode percent-decodes s; '+' is kept literally (it is a valid version
// character) and malformed escapes leave the input unchanged.
func decode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

// String renders the canonical purl:
//
//	pkg:<type>/<namespace>/<name>@<version>?<k>=<v>&...#<subpath>
//
// Namespace segments, name, version, qualifier values and subpath segments
// are percent-encoded with Encode; qualifier keys are sorted and lowercased.
func (p PURL) String() string {
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	p.normalize()
	if p.Type == "" || p.Name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(strings.ToLower(p.Type))
	b.WriteByte('/')
	if ns := EncodeSegments(p.Namespace); ns != "" {
		b.WriteString(ns)
		b.WriteByte('/')
	}
	b.WriteString(Encode(p.Name))
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(Encode(p.Version))
	}

	if len(p.Qualifiers) > 0 {
		// Normalize before sorting so mixed-case input still renders canonical
		// key order. Sorting source keys makes duplicate casing deterministic.
		sourceKeys := make([]string, 0, len(p.Qualifiers))
		for k := range p.Qualifiers {
			sourceKeys = append(sourceKeys, k)
		}
		sort.Strings(sourceKeys)
		qualifiers := map[string]string{}
		for _, k := range sourceKeys {
			key := strings.ToLower(strings.TrimSpace(k))
			if key != "" && strings.TrimSpace(p.Qualifiers[k]) != "" {
				qualifiers[key] = p.Qualifiers[k]
			}
		}
		keys := make([]string, 0, len(qualifiers))
		for k := range qualifiers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i == 0 {
				b.WriteByte('?')
			} else {
				b.WriteByte('&')
			}
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(Encode(qualifiers[k]))
		}
	}

	if sp := EncodeSegments(p.Subpath); sp != "" {
		b.WriteByte('#')
		b.WriteString(sp)
	}
	return b.String()
}

// FullName is the package name as vulnerability databases key it: the
// namespace joined to the name with '/' (npm scopes, golang module paths,
// composer vendors) or ':' for maven coordinates. Types whose namespace is
// a distribution or registry (deb, apk, rpm, github, ...) return the bare
// name.
func (p PURL) FullName() string {
	if p.Namespace == "" {
		return p.Name
	}
	switch p.Type {
	case "npm", "golang", "composer", "swift", "huggingface":
		return p.Namespace + "/" + p.Name
	case "maven", "nuget":
		return p.Namespace + ":" + p.Name
	}
	return p.Name
}

// Encode percent-encodes a purl component. RFC 3986 unreserved characters
// and ':' pass through; delimiters such as '@', '+', '/', '#', and '?'
// are encoded. Both purl encoders use the same rules.
func Encode(s string) string {
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

// EncodeSegments encodes each '/'-separated segment on its own and keeps
// the separators, as required for namespaces and subpaths.
func EncodeSegments(s string) string {
	if s == "" {
		return ""
	}
	segs := strings.Split(s, "/")
	out := segs[:0]
	for _, seg := range segs {
		if seg != "" {
			out = append(out, Encode(seg))
		}
	}
	return strings.Join(out, "/")
}
