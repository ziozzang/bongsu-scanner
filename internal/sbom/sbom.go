// Package sbom renders scan.Result as CycloneDX 1.6 and SPDX 2.3 JSON.
//
// Both writers are deterministic: given the same Result they produce
// byte-identical output. Component identifiers are derived from purls so
// they stay stable across runs; the document serial number and namespace
// change with every scan because they include the scan timestamp.
package sbom

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

// ToolVersion is the bscan build version recorded in generated documents
// (CycloneDX metadata.tools, SPDX creators). cmd/bscan overrides it at
// startup; the default is used by tests and library callers.
var ToolVersion = "dev"

// maxListedPaths bounds how many scan.Scan.Excluded / SkippedPaths entries
// are copied into a single property or annotation.
const maxListedPaths = 50

// maxLicenseText is the longest free-form license fragment carried into a
// document when the value is not a valid SPDX expression.
const maxLicenseText = 200

var (
	invalidID = regexp.MustCompile(`[^A-Za-z0-9.-]+`)
	hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Write renders r in the requested format ("spdx"/"spdx-json" or
// "cyclonedx"/"cdx"/"cyclonedx-json") and stores it at path.
func Write(path, format string, r scan.Result) (err error) {
	var render func(io.Writer, scan.Result) error
	switch strings.ToLower(format) {
	case "spdx", "spdx-json":
		render = writeSPDX
	case "cyclonedx", "cdx", "cyclonedx-json":
		render = writeCycloneDX
	default:
		return fmt.Errorf("unsupported SBOM format %q", format)
	}
	// SBOMs are deliverables meant to be shared and read by other tools and
	// users (CI collectors, container smoke tests running as another uid), so
	// they get the conventional 0644 subject to the umask; the catalog and
	// keys under BONGSU_HOME keep their private modes.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) // #nosec G302,G304 -- Deliverable output at a caller-chosen path; readable on purpose.
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	w := bufio.NewWriterSize(f, 64*1024)
	if err := render(w, r); err != nil {
		return err
	}
	if err := w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}

// jsonStream keeps only one encoded value at a time. Reusing the encoder and
// its buffer bounds temporary JSON storage by the largest individual value.
// Explicit array separators preserve Encoder's two-space document layout,
// including empty arrays, field order, and unescaped HTML characters.
type jsonStream struct {
	w      io.Writer
	buf    bytes.Buffer
	enc    *json.Encoder
	err    error
	fields int
}

func newJSONStream(w io.Writer) *jsonStream {
	s := &jsonStream{w: w}
	s.enc = json.NewEncoder(&s.buf)
	s.enc.SetEscapeHTML(false)
	s.text("{")
	return s
}

func (s *jsonStream) text(v string) {
	if s.err != nil {
		return
	}
	var n int
	n, s.err = io.WriteString(s.w, v)
	if s.err == nil && n != len(v) {
		s.err = io.ErrShortWrite
	}
}

func (s *jsonStream) value(v any, prefix string) {
	if s.err != nil {
		return
	}
	s.buf.Reset()
	s.enc.SetIndent(prefix, "  ")
	if s.err = s.enc.Encode(v); s.err != nil {
		return
	}
	b := s.buf.Bytes()
	b = b[:len(b)-1] // Encode appends exactly one newline.
	var n int
	n, s.err = s.w.Write(b)
	if s.err == nil && n != len(b) {
		s.err = io.ErrShortWrite
	}
}

// Field names are fixed schema keys supplied by the two renderers.
func (s *jsonStream) fieldName(name string) {
	if s.fields > 0 {
		s.text(",")
	}
	s.text("\n  \"" + name + "\": ")
	s.fields++
}

func (s *jsonStream) field(name string, v any) {
	s.fieldName(name)
	s.value(v, "  ")
}

func (s *jsonStream) end() error {
	s.text("\n}")
	return s.err
}

type jsonArray struct {
	stream *jsonStream
	prefix string
	count  int
}

func (s *jsonStream) array(prefix string) jsonArray {
	s.text("[")
	return jsonArray{stream: s, prefix: prefix}
}

func (a *jsonArray) next() {
	if a.count > 0 {
		a.stream.text(",")
	}
	a.stream.text("\n")
	a.stream.text(a.prefix)
	a.count++
}

func (a *jsonArray) add(v any) {
	a.next()
	a.stream.value(v, a.prefix)
}

func (a *jsonArray) end() {
	if a.count > 0 {
		a.stream.text("\n")
		a.stream.text(a.prefix[:len(a.prefix)-2])
	}
	a.stream.text("]")
}

// safeID reduces s to the SPDX identifier alphabet [A-Za-z0-9.-].
func safeID(s string) string {
	s = invalidID.ReplaceAllString(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}

// stableHash seeds the document serial number / namespace. It covers the
// identity of what was scanned (name, source hash, image id, os-release,
// completeness), package identities, source type, tool version and scan time.
func stableHash(r scan.Result) string {
	h := sha256.New()
	h.Write([]byte(r.Name + "\x00" + r.SourceHash + "\x00" + r.ScannedAt.UTC().Format("20060102T150405.000000000Z")))
	// JSON encoding preserves field and package boundaries even for embedded
	// delimiters. Hash every package in document order, including duplicates.
	packages := sha256.New()
	enc := json.NewEncoder(packages)
	for _, p := range r.Packages {
		_ = enc.Encode([5]string{p.Type, p.Namespace, p.Name, p.Version, p.PURL})
	}
	identity, _ := json.Marshal([3]string{r.SourceType, ToolVersion, hex.EncodeToString(packages.Sum(nil))})
	h.Write(append([]byte("\x00content\x00"), identity...))
	if r.Host != nil {
		b, _ := json.Marshal(r.Host)
		h.Write(append([]byte("\x00host\x00"), b...))
	}
	if r.Image != nil {
		h.Write([]byte("\x00image\x00" + r.Image.ID))
	}
	if r.OS != nil {
		b, _ := json.Marshal(r.OS)
		h.Write(append([]byte("\x00os\x00"), b...))
	}
	if r.Scan != nil {
		h.Write([]byte(fmt.Sprintf("\x00scan\x00partial=%t", r.Scan.Partial)))
	}
	for _, f := range r.Files {
		h.Write([]byte("\x00" + f.Path + "\x00" + f.SHA256))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func uuidFromHash(h string) string {
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

// isContainerSource reports whether a Result.SourceType denotes an image,
// running container or image archive rather than a directory or host.
func isContainerSource(source string) bool {
	return strings.Contains(source, "image") || strings.Contains(source, "archive") || source == "container"
}

// componentType maps Result.SourceType to the CycloneDX root component type.
func componentType(source string) string {
	if isContainerSource(source) {
		return "container"
	}
	return "application"
}

// isOSPackage reports whether typ is a distribution package manager type.
func isOSPackage(typ string) bool {
	switch strings.ToLower(typ) {
	case "deb", "apk", "rpm":
		return true
	}
	return false
}

// isBinarySource reports whether p was recovered from a compiled Go binary
// rather than from go.mod. Merged packages list several sources separated
// by ';'; any non-lockfile source counts, because a module linked into a
// shipped binary is the stronger signal.
func isBinarySource(p scan.Package) bool {
	if strings.ToLower(p.Type) != "golang" || p.Source == "" {
		return false
	}
	for _, src := range strings.Split(p.Source, ";") {
		base := strings.ToLower(src)
		if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
			base = base[i+1:]
		}
		switch base {
		case "go.mod", "go.sum", "":
			continue
		}
		return true
	}
	return false
}

// upstream renders the ?upstream= style "source[@version]" of an OS package.
func upstream(p scan.Package) string {
	src := strings.TrimSpace(p.SourceName)
	if src == "" {
		return ""
	}
	if v := strings.TrimSpace(p.SourceVersion); v != "" {
		return src + "@" + v
	}
	return src
}

// firstTag returns the first tag of an image, or "".
func firstTag(img *scan.ImageMetadata) string {
	if img == nil || len(img.Tags) == 0 {
		return ""
	}
	return img.Tags[0]
}

// imageTag extracts the ":tag" part of an image reference such as
// "nginx:1.25", "registry:5000/team/app:v2" or "app:v2@sha256:...".
func imageTag(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	last := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		last = ref[i+1:]
	}
	if i := strings.LastIndex(last, ":"); i >= 0 {
		return last[i+1:]
	}
	return ""
}

// imageRepoName returns the final path segment of an image reference with
// tag and digest removed, lower-cased: "docker.io/library/nginx:1.25" -> "nginx".
func imageRepoName(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		ref = ref[:i]
	}
	return strings.ToLower(strings.TrimSpace(ref))
}

// imageIDHex returns the 64-character hex digest of an image id such as
// "sha256:abc..." and "" when the id is missing or not SHA-256.
func imageIDHex(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if i := strings.LastIndex(id, ":"); i >= 0 {
		if id[:i] != "sha256" {
			return ""
		}
		id = id[i+1:]
	}
	if !hexDigest.MatchString(id) {
		return ""
	}
	return id
}

// firstLine returns the first non-empty line of s trimmed to at most max
// runes. It is used for free-form license text that cannot be an SPDX
// expression.
func firstLine(s string, max int) string {
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
		if line == "" {
			continue
		}
		if r := []rune(line); len(r) > max {
			return string(r[:max])
		}
		return line
	}
	return ""
}

// capList returns at most max entries of list; the boolean reports whether
// anything was dropped.
func capList(list []string, max int) ([]string, bool) {
	if len(list) <= max {
		return list, false
	}
	return list[:max], true
}

// purlEncode percent-encodes every byte outside the RFC 3986 unreserved set,
// matching internal/scan's purl builder.
func purlEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

// ociPURL builds "pkg:oci/<name>@sha256%3A<hex>?tag=<tag>" for the root
// image package. The name must be the lower-cased last repository segment.
func ociPURL(name, hexID, tag string) string {
	if name == "" || hexID == "" {
		return ""
	}
	s := "pkg:oci/" + purlEncode(name) + "@" + purlEncode("sha256:"+hexID)
	if tag != "" {
		s += "?tag=" + purlEncode(tag)
	}
	return s
}

// timestampSeconds formats t as UTC RFC 3339 with second precision, the
// form both SPDX ("YYYY-MM-DDThh:mm:ssZ") and CycloneDX accept.
func timestampSeconds(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}
