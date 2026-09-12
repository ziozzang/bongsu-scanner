package sbom

import (
	"strings"
	"unicode"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

// osCPEVendors maps an os-release ID to the NVD vendor/product pair used in
// operating-system CPEs. Unknown IDs fall back to "<id>:<id>".
var osCPEVendors = map[string][2]string{
	"debian":        {"debian", "debian_linux"},
	"ubuntu":        {"canonical", "ubuntu_linux"},
	"alpine":        {"alpinelinux", "alpine_linux"},
	"rhel":          {"redhat", "enterprise_linux"},
	"centos":        {"centos", "centos"},
	"fedora":        {"fedoraproject", "fedora"},
	"rocky":         {"resf", "rocky_linux"},
	"almalinux":     {"almalinux", "almalinux"},
	"opensuse-leap": {"opensuse", "leap"},
	"sles":          {"suse", "linux_enterprise_server"},
	"amzn":          {"amazon", "linux"},
	"wolfi":         {"wolfi", "wolfi"},
	"chainguard":    {"chainguard", "chainguard"},
	"arch":          {"archlinux", "arch_linux"},
}

// osCPE renders the CPE 2.3 formatted string for an operating system:
//
//	cpe:2.3:o:<vendor>:<product>:<version>:*:*:*:*:*:*:*
//
// The version falls back to the ANY wildcard when os-release has none.
func osCPE(o scan.OSRelease) string {
	id := strings.ToLower(strings.TrimSpace(o.ID))
	if id == "" {
		return ""
	}
	vendor, product := id, id
	if vp, ok := osCPEVendors[id]; ok {
		vendor, product = vp[0], vp[1]
	}
	version := "*"
	if v := strings.TrimSpace(o.VersionID); v != "" {
		version = cpeEscape(v)
	}
	return "cpe:2.3:o:" + cpeEscape(vendor) + ":" + cpeEscape(product) + ":" + version + ":*:*:*:*:*:*:*"
}

// cpeEscape quotes s for use as one attribute of a CPE 2.3 formatted string
// (NISTIR 7695 section 6.2.2). Letters, digits, '_', '-' and '.' pass
// through; every other printable ASCII character, including the ':'
// separator and the '*' / '?' wildcards, is prefixed with a backslash.
// Whitespace and non-ASCII runes, which the grammar does not allow at all,
// become '_'.
func cpeEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		case r > unicode.MaxASCII, unicode.IsSpace(r), !unicode.IsPrint(r):
			b.WriteByte('_')
		default:
			b.WriteByte('\\')
			b.WriteRune(r)
		}
	}
	return b.String()
}
