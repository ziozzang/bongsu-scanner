// Package vulndb stores vulnerability advisories downloaded from external
// sources (OSV, distribution security databases, GitHub advisories) in a
// local, signed, offline-usable database and exposes a lookup API used by
// the matcher. Records use the OSV schema (https://ossf.github.io/osv-schema/)
// as the common representation; every source is converted into it.
package vulndb

import (
	"strings"
	"time"
)

// SchemaVersion is bumped whenever the on-disk layout changes incompatibly.
const SchemaVersion = 2

// Ecosystem names follow OSV spelling: "Debian", "Ubuntu", "Alpine",
// "Wolfi", "Chainguard", "npm", "PyPI", "Go", "crates.io", "Maven",
// "RubyGems", "NuGet", "Packagist". Release-qualified ecosystems keep the OSV
// suffix, e.g. "Debian:13", "Alpine:v3.20", "Ubuntu:24.04".

// Severity is one OSV severity entry.
type Severity struct {
	Type  string `json:"type"`  // CVSS_V2, CVSS_V3, CVSS_V4, Ubuntu
	Score string `json:"score"` // vector string or textual level
}

// Event is one OSV range event. Exactly one field is non-empty.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Range is one OSV affected range.
type Range struct {
	Type   string  `json:"type"`           // ECOSYSTEM, SEMVER, GIT
	Repo   string  `json:"repo,omitempty"` // GIT only
	Events []Event `json:"events"`
}

// Affected is one OSV affected entry.
type Affected struct {
	Ecosystem string         `json:"ecosystem"` // may carry release suffix
	Package   string         `json:"package"`   // OSV package name
	PURL      string         `json:"purl,omitempty"`
	Ranges    []Range        `json:"ranges,omitempty"`
	Versions  []string       `json:"versions,omitempty"` // explicit affected versions
	Specific  map[string]any `json:"ecosystem_specific,omitempty"`
	Database  map[string]any `json:"database_specific,omitempty"`
	// Severity is the OSV affected[].severity (package-specific severity).
	// When present it takes precedence over Record.Severity for this entry.
	Severity []Severity `json:"severity,omitempty"`
}

// Reference is one OSV reference.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// RecordSource identifies the exact feed that supplied an advisory.
type RecordSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Record is one advisory in OSV form plus provenance.
type Record struct {
	Provenance       []RecordSource `json:"provenance,omitempty"`
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases,omitempty"`
	Related          []string       `json:"related,omitempty"`
	Summary          string         `json:"summary,omitempty"`
	Details          string         `json:"details,omitempty"`
	AddedAt          time.Time      `json:"added_at,omitempty,omitzero"`
	LastSeenAt       time.Time      `json:"last_seen_at,omitempty,omitzero"`
	DetailsTruncated bool           `json:"details_truncated,omitempty"`
	Published        string         `json:"published,omitempty"` // RFC 3339
	Modified         string         `json:"modified,omitempty"`  // RFC 3339
	Withdrawn        string         `json:"withdrawn,omitempty"`
	Severity         []Severity     `json:"severity,omitempty"`
	Affected         []Affected     `json:"affected"`
	References       []Reference    `json:"references,omitempty"`
	Source           string         `json:"source"` // provenance: osv, alpine-secdb, debian-tracker, ghsa, ...
	Database         map[string]any `json:"database_specific,omitempty"`
}

// SourceMeta describes one fetched source feed.
type SourceMeta struct {
	ConversionVersion int       `json:"conversion_version,omitempty"`
	Name              string    `json:"name"`
	URL               string    `json:"url"`
	Ecosystems        []string  `json:"ecosystems,omitempty"`
	ETag              string    `json:"etag,omitempty"`
	LastMod           string    `json:"last_modified,omitempty"`
	SHA256            string    `json:"sha256,omitempty"`
	Bytes             int64     `json:"bytes,omitempty"`
	Records           int       `json:"records"`
	FetchedAt         time.Time `json:"fetched_at"`
	Error             string    `json:"error,omitempty"`

	// DataThrough is the newest valid record modified time, independent of fetching.
	DataThrough time.Time `json:"data_through,omitempty,omitzero"`
}

// Meta is the database manifest written after every update.
type Meta struct {
	Selection     *Selection   `json:"selection,omitempty"`
	SchemaVersion int          `json:"schema_version"`
	UpdatedAt     time.Time    `json:"updated_at"`
	Sources       []SourceMeta `json:"sources"`
	Ecosystems    []string     `json:"ecosystems"`
	Records       int          `json:"records"`
}

// Store is the read API consumed by the matcher.
type Store interface {
	// Lookup returns every record with an affected entry whose base
	// ecosystem equals BaseEcosystem(ecosystem) and whose normalized package
	// name equals NormalizeName(ecosystem, name). The caller filters
	// release-qualified ecosystems ("Debian:13") itself.
	Lookup(ecosystem, name string) ([]Record, error)
	Ecosystems() ([]string, error)
	Meta() (Meta, error)
	Close() error
}

// BaseEcosystem strips an OSV release suffix: "Debian:13" -> "Debian".
func BaseEcosystem(e string) string {
	if i := strings.IndexByte(e, ':'); i > 0 {
		return e[:i]
	}
	return e
}

// EcosystemRelease returns the release used for indexing and matching:
// "Alpine:v3.20" -> "v3.20", "Ubuntu:Pro:24.04:LTS" -> "24.04".
// Mainline Red Hat Enterprise Linux preserves major.minor when the feed supplies
// a minor (RHEL 10+); older mainline feeds use the major across repositories.
// Affected.Ecosystem retains the original OSV spelling for display.
func EcosystemRelease(e string) string {
	if i := strings.IndexByte(e, ':'); i > 0 {
		if e[:i] == "Ubuntu" {
			return NormalizeUbuntuRelease(e[i+1:])
		}
		if e[:i] == "Red Hat" {
			return redHatRelease(e[i+1:])
		}
		return e[i+1:]
	}
	return ""
}

// NormalizeName canonicalizes a package name for index keys.
func NormalizeName(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	switch BaseEcosystem(ecosystem) {
	case "PyPI":
		name = strings.ToLower(name)
		var b strings.Builder
		prevSep := false
		for _, r := range name {
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
	case "npm", "Debian", "Ubuntu", "Alpine", "Wolfi", "Chainguard", "RubyGems", "NuGet", "Packagist", "crates.io":
		return strings.ToLower(name)
	default: // Go, Maven: case-sensitive
		return name
	}
}

// PURLTypeToEcosystem maps a purl type (and optional namespace) to the OSV
// base ecosystem. Unknown types return "".
func PURLTypeToEcosystem(purlType, namespace string) string {
	switch strings.ToLower(purlType) {
	case "deb":
		if strings.EqualFold(namespace, "ubuntu") {
			return "Ubuntu"
		}
		return "Debian"
	case "apk":
		switch strings.ToLower(namespace) {
		case "wolfi":
			return "Wolfi"
		case "chainguard":
			return "Chainguard"
		}
		return "Alpine"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "golang":
		return "Go"
	case "cargo":
		return "crates.io"
	case "maven":
		return "Maven"
	case "gem":
		return "RubyGems"
	case "nuget":
		return "NuGet"
	case "composer":
		return "Packagist"
	case "rpm":
		switch strings.ToLower(namespace) {
		case "rocky", "rockylinux", "rocky-linux":
			return "Rocky Linux"
		case "almalinux", "alma":
			return "AlmaLinux"
		case "redhat", "rhel", "centos":
			return "Red Hat"
		case "sles", "sled", "suse":
			return "SUSE"
		}
		if strings.HasPrefix(strings.ToLower(namespace), "opensuse") {
			return "openSUSE"
		}
		// Fedora and Amazon Linux have no OSV ecosystems. Do not map
		// derivatives such as Oracle or Photon to unrelated advisory feeds.
		return ""
	}
	return ""
}
