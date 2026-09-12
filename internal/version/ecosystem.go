package version

import (
	"errors"
	"strings"
)

// ErrUnknownEcosystem is returned by Compare when the ecosystem name is not
// recognised.
var ErrUnknownEcosystem = errors.New("unknown ecosystem")

// family selects the comparison algorithm for an ecosystem.
type family int

const (
	famDeb family = iota + 1
	famApk
	famRPM
	famSemver
	famPyPI
	famGo
	famMaven
	famGeneric
)

// ecosystems is the single mapping from lower-cased ecosystem names to
// comparison families. Keys are purl types, OSV ecosystem names (without
// their ":release" suffix), a few common aliases and the universal names.
var ecosystems = map[string]family{
	// purl types
	"deb":    famDeb,
	"apk":    famApk,
	"rpm":    famRPM,
	"npm":    famSemver,
	"cargo":  famSemver,
	"golang": famGo,
	"pypi":   famPyPI,
	"maven":  famMaven,
	"gem":    famSemver,
	"nuget":  famSemver,

	// OSV ecosystems
	"debian":      famDeb,
	"ubuntu":      famDeb,
	"alpine":      famApk,
	"wolfi":       famApk,
	"chainguard":  famApk,
	"crates.io":   famSemver,
	"go":          famGo,
	"rubygems":    famSemver,
	"rocky linux": famRPM,
	"almalinux":   famRPM,
	"red hat":     famRPM,

	// aliases
	"dpkg":     famDeb,
	"redhat":   famRPM,
	"rhel":     famRPM,
	"rocky":    famRPM,
	"fedora":   famRPM,
	"opensuse": famRPM,
	"suse":     famRPM,
	"python":   famPyPI,
	"pip":      famPyPI,
	"gomod":    famGo,
	"gradle":   famMaven,

	// universal
	"semver":  famSemver,
	"generic": famGeneric,
}

// lookup resolves an ecosystem name case-insensitively, ignoring any
// ":release" suffix ("Debian:13", "Alpine:v3.20", "Red Hat:rhel_aus:8.4").
func lookup(eco string) (family, bool) {
	e := eco
	if i := strings.IndexByte(e, ':'); i >= 0 {
		e = e[:i]
	}
	f, ok := ecosystems[strings.ToLower(strings.TrimSpace(e))]
	return f, ok
}

// Compare compares versions a and b with the rules of ecosystem eco and
// returns -1, 0 or +1. An unknown ecosystem yields ErrUnknownEcosystem;
// ecosystems with strict grammars (semver, npm, cargo, nuget, gem, pypi,
// go) return a parse error for versions they cannot read.
func Compare(eco, a, b string) (int, error) {
	f, ok := lookup(eco)
	if !ok {
		return 0, ErrUnknownEcosystem
	}
	switch f {
	case famDeb:
		return CompareDeb(a, b), nil
	case famApk:
		return CompareApk(a, b), nil
	case famRPM:
		return CompareRPM(a, b), nil
	case famSemver:
		return CompareSemver(a, b)
	case famPyPI:
		return ComparePyPI(a, b)
	case famGo:
		return CompareGo(a, b)
	case famMaven:
		return CompareMaven(a, b), nil
	default:
		return CompareGeneric(a, b), nil
	}
}

// Valid reports whether v can be parsed as a version of ecosystem eco.
// Unknown ecosystems are never valid.
func Valid(eco, v string) bool {
	f, ok := lookup(eco)
	if !ok {
		return false
	}
	switch f {
	case famDeb:
		return validDeb(v)
	case famApk:
		return validApk(v)
	case famRPM:
		return validRPM(v)
	case famSemver:
		_, err := parseSemver(v)
		return err == nil
	case famPyPI:
		_, err := parsePyPI(v)
		return err == nil
	case famGo:
		_, err := parseGo(v)
		return err == nil
	default:
		return strings.TrimSpace(v) != ""
	}
}

// Normalize returns the canonical form of v for ecosystem eco, suitable
// for comparison and storage: PEP 440 normalization for pypi, 'v' prefix
// and build metadata removed for semver and Go, zero epochs dropped for
// deb and rpm, Maven's canonical item form for maven. When v cannot be
// parsed, or eco is unknown, v is returned unchanged.
func Normalize(eco, v string) string {
	f, ok := lookup(eco)
	if !ok {
		return v
	}
	switch f {
	case famDeb:
		return normalizeDeb(v)
	case famApk:
		return normalizeApk(v)
	case famRPM:
		return normalizeRPM(v)
	case famSemver:
		return normalizeSemver(v)
	case famPyPI:
		return normalizePyPI(v)
	case famGo:
		return normalizeGo(v)
	case famMaven:
		return normalizeMaven(v)
	default:
		return strings.TrimSpace(v)
	}
}
