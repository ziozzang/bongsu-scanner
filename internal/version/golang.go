package version

import "fmt"

// parseGo parses a Go module version. Module versions are semver with an
// optional 'v' prefix; pseudo-versions such as
// v0.0.0-20210101000000-abcdef123456, v1.2.3-0.20210101000000-abcdef123456
// and v1.2.3-pre.0.20210101000000-abcdef123456 are ordinary pre-releases
// whose identifiers already sort chronologically under SemVer rules, and
// "+incompatible" is build metadata, which is ignored.
func parseGo(v string) (semverVersion, error) {
	s, err := parseSemver(v)
	if err != nil {
		return s, fmt.Errorf("go: %w", err)
	}
	if s.parts > 3 {
		return s, fmt.Errorf("go: invalid module version %q", v)
	}
	return s, nil
}

// CompareGo compares two Go module versions (golang.org/x/mod/semver
// semantics, 'v' prefix optional).
func CompareGo(a, b string) (int, error) {
	x, err := parseGo(a)
	if err != nil {
		return 0, err
	}
	y, err := parseGo(b)
	if err != nil {
		return 0, err
	}
	return compareSemver(x, y), nil
}

// normalizeGo returns the version without the 'v' prefix and without
// build metadata, which is the form OSV uses for the Go ecosystem.
func normalizeGo(v string) string {
	s, err := parseGo(v)
	if err != nil {
		return v
	}
	return s.String()
}
