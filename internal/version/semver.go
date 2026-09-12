package version

import (
	"fmt"
	"strings"
)

// semverVersion is a parsed Semantic Versioning 2.0.0 version. Numeric
// fields are kept as digit strings with leading zeros stripped.
type semverVersion struct {
	nums  []string // 3 or 4 core numbers ("1.2.3.4" is tolerated for NuGet-style versions)
	parts int      // number of core numbers actually written
	pre   []string // pre-release identifiers, nil for a release
	build string   // build metadata without the '+', ignored when comparing
}

// parseSemver accepts SemVer 2.0.0 with these relaxations: an optional
// 'v'/'V' prefix, surrounding whitespace, 1 to 4 core numbers (missing
// ones are 0) and leading zeros in numeric fields.
func parseSemver(v string) (semverVersion, error) {
	var out semverVersion
	s := strings.TrimSpace(v)
	if s == "" {
		return out, fmt.Errorf("semver: empty version")
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		out.build = s[i+1:]
		s = s[:i]
		if !validIdentifiers(out.build) {
			return out, fmt.Errorf("semver: invalid build metadata in %q", v)
		}
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre := s[i+1:]
		s = s[:i]
		if !validIdentifiers(pre) {
			return out, fmt.Errorf("semver: invalid pre-release in %q", v)
		}
		out.pre = strings.Split(pre, ".")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return out, fmt.Errorf("semver: too many version numbers in %q", v)
	}
	out.parts = len(parts)
	for _, p := range parts {
		if !allDigits(p) {
			return out, fmt.Errorf("semver: invalid version number in %q", v)
		}
		out.nums = append(out.nums, stripZeros(p))
	}
	for len(out.nums) < 3 {
		out.nums = append(out.nums, "0")
	}
	if len(out.nums) == 4 && out.nums[3] == "0" {
		out.nums = out.nums[:3]
	}
	return out, nil
}

// validIdentifiers checks a dot-separated list of non-empty identifiers
// made of [0-9A-Za-z-].
func validIdentifiers(s string) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for i := 0; i < len(id); i++ {
			if !isAlnum(id[i]) && id[i] != '-' {
				return false
			}
		}
	}
	return true
}

func compareSemver(x, y semverVersion) int {
	for k := 0; k < len(x.nums) || k < len(y.nums); k++ {
		xa, ya := "0", "0"
		if k < len(x.nums) {
			xa = x.nums[k]
		}
		if k < len(y.nums) {
			ya = y.nums[k]
		}
		if c := cmpDigits(xa, ya); c != 0 {
			return c
		}
	}
	return comparePrerelease(x.pre, y.pre)
}

// comparePrerelease follows SemVer §11.4: a release beats any pre-release;
// numeric identifiers compare numerically and rank below alphanumeric
// ones; alphanumeric identifiers compare in ASCII order; a shorter list
// that is a prefix of a longer one ranks lower.
func comparePrerelease(x, y []string) int {
	if len(x) == 0 || len(y) == 0 {
		return sign(len(y) - len(x))
	}
	for k := 0; k < len(x) && k < len(y); k++ {
		xd, yd := allDigits(x[k]), allDigits(y[k])
		switch {
		case xd && yd:
			if c := cmpDigits(x[k], y[k]); c != 0 {
				return c
			}
		case xd:
			return -1
		case yd:
			return 1
		default:
			if c := strings.Compare(x[k], y[k]); c != 0 {
				return c
			}
		}
	}
	return sign(len(x) - len(y))
}

// String renders the canonical form: MAJOR.MINOR.PATCH[.FOURTH][-pre].
// Build metadata is dropped because it does not take part in ordering.
func (s semverVersion) String() string {
	out := strings.Join(s.nums, ".")
	if len(s.pre) > 0 {
		out += "-" + strings.Join(s.pre, ".")
	}
	return out
}

// CompareSemver compares two Semantic Versioning 2.0.0 versions. Parsing
// is lenient (see parseSemver); an unparsable input is an error.
func CompareSemver(a, b string) (int, error) {
	x, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	y, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	return compareSemver(x, y), nil
}

func normalizeSemver(v string) string {
	s, err := parseSemver(v)
	if err != nil {
		return v
	}
	return s.String()
}
