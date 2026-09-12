package version

import (
	"errors"
	"testing"
)

func TestLookupNames(t *testing.T) {
	cases := map[string]family{
		// purl types
		"deb": famDeb, "apk": famApk, "rpm": famRPM, "npm": famSemver, "cargo": famSemver,
		"golang": famGo, "pypi": famPyPI, "maven": famMaven, "gem": famSemver, "nuget": famSemver,
		// OSV ecosystems
		"Debian": famDeb, "Ubuntu": famDeb, "Alpine": famApk, "Wolfi": famApk, "Chainguard": famApk,
		"crates.io": famSemver, "Go": famGo, "PyPI": famPyPI, "Maven": famMaven, "RubyGems": famSemver,
		"NuGet": famSemver, "Rocky Linux": famRPM, "AlmaLinux": famRPM, "Red Hat": famRPM,
		// OSV ecosystems with release suffixes
		"Debian:13": famDeb, "Debian:11": famDeb, "Alpine:v3.20": famApk, "Ubuntu:22.04:LTS": famDeb,
		"Ubuntu:Pro:18.04:LTS": famDeb, "Red Hat:rhel_aus:8.4::appstream": famRPM, "Rocky Linux:9": famRPM,
		"AlmaLinux:8": famRPM, "Wolfi:rolling": famApk, "Chainguard:latest": famApk,
		// case and whitespace insensitivity
		"DEBIAN": famDeb, "CRATES.IO": famSemver, " npm ": famSemver, "GoLang": famGo, "pYpI": famPyPI,
		"rocky linux:9": famRPM, "ALPINE:V3.20": famApk,
		// universal
		"semver": famSemver, "SemVer": famSemver, "generic": famGeneric, "Generic": famGeneric,
	}
	for name, want := range cases {
		got, ok := lookup(name)
		if !ok || got != want {
			t.Errorf("lookup(%q) = (%v, %v), want (%v, true)", name, got, ok, want)
		}
	}
	for _, name := range []string{"", " ", ":", "foo", "Debian13", "npmjs", "hackage:1", "deb ian"} {
		if _, ok := lookup(name); ok {
			t.Errorf("lookup(%q) succeeded, want unknown", name)
		}
	}
}

func TestCompareDispatch(t *testing.T) {
	cases := []struct {
		eco, a, b string
		want      int
	}{
		{"deb", "1:1.0", "2.0", 1},
		{"Debian:13", "8.14.1-2+deb13u3", "8.14.1-2+deb13u4", -1},
		{"Ubuntu:22.04:LTS", "1.0-1ubuntu1", "1.0-1", 1},
		{"apk", "3.1.4-r5", "3.1.4-r6", -1},
		{"Alpine:v3.20", "2.14.4_rc1-r0", "2.14.4-r0", -1},
		{"Wolfi", "1.36.1-r31", "1.36.1-r3", 1},
		{"Chainguard", "1.0_p1", "1.0", 1},
		{"rpm", "1:1.0-1", "2.0-1", 1},
		{"Rocky Linux:9", "1.0a", "1.0.1", -1},
		{"AlmaLinux:8", "1.0~rc1", "1.0", -1},
		{"Red Hat:rhel_aus:8.4::appstream", "1.0^1", "1.0", 1},
		{"npm", "1.0.0-rc.1", "1.0.0", -1},
		{"npm", "4.17.21", "4.17.20", 1},
		{"cargo", "0.1.0", "0.1.0-alpha", 1},
		{"crates.io", "1.0.0", "v1.0.0", 0},
		{"nuget", "1.0.0.0", "1.0.0", 0},
		{"NuGet", "1.0.0.1", "1.0.0", 1},
		{"gem", "1.0.0", "1.0.1", -1},
		{"RubyGems", "3.0.0-beta.1", "3.0.0", -1},
		{"semver", "1.0.0+build", "1.0.0", 0},
		{"pypi", "1.0a1", "1.0", -1},
		{"PyPI", "2!1.0", "1.5", 1},
		{"golang", "v1.2.3+incompatible", "v1.2.3", 0},
		{"Go", "1.21.0", "v1.21.0", 0},
		{"Go", "0.0.0-20200101000000-aaaaaaaaaaaa", "0.0.0-20210101000000-bbbbbbbbbbbb", -1},
		{"maven", "1.0-alpha1", "1.0-beta1", -1},
		{"Maven", "5.3.0-M1", "5.3.0", -1},
		{"generic", "1.0", "1.1", -1},
		{"generic", "1.9", "1.10", -1},
	}
	for _, c := range cases {
		got, err := Compare(c.eco, c.a, c.b)
		if err != nil {
			t.Errorf("Compare(%q, %q, %q): unexpected error %v", c.eco, c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(%q, %q, %q) = %d, want %d", c.eco, c.a, c.b, got, c.want)
		}
		back, _ := Compare(c.eco, c.b, c.a)
		if back != -c.want {
			t.Errorf("Compare(%q, %q, %q) = %d, want %d", c.eco, c.b, c.a, back, -c.want)
		}
	}
}

func TestCompareErrors(t *testing.T) {
	for _, eco := range []string{"", "foo", "Debian13", ":"} {
		_, err := Compare(eco, "1.0", "1.0")
		if !errors.Is(err, ErrUnknownEcosystem) || err != ErrUnknownEcosystem {
			t.Errorf("Compare(%q): err = %v, want ErrUnknownEcosystem", eco, err)
		}
	}
	// strict grammars report parse errors that are not ErrUnknownEcosystem
	for _, c := range [][3]string{
		{"npm", "not-a-version", "1.0.0"},
		{"npm", "1.0.0", "1.2.3.4.5"},
		{"pypi", "latest", "1.0"},
		{"Go", "master", "v1.0.0"},
		{"nuget", "", "1.0"},
	} {
		_, err := Compare(c[0], c[1], c[2])
		if err == nil {
			t.Errorf("Compare(%q, %q, %q): want parse error", c[0], c[1], c[2])
		} else if errors.Is(err, ErrUnknownEcosystem) {
			t.Errorf("Compare(%q, %q, %q): parse error must not be ErrUnknownEcosystem", c[0], c[1], c[2])
		}
	}
	// total comparators never fail, whatever the input
	for _, eco := range []string{"deb", "apk", "rpm", "maven", "generic"} {
		if _, err := Compare(eco, "", "!!!"); err != nil {
			t.Errorf("Compare(%q) on garbage: unexpected error %v", eco, err)
		}
	}
}

func TestValidDispatch(t *testing.T) {
	cases := []struct {
		eco, v string
		want   bool
	}{
		{"Debian:12", "1:7.88.1-10+deb12u5", true},
		{"deb", "1:", false},
		{"Alpine", "3.20.3-r0", true},
		{"apk", "3.20.3-1", false},
		{"Rocky Linux", "4.18.0-553.el8_10", true},
		{"rpm", "1.0-1-1", false},
		{"npm", "1.0.0-canary.3", true},
		{"npm", "1.0.0-canary.3 ", true},
		{"npm", "1.x", false},
		{"pypi", "1.26.0b1", true},
		{"pypi", "1.26.0b1x", false},
		{"Go", "v0.0.0-20240103183307-be819d1f06fc", true},
		{"Go", "1.2.3.4", false},
		{"maven", "2.17.1", true},
		{"maven", "", false},
		{"generic", "anything", true},
		{"generic", " ", false},
		{"unknown", "1.0", false},
		{"", "1.0", false},
	}
	for _, c := range cases {
		if got := Valid(c.eco, c.v); got != c.want {
			t.Errorf("Valid(%q, %q) = %v, want %v", c.eco, c.v, got, c.want)
		}
	}
}

func TestNormalizeDispatch(t *testing.T) {
	cases := []struct{ eco, v, want string }{
		{"deb", "0:1.0-1", "1.0-1"},
		{"Debian:13", "1:2.47.3-0+deb13u1", "1:2.47.3-0+deb13u1"},
		{"apk", " 3.20.3-r0 ", "3.20.3-r0"},
		{"rpm", "0:4.18.0-553.el8_10", "4.18.0-553.el8_10"},
		{"npm", "v1.2", "1.2.0"},
		{"pypi", "1.0.Alpha.1", "1.0a1"},
		{"golang", "v2.0.0+incompatible", "2.0.0"},
		{"maven", "5.3.0-M1", "5.3-milestone-1"},
		{"generic", " 1.0 ", "1.0"},
		{"unknown", " 1.0 ", " 1.0 "},
		{"npm", "not a version", "not a version"},
	}
	for _, c := range cases {
		if got := Normalize(c.eco, c.v); got != c.want {
			t.Errorf("Normalize(%q, %q) = %q, want %q", c.eco, c.v, got, c.want)
		}
	}
}

// realWorld lists versions seen in the wild for each ecosystem; every
// entry must be valid, normalization must be idempotent, and comparing
// normalized forms must agree with comparing the raw strings.
var realWorld = map[string][]string{
	"Debian":  {"1:7.88.1-10+deb12u5", "5.10.209-2", "2.36-9+deb12u7", "0.0.0~git20230101-1", "8.14.1-2+deb13u3", "2.8.2-1~deb13u1", "1:2.47.3-0+deb13u1", "0:1.0-1"},
	"Alpine":  {"3.20.3-r0", "1.1.1w-r1", "2.14.4_rc1-r0", "1.36.1-r31", "1.0_p1", "3.1.4-r5"},
	"Red Hat": {"0:4.18.0-553.el8_10", "1:1.0-1", "3.10.0-1160.2.1.el7", "1.0~rc1", "1.0^git1", "2.0-1"},
	"PyPI":    {"2024.2.2", "1.26.0b1", "0.0.1.post2.dev3", "1.0.alpha.1", "2!1.0", "1.0+local", "v1.0", "1.0-1"},
	"Go":      {"v1.21.0", "v0.0.0-20240103183307-be819d1f06fc", "v1.2.3+incompatible", "1.21.0", "v1.2.3-0.20210101000000-abcdef123456", "v1"},
	"npm":     {"4.17.21", "1.0.0-canary.3", "v18.3.1", "1.0.0+build.7", "1.2"},
	"NuGet":   {"13.0.3", "1.0.0.0", "4.7.0.1", "6.0.0-preview.1"},
	"Maven":   {"2.17.1", "5.3.0-M1", "1.0-alpha1", "1.0.0.RELEASE", "1.0-SNAPSHOT", "1-ga-1", "2.0.0.RC1"},
	"generic": {"1.0", "1.0.1", "2024.1", "abc"},
}

func TestRealWorldNormalizePreservesOrder(t *testing.T) {
	for eco, versions := range realWorld {
		for _, v := range versions {
			if !Valid(eco, v) {
				t.Errorf("Valid(%q, %q) = false", eco, v)
			}
			n := Normalize(eco, v)
			if again := Normalize(eco, n); again != n {
				t.Errorf("Normalize(%q) not idempotent: %q -> %q -> %q", eco, v, n, again)
			}
			if !Valid(eco, n) {
				t.Errorf("Normalize(%q, %q) = %q is not valid", eco, v, n)
			}
		}
		for _, a := range versions {
			for _, b := range versions {
				raw, err := Compare(eco, a, b)
				if err != nil {
					t.Errorf("Compare(%q, %q, %q): %v", eco, a, b, err)
					continue
				}
				norm, err := Compare(eco, Normalize(eco, a), Normalize(eco, b))
				if err != nil || norm != raw {
					t.Errorf("Compare(%q) differs after Normalize: raw %q/%q = %d, normalized %q/%q = %d (%v)",
						eco, a, b, raw, Normalize(eco, a), Normalize(eco, b), norm, err)
				}
			}
		}
	}
}
