package version

import (
	"strings"
	"testing"
)

var fuzzEcosystems = []string{"deb", "apk", "rpm", "npm", "pypi", "golang", "maven", "generic", "Debian:13", "Alpine:v3.20", "Red Hat:rhel_aus:8.4", "nuget", "unknown"}

var fuzzVersionPairs = [][2]string{
	{"1.0", "1.0"}, {"1:2.3-4", "2.3-4"}, {"0:1.2-1", "1.2-1"}, {"1.2~rc1", "1.2"}, {"1.2+dfsg-1", "1.2-1"},
	{"1.2.3_alpha1", "1.2.3_beta"}, {"1.2.3-r0", "1.2.3-r1"}, {"1.01", "1.1"}, {"1.00", "1.0"}, {"3.1.4-r5_p1", "3.1.4-r5"},
	{"1.2.3", "1.2.3-alpha.1"}, {"v1.2.3+build.5", "1.2.3"}, {"1.2.3.4", "1.2.3"}, {"1.2.3-rc.10", "1.2.3-rc.9"},
	{"1!2.0", "2.0"}, {"1.0a1", "1.0.dev1"}, {"1.0.post1", "1.0+local.1"}, {"2024.01.01", "2024.1.1"},
	{"v0.0.0-20210101000000-abcdef123456", "v0.0.1"}, {"v1.2.3-0.20210101000000-abcdef123456", "v1.2.3"}, {"v2.0.0+incompatible", "v2.0.0"},
	{"1.0-alpha1", "1.0-a1"}, {"1.0-SNAPSHOT", "1.0"}, {"1.0.0.RELEASE", "1.0.0"}, {"1-sp", "1-ga"}, {"1.0-cr1", "1.0-rc1"}, {"1.0.x", "1.0.1"},
	{"~", "^"}, {"1^", "1~"}, {"0", ""}, {"", ""}, {"a", "1"}, {"1.2.3-", "-1.2.3"}, {":", "::"}, {"1.2.3\x00junk", "1.2.3"},
	{strings.Repeat("9", 40), strings.Repeat("1", 41)}, {strings.Repeat("1.", 30) + "1", strings.Repeat("1.", 31)}, {strings.Repeat("-", 200), strings.Repeat("-", 199) + "1"},
}

func FuzzCompareAntisymmetry(f *testing.F) {
	for _, eco := range fuzzEcosystems {
		for _, pair := range fuzzVersionPairs {
			f.Add(eco, pair[0], pair[1])
		}
	}
	f.Fuzz(func(t *testing.T, eco, a, b string) {
		ab, errAB := Compare(eco, a, b)
		ba, errBA := Compare(eco, b, a)
		if (errAB == nil) != (errBA == nil) {
			t.Fatalf("Compare(%q, %q, %q) err=%v but reversed err=%v", eco, a, b, errAB, errBA)
		}
		if errAB != nil {
			if ab != 0 || ba != 0 {
				t.Fatalf("Compare(%q, %q, %q) returned %d with error %v", eco, a, b, ab, errAB)
			}
			return
		}
		if ab < -1 || ab > 1 || ba < -1 || ba > 1 {
			t.Fatalf("Compare(%q, %q, %q) = %d / %d outside [-1, 1]", eco, a, b, ab, ba)
		}
		if ab != -ba {
			t.Fatalf("Compare(%q, %q, %q) = %d but reversed = %d", eco, a, b, ab, ba)
		}
		aa, err := Compare(eco, a, a)
		if err != nil || aa != 0 {
			t.Fatalf("Compare(%q, %q, %q) = %d, %v (want 0)", eco, a, a, aa, err)
		}
		// Normalize must be idempotent and order-preserving: a valid version
		// compares equal to its normalized form.
		na := Normalize(eco, a)
		if Normalize(eco, na) != na {
			t.Fatalf("Normalize(%q, %q) = %q is not idempotent (%q)", eco, a, na, Normalize(eco, na))
		}
		if Valid(eco, a) {
			if c, err := Compare(eco, a, na); err != nil || c != 0 {
				t.Fatalf("Compare(%q, %q, Normalize=%q) = %d, %v", eco, a, na, c, err)
			}
			if !Valid(eco, na) {
				t.Fatalf("Normalize(%q, %q) = %q is not valid", eco, a, na)
			}
		}
	})
}

// FuzzCompareTransitivity checks the strict orderings. Maven is excluded on
// purpose: ComparableVersion itself is not transitive in corner cases (for
// example "a" < "0beta" < "0" < "a", because a string item sorts before a
// nested list but after the release marker), and the port follows Maven.
func FuzzCompareTransitivity(f *testing.F) {
	for _, eco := range []string{"deb", "apk", "rpm", "npm", "pypi", "golang", "generic"} {
		f.Add(eco, "1.0", "1.0.1", "1.1")
		f.Add(eco, "1.2~rc1", "1.2", "1:0")
		f.Add(eco, "1.0-alpha", "1.0-beta", "1.0-1")
		f.Add(eco, "1.0_pre1", "1.0", "1.0_p1")
		f.Add(eco, "1.0.dev1", "1.0a1", "1.0.post1")
	}
	f.Fuzz(func(t *testing.T, eco, a, b, c string) {
		if f, ok := lookup(eco); !ok || f == famMaven {
			return
		}
		ab, err1 := Compare(eco, a, b)
		bc, err2 := Compare(eco, b, c)
		ac, err3 := Compare(eco, a, c)
		if err1 != nil || err2 != nil || err3 != nil {
			return
		}
		// Only the strict form is checked: a<b && b<c implies a<c, and the
		// mirror image. Every comparator is a total preorder by construction.
		if ab < 0 && bc < 0 && ac >= 0 {
			t.Fatalf("%s: %q < %q < %q but Compare(a, c) = %d", eco, a, b, c, ac)
		}
		if ab > 0 && bc > 0 && ac <= 0 {
			t.Fatalf("%s: %q > %q > %q but Compare(a, c) = %d", eco, a, b, c, ac)
		}
		if ab == 0 && bc == 0 && ac != 0 {
			t.Fatalf("%s: %q == %q == %q but Compare(a, c) = %d", eco, a, b, c, ac)
		}
	})
}

func FuzzComparatorsDirect(f *testing.F) {
	for _, pair := range fuzzVersionPairs {
		f.Add(pair[0], pair[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		for name, cmp := range map[string]func(string, string) int{
			"deb": CompareDeb, "apk": CompareApk, "rpm": CompareRPM, "maven": CompareMaven, "generic": CompareGeneric,
		} {
			if x, y := cmp(a, b), cmp(b, a); x != -y || x < -1 || x > 1 {
				t.Fatalf("%s(%q, %q) = %d, reversed %d", name, a, b, x, y)
			}
			if cmp(a, a) != 0 {
				t.Fatalf("%s(%q, %q) != 0", name, a, a)
			}
		}
		for name, cmp := range map[string]func(string, string) (int, error){
			"semver": CompareSemver, "pypi": ComparePyPI, "go": CompareGo,
		} {
			x, errX := cmp(a, b)
			y, errY := cmp(b, a)
			if (errX == nil) != (errY == nil) || (errX == nil && (x != -y || x < -1 || x > 1)) {
				t.Fatalf("%s(%q, %q) = %d, %v; reversed %d, %v", name, a, b, x, errX, y, errY)
			}
		}
		_ = validDeb(a)
		_ = validApk(a)
		_ = validRPM(a)
		_ = normalizeMaven(a)
		_ = normalizePyPI(a)
		_ = normalizeSemver(a)
		_ = normalizeGo(a)
	})
}
