package version

import "testing"

func TestCompareSemverPairs(t *testing.T) {
	cmp := must(t, "CompareSemver", CompareSemver)
	checkPairs(t, "CompareSemver", cmp, []pair{
		// examples from the specification
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-beta", -1},
		// semver.org §11 example chain
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-beta.2", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-beta.11", "1.0.0-rc.1", -1},
		// lenient forms
		{"v1.2.3", "1.2.3", 0},
		{"V1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"1", "1.0.0", 0},
		{"01.02.03", "1.2.3", 0},
		{" 1.2.3 ", "1.2.3", 0},
		{"1.0.0.0", "1.0.0", 0},
		{"1.0.0.1", "1.0.0", 1},
		{"1.0.0.1", "1.0.1", -1},
		// build metadata is ignored
		{"1.0.0+build", "1.0.0", 0},
		{"1.0.0+build.1", "1.0.0+build.2", 0},
		{"1.0.0-alpha+001", "1.0.0-alpha", 0},
		{"1.0.0+a-b", "1.0.0", 0},
		// numeric identifiers < alphanumeric, shorter < longer
		{"1.0.0-1", "1.0.0-2", -1},
		{"1.0.0-2", "1.0.0-10", -1},
		{"1.0.0-10", "1.0.0-a", -1},
		{"1.0.0-alpha-1", "1.0.0-alpha", 1},
		{"1.0.0-alpha-1", "1.0.0-beta", -1},
		{"1.0.0-canary.3", "1.0.0", -1},
		{"1.0.0-canary.3", "1.0.0-canary.2", 1},
		{"1.0.0-canary.10", "1.0.0-canary.9", 1},
		{"1.0.0-RC1", "1.0.0-rc1", -1},
		// real-world
		{"4.17.21", "4.17.20", 1},
		{"0.0.1", "0.1.0", -1},
		{"2.0.0", "1.99.99", 1},
		{"1.10.0", "1.9.0", 1},
		{"18.3.1", "18.3.0-canary", 1},
		{"99999999999999999999.0.0", "100000000000000000000.0.0", -1},
	})
}

func TestCompareSemverOrder(t *testing.T) {
	checkOrder(t, "CompareSemver", must(t, "CompareSemver", CompareSemver), []string{
		"0.0.1",
		"0.1.0",
		"0.9.9",
		"1.0.0-1",
		"1.0.0-2",
		"1.0.0-10",
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-alpha-1",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-canary.2",
		"1.0.0-canary.3",
		"1.0.0-canary.10",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.0.1",
		"1.0.1",
		"1.2",
		"1.2.3",
		"1.10.0",
		"2.0.0",
		"4.17.20",
		"4.17.21",
		"10.0.0",
	})
}

func TestSemverEqualGroups(t *testing.T) {
	checkEqual(t, "CompareSemver", must(t, "CompareSemver", CompareSemver), [][]string{
		{"1.0.0", "v1.0.0", "V1.0.0", "1.0", "1", "1.0.0+build", "1.0.0+build.2", "01.0.0", "1.0.0.0", " 1.0.0 "},
		{"1.0.0-alpha", "1.0.0-alpha+001", "v1.0.0-alpha"},
	})
}

func TestSemverInvalid(t *testing.T) {
	for _, v := range []string{"", " ", "1.2.3.4.5", "1.x", "1.0.0-", "1.0.0+", "abc", "1.0.0-a..b", "1.0.0 beta", "1.0.0-α", "1..0", ".1", "1.0.0-rc.1+", "-1.0.0", "1.0.0-rc 1"} {
		if _, err := CompareSemver(v, "1.0.0"); err == nil {
			t.Errorf("CompareSemver(%q, 1.0.0): want error", v)
		}
		if _, err := CompareSemver("1.0.0", v); err == nil {
			t.Errorf("CompareSemver(1.0.0, %q): want error", v)
		}
		if Valid("semver", v) {
			t.Errorf("Valid(semver, %q) = true, want false", v)
		}
		if got := Normalize("semver", v); got != v {
			t.Errorf("Normalize(semver, %q) = %q, want input unchanged", v, got)
		}
	}
}

func TestSemverNormalize(t *testing.T) {
	cases := map[string]string{
		"v1.2.3":               "1.2.3",
		"1.2":                  "1.2.0",
		"1":                    "1.0.0",
		"01.02.03":             "1.2.3",
		"1.0.0+build.5":        "1.0.0",
		"1.0.0-rc.1+build":     "1.0.0-rc.1",
		"v1.0.0-canary.3":      "1.0.0-canary.3",
		"1.0.0.0":              "1.0.0",
		"1.0.0.1":              "1.0.0.1",
		" 4.17.21 ":            "4.17.21",
		"1.0.0-rc.01":          "1.0.0-rc.01",
		"2.0.0-beta.1+exp.sha": "2.0.0-beta.1",
	}
	for in, want := range cases {
		if got := Normalize("npm", in); got != want {
			t.Errorf("Normalize(npm, %q) = %q, want %q", in, got, want)
		}
	}
}
