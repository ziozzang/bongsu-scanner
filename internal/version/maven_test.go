package version

import "testing"

func TestCompareMavenPairs(t *testing.T) {
	checkPairs(t, "CompareMaven", CompareMaven, []pair{
		// examples from the specification
		{"1.0-alpha1", "1.0-beta1", -1},
		{"1.0-beta1", "1.0-SNAPSHOT", -1},
		{"1.0-SNAPSHOT", "1.0", -1},
		{"1.0", "1.0-sp1", -1},
		{"1.0-sp1", "1.0.1", -1},
		{"1.0", "1.0.0", 0},
		{"1.0-RC1", "1.0", -1},
		{"2.0.0", "1.9.9", 1},
		// aliases and qualifiers
		{"1.0-milestone-1", "1.0-m1", 0},
		{"1.0-cr1", "1.0-rc1", 0},
		{"1.0-ga", "1.0", 0},
		{"1.0-final", "1.0", 0},
		{"1.0-release", "1.0", 0},
		{"1.0.0.RELEASE", "1", 0},
		{"1-0", "1", 0},
		{"1.0.0-0", "1", 0},
		{"1.0-SP1", "1.0-sp1", 0},
		{"5.3.0-M1", "5.3.0-RC1", -1},
		{"5.3.0-beta1", "5.3.0-M1", -1},
		{"5.3.0-RC1", "5.3.0", -1},
		{"2.0.0.RC1", "2.0.0.RELEASE", -1},
		{"1.0-alpha", "1.0-alpha1", -1},
		{"1.0-beta", "1.0-beta-2", -1},
		{"1.0-alpha1", "1.0-alpha-1", 0},
		{"1.0a1", "1.0-alpha-1", 0},
		{"1.0-a1", "1.0-alpha-1", 0},
		// unknown qualifiers sort after release, lexically among themselves
		{"1.0-foo", "1.0", 1},
		{"1.0-foo", "1.0-sp1", 1},
		{"1.0-bar", "1.0-foo", -1},
		// numeric list items
		{"1.0-1", "1.0-2", -1},
		{"1.0-1", "1.0", 1},
		{"1.0-1", "1.0.1", -1},
		{"1.0-1", "1.0-sp1", 1},
		{"1.0-snapshot", "1.0-1", -1},
		{"1.0-20240101", "1.0", 1},
		// plain numbers
		{"2.17.1", "2.17.0", 1},
		{"2.17.1", "2.18", -1},
		{"0.99", "1.0", -1},
		{"1.0.1-SNAPSHOT", "1.0.1", -1},
		{"1.0.1-SNAPSHOT", "1.0", 1},
		{"1.10", "1.9", 1},
		{"1.01", "1.1", 0},
		{"99999999999999999999", "100000000000000000000", -1},
		// degenerate input must still be total
		{"", "", 0},
		{"", "1", -1},
		{"", "0-alpha", 1},
		{"", "1-alpha", -1},
		{"-", "", 0},
		{".", "", 0},
		{"-1", "1", -1},
	})
}

func TestCompareMavenOrder(t *testing.T) {
	checkOrder(t, "CompareMaven", CompareMaven, []string{
		"0.99",
		"1.0-alpha",
		"1.0-alpha1",
		"1.0-alpha2",
		"1.0-beta",
		"1.0-beta1",
		"1.0-m1",
		"1.0-RC1",
		"1.0-SNAPSHOT",
		"1.0",
		"1.0-sp1",
		"1.0-bar",
		"1.0-foo",
		"1.0-1",
		"1.0-2",
		"1.0-20240101",
		"1.0.1-SNAPSHOT",
		"1.0.1",
		"1.1",
		"1.9.9",
		"2.0.0.RC1",
		"2.0.0",
		"2.17.0",
		"2.17.1",
		"2.18",
		"5.3.0-beta1",
		"5.3.0-M1",
		"5.3.0-RC1",
		"5.3.0",
		"10.0",
	})
}

func TestMavenEqualGroups(t *testing.T) {
	checkEqual(t, "CompareMaven", CompareMaven, [][]string{
		{"1.0", "1", "1.0.0", "1-0", "1.0-ga", "1.0-final", "1.0-release", "1.0.0.RELEASE", "1.0-0", "1.0.0-0", " 1.0 ", "1.0-GA"},
		{"1.0-alpha1", "1.0-alpha-1", "1.0a1", "1.0-a1", "1.0-ALPHA1", "1-alpha-1"},
		{"1.0-m1", "1.0-milestone-1", "1.0-milestone1"},
		{"1.0-cr1", "1.0-rc1", "1.0-RC1", "1-rc-1"},
		{"1.0-sp1", "1.0-SP1"},
		{"5.3.0-M1", "5.3.0-milestone-1", "5.3-milestone-1"},
	})
}

func TestMavenNormalize(t *testing.T) {
	cases := map[string]string{
		"1.0-alpha1":     "1-alpha-1",
		"5.3.0-M1":       "5.3-milestone-1",
		"2.17.1":         "2.17.1",
		"1.0":            "1",
		"1.0.0.RELEASE":  "1",
		"1.0-cr1":        "1-rc-1",
		"1.0-SNAPSHOT":   "1-snapshot",
		"1.0.1-SNAPSHOT": "1.0.1-snapshot",
		"1.0-1":          "1-1",
		"1.0-ga-1":       "1--1",
		"":               "",
		"   ":            "   ",
	}
	for in, want := range cases {
		if got := Normalize("Maven", in); got != want {
			t.Errorf("Normalize(Maven, %q) = %q, want %q", in, got, want)
		}
	}
	if !Valid("maven", "anything-goes") || Valid("maven", "") || Valid("maven", "  ") {
		t.Error("Valid(maven) should accept any non-blank string only")
	}
}
