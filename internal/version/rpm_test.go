package version

import "testing"

func TestCompareRPMPairs(t *testing.T) {
	checkPairs(t, "CompareRPM", CompareRPM, []pair{
		// examples from the specification
		{"1:1.0-1", "2.0-1", 1},
		{"1.0.1", "1.0", 1},
		{"1.0a", "1.0.1", -1},
		// tilde and caret
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0^1", "1.0", 1},
		{"1.0^1", "1.0.1", -1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.0.1", -1},
		{"1.0^git1", "1.0a", -1},
		{"1.0~rc1", "1.0^1", -1},
		{"1.0^git2", "1.0-1", 1},
		// epochs and releases
		{"0:1.0", "1.0", 0},
		{"2:1.0", "1:9.0", 1},
		{"1.0", "1.0-1", -1},
		{"1.0-1.el8", "1.0-2.el8", -1},
		{"1.0-1.el8", "1.0-1.el9", -1},
		{"4.18.0-553.el8_10", "4.18.0-513.el8_9", 1},
		{"3.10.0-1160.el7", "3.10.0-1160.2.1.el7", -1},
		{"1:7.88.1-10", "1:7.88.1-9", 1},
		// segments
		{"2.0.0", "1.9.9", 1},
		{"1.10", "1.9", 1},
		{"1.0010", "1.10", 0},
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0b", -1},
		{"1.a", "1.1", -1},
		{"1.0.0", "1.0", 1},
		{"1_0", "1.0", 0},
		{"1..0", "1.0", 0},
		{"1.0", "1.0.", 0},
		{"a", "1", -1},
		{"99999999999999999999", "100000000000000000000", -1},
		// degenerate input must still be total
		{"", "", 0},
		{"", "1", -1},
		{"", "~", 1},
		{"", "^", -1},
		{"-", "", 0},
		{":", "", 0},
	})
}

func TestCompareRPMOrder(t *testing.T) {
	checkOrder(t, "CompareRPM", CompareRPM, []string{
		"1.0~~",
		"1.0~rc1",
		"1.0~rc2",
		"1.0",
		"1.0-1",
		"1.0-1.el8",
		"1.0-1.el9",
		"1.0-2.el8",
		"1.0^",
		"1.0^git1",
		"1.0^git2",
		"1.0a",
		"1.0a-1",
		"1.0b",
		"1.0.1",
		"1.0.1-1",
		"1.1",
		"1.10",
		"2.0-1",
		"3.10.0-1160.el7",
		"3.10.0-1160.2.1.el7",
		"4.18.0-513.el8_9",
		"4.18.0-553.el8_10",
		"1:1.0-1",
		"2:0.1",
	})
}

func TestRPMValidNormalize(t *testing.T) {
	valid := []string{"1.0", "1:1.0-1", "4.18.0-553.el8_10", "1.0~rc1", "1.0^git1", "0:3.10.0-1160.2.1.el7", " 1.0-1 "}
	for _, v := range valid {
		if !Valid("rpm", v) {
			t.Errorf("Valid(rpm, %q) = false, want true", v)
		}
	}
	invalid := []string{"", " ", "1:", "a:1.0", "1.0-1-2", "1.0:1", "1.0 1", "-1", "1.0-", "1.0\t1"}
	for _, v := range invalid {
		if Valid("rpm", v) {
			t.Errorf("Valid(rpm, %q) = true, want false", v)
		}
	}
	norm := map[string]string{
		"0:1.0-1":   "1.0-1",
		"1:1.0-1":   "1:1.0-1",
		"01:1.0":    "1:1.0",
		" 1.0-1 ":   "1.0-1",
		"1.0-1-2":   "1.0-1-2",
		"":          "",
		"0:1.0^git": "1.0^git",
	}
	for in, want := range norm {
		if got := Normalize("Red Hat:rhel_aus:8.4::appstream", in); got != want {
			t.Errorf("Normalize(rpm, %q) = %q, want %q", in, got, want)
		}
	}
}
