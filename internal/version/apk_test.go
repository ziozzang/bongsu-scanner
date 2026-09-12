package version

import "testing"

func TestCompareApkPairs(t *testing.T) {
	checkPairs(t, "CompareApk", CompareApk, []pair{
		// examples from the specification
		{"3.1.4-r5", "3.1.4-r6", -1},
		{"1.36.1-r31", "1.36.1-r3", 1},
		{"2.14.4_rc1-r0", "2.14.4-r0", -1},
		{"1.0_p1", "1.0", 1},
		// revisions
		{"1.0", "1.0-r0", -1},
		{"1.0-r0", "1.0-r1", -1},
		{"1.0-r", "1.0-r0", 0},
		{"3.20.3-r0", "3.20.2-r9", 1},
		// suffixes
		{"1.0_alpha", "1.0_beta", -1},
		{"1.0_beta", "1.0_pre", -1},
		{"1.0_pre", "1.0_rc", -1},
		{"1.0_rc", "1.0", -1},
		{"1.0", "1.0_cvs", -1},
		{"1.0_cvs", "1.0_svn", -1},
		{"1.0_svn", "1.0_git", -1},
		{"1.0_git", "1.0_hg", -1},
		{"1.0_hg", "1.0_p", -1},
		{"1.0_rc1", "1.0_rc2", -1},
		{"1.0_rc", "1.0_rc1", -1},
		{"1.0_rc0", "1.0_rc", 1},
		{"1.0_p", "1.0_p0", -1},
		{"1.0_git20240101", "1.0_git", 1},
		{"1.0_rc1", "1.0_rc1_p1", -1},
		{"1.0_rc1_p1", "1.0", -1},
		{"1.0_p1", "1.0_p2", -1},
		{"1.0_p1", "1.0.1", -1},
		{"1.0_p1", "1.0-r0", 1},
		{"2.14.4_rc1-r0", "2.14.4_rc2-r0", -1},
		// token-type divergence, verified against apk-tools 2.14
		{"1.0_svn-r1", "1.0_svn0", -1},
		{"1.0_svn_rc", "1.0_svn0", -1},
		{"1.0_svn_p1", "1.0_svn0", 1},
		{"1.0_svn", "1.0_svn0", -1},
		{"1.0_p1-r0", "1.0_p1_p2", -1},
		{"1.0_p1-r0", "1.0_p1_rc", 1},
		{"1.0_rc1-r2", "1.0_rc1_p1", -1},
		{"1.0_rc1", "1.0-r0", -1},
		{"1.0b_rc1", "1.0b", -1},
		{"1.0a", "1.0-r1", 1},
		{"1.0a", "1.0_p1", 1},
		{"1.0.1", "1.0-r0", 1},
		{"1", "1.0", -1},
		// letters
		{"1.1.1w-r1", "1.1.1v-r5", 1},
		{"1.1.1w-r1", "1.1.1-r9", 1},
		{"1.2a", "1.2", 1},
		{"1.2a", "1.2b", -1},
		{"1.2a", "1.2_rc1", 1},
		// numeric components and the leading-zero rule
		{"1.0.1", "1.0", 1},
		{"1.0.0", "1.0", 1},
		{"1.0", "1.01", -1},
		{"1.00", "1.0", -1},
		{"1.05", "1.5", -1},
		{"1.05", "1.0.1", 1},
		{"1.10", "1.9", 1},
		{"0.1", "1.0", -1},
		{"20240101", "2.0", 1},
		{"01.0", "1.0", 0},
		{"1.99999999999999999999", "1.9", 1},
		// unparsable tails sort after clean versions
		{"1.0-r1", "1.0-r1x", -1},
		{"1.0-rc1", "1.0-r0", 1},
		{"", "", 0},
		{"", "1", -1},
		{"x", "", 1},
		{"1.0_foo", "1.0", 1},
	})
}

func TestCompareApkOrder(t *testing.T) {
	checkOrder(t, "CompareApk", CompareApk, []string{
		"0.9",
		"1.00",
		"1.0_alpha",
		"1.0_alpha1",
		"1.0_beta",
		"1.0_pre",
		"1.0_rc",
		"1.0_rc1",
		"1.0_rc1_p1",
		"1.0",
		"1.0-r0",
		"1.0-r1",
		"1.0_cvs",
		"1.0_svn",
		"1.0_git",
		"1.0_hg",
		"1.0_p",
		"1.0_p1",
		"1.0.1",
		"1.01",
		"1.05",
		"1.1",
		"1.1.1v-r5",
		"1.1.1w-r1",
		"1.2",
		"1.2a",
		"1.2b",
		"1.5",
		"1.9",
		"1.10",
		"1.36.1-r3",
		"1.36.1-r31",
		"2.14.4_rc1-r0",
		"2.14.4-r0",
		"3.1.4-r5",
		"3.1.4-r6",
		"3.20.2-r9",
		"3.20.3-r0",
	})
}

func TestApkValidNormalize(t *testing.T) {
	valid := []string{"3.20.3-r0", "1.1.1w-r1", "2.14.4_rc1-r0", "1.0_p20240101", "1.0_alpha_p1", "1", "1.0-r", " 1.0-r1 "}
	for _, v := range valid {
		if !Valid("apk", v) {
			t.Errorf("Valid(apk, %q) = false, want true", v)
		}
	}
	invalid := []string{"", " ", "v1.0", "1.0-1", "1.0_foo", "1.0A", "1.0-rc1", "1.0.", "1.0-r1x", "1.0 " + "x"}
	for _, v := range invalid {
		if Valid("apk", v) {
			t.Errorf("Valid(apk, %q) = true, want false", v)
		}
	}
	if got := Normalize("Alpine:v3.20", " 3.20.3-r0 "); got != "3.20.3-r0" {
		t.Errorf("Normalize(apk) = %q", got)
	}
	if got := Normalize("apk", "bad version"); got != "bad version" {
		t.Errorf("Normalize(apk, invalid) = %q, want input", got)
	}
}
