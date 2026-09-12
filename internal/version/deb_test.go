package version

import "testing"

func TestCompareDebPairs(t *testing.T) {
	checkPairs(t, "CompareDeb", CompareDeb, []pair{
		// examples from the specification
		{"8.14.1-2+deb13u3", "8.14.1-2+deb13u4", -1},
		{"2.7.1-2", "2.8.2-1~deb13u1", -1},
		{"2.8.2-1~deb13u1", "2.8.2-1", -1},
		{"1:2.47.3-0+deb13u1", "2.50.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0-1", "1.0-1+b1", -1},
		// epochs
		{"0:1.0", "1.0", 0},
		{"00:1.0", "1.0", 0},
		{"2:1.0", "1:9.9", 1},
		{"1:1.0", "9.9", 1},
		// revisions
		{"1.0", "1.0-0", 0},
		{"1.0", "1.0-1", -1},
		{"1.0-1ubuntu1", "1.0-1", 1},
		{"1.0-1ubuntu1", "1.0-2", -1},
		{"1.0-1~bpo12+1", "1.0-1", -1},
		{"1.2.3-1", "1.2.3-1.1", -1},
		{"1.0-1", "1.0-1", 0},
		// tilde sorts before everything, even the end of the string
		{"1.0~", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~beta1", "1.0~rc1", -1},
		{"0.0.0~git20230101-1", "0.0.0-1", -1},
		// letters sort before non-letters, non-letters after end of string
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0+", -1},
		{"1.0.", "1.0", 1},
		{"1.0+dfsg-1", "1.0-1", 1},
		{"1.0.1", "1.0+dfsg", 1},
		// numeric segments
		{"1.0", "1.0.1", -1},
		{"1.10", "1.9", 1},
		{"1.010", "1.10", 0},
		{"7.88.1-10+deb12u5", "7.88.1-10+deb12u10", -1},
		{"2.36-9+deb12u7", "2.36-9", 1},
		{"5.10.209-2", "5.10.216-1", -1},
		{"1.0", "1.00", 0},
		{"99999999999999999999", "100000000000000000000", -1},
		// degenerate input must still be total
		{"", "", 0},
		{"", "1", -1},
		{"~", "", -1},
		{"a", "", 1},
		{":", "", 0},
		{"-", "", 0},
	})
}

func TestCompareDebOrder(t *testing.T) {
	checkOrder(t, "CompareDeb", CompareDeb, []string{
		"0.0.0~git20230101-1",
		"0.0.0-1",
		"1.0~~",
		"1.0~",
		"1.0~rc1",
		"1.0",
		"1.0-1~bpo12+1",
		"1.0-1",
		"1.0-1ubuntu1",
		"1.0-1+b1",
		"1.0-2",
		"1.0a",
		"1.0a-1",
		"1.0+dfsg-1",
		"1.0.1",
		"1.1",
		"1.10",
		"2.7.1-2",
		"2.8.2-1~deb13u1",
		"2.8.2-1",
		"2.36-9",
		"2.36-9+deb12u7",
		"5.10.209-1",
		"5.10.209-2",
		"5.10.216-1",
		"7.88.1-10+deb12u5",
		"7.88.1-10+deb12u10",
		"8.14.1-2+deb13u3",
		"8.14.1-2+deb13u4",
		"1:1.0",
		"1:2.47.3-0+deb13u1",
		"1:7.88.1-10+deb12u5",
		"2:0.1",
	})
}

func TestDebValidNormalize(t *testing.T) {
	valid := []string{"1.0", "1:7.88.1-10+deb12u5", "5.10.209-2", "2.36-9+deb12u7", "0.0.0~git20230101-1", "1.0+dfsg-1", "1:1.0-1-2", "1:2.3:4-5", "a1", " 1.0 "}
	for _, v := range valid {
		if !Valid("deb", v) {
			t.Errorf("Valid(deb, %q) = false, want true", v)
		}
	}
	invalid := []string{"", " ", "1:", ":1.0", "a:1.0", "1.0-", "1.0 1", "1.0-1:2", "1.0-1-", "1.0_1", "1.0/1", "2.3:4"}
	for _, v := range invalid {
		if Valid("deb", v) {
			t.Errorf("Valid(deb, %q) = true, want false", v)
		}
	}
	norm := map[string]string{
		"0:1.0-1":   "1.0-1",
		"00:1.0":    "1.0",
		"1:1.0":     "1:1.0",
		"01:1.0":    "1:1.0",
		" 1.0-1 ":   "1.0-1",
		"1.0-":      "1.0-",
		"":          "",
		"1:2.3:4-5": "1:2.3:4-5",
	}
	for in, want := range norm {
		if got := Normalize("deb", in); got != want {
			t.Errorf("Normalize(deb, %q) = %q, want %q", in, got, want)
		}
	}
}
