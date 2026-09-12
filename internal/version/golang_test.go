package version

import "testing"

func TestCompareGoPairs(t *testing.T) {
	cmp := must(t, "CompareGo", CompareGo)
	checkPairs(t, "CompareGo", cmp, []pair{
		// examples from the specification
		{"v0.0.0-20200101000000-aaaaaaaaaaaa", "v0.0.0-20210101000000-bbbbbbbbbbbb", -1},
		{"v0.0.0-20210101000000-bbbbbbbbbbbb", "v0.1.0", -1},
		{"v1.2.3+incompatible", "v1.2.3", 0},
		// pseudo-versions
		{"v0.0.0-20240103183307-be819d1f06fc", "v0.1.0", -1},
		{"v0.0.0-20240103183307-be819d1f06fc", "v0.0.0-20231201000000-000000000000", 1},
		{"v1.2.3-0.20210101000000-abcdef123456", "v1.2.3", -1},
		{"v1.2.3-0.20210101000000-abcdef123456", "v1.2.2", 1},
		{"v1.2.3-0.20210101000000-abcdef123456", "v1.2.3-pre", -1},
		{"v1.2.3-pre.0.20210101000000-abcdef123456", "v1.2.3-pre", 1},
		{"v1.2.3-pre.0.20210101000000-abcdef123456", "v1.2.3", -1},
		{"v1.2.3-pre.0.20210101000000-abcdef123456", "v1.2.3-pre.0.20210102000000-abcdef123456", -1},
		// 'v' prefix optional, build metadata ignored
		{"1.21.0", "v1.21.0", 0},
		{"v1.21.0", "v1.20.14", 1},
		{"v2.0.0+incompatible", "v1.9.9", 1},
		{"v2.0.0+incompatible", "2.0.0", 0},
		{"v1", "v1.0.0", 0},
		{"v1.2", "v1.2.0", 0},
		{"v1.0.0-rc.1", "v1.0.0", -1},
		{"v0.0.0-20240103183307-be819d1f06fc", "0.0.0-20240103183307-be819d1f06fc", 0},
		{"v1.0.0-alpha", "v1.0.0-beta", -1},
		{"v1.10.0", "v1.9.0", 1},
		{"v0.0.1", "v0.0.0-20240103183307-be819d1f06fc", 1},
	})
}

func TestCompareGoOrder(t *testing.T) {
	checkOrder(t, "CompareGo", must(t, "CompareGo", CompareGo), []string{
		"v0.0.0-20200101000000-aaaaaaaaaaaa",
		"v0.0.0-20210101000000-bbbbbbbbbbbb",
		"v0.0.0-20231201000000-000000000000",
		"v0.0.0-20240103183307-be819d1f06fc",
		"v0.0.1",
		"v0.1.0",
		"v1.0.0-rc.1",
		"v1.0.0",
		"v1.2.2",
		"v1.2.3-0.20210101000000-abcdef123456",
		"v1.2.3-pre",
		"v1.2.3-pre.0.20210101000000-abcdef123456",
		"v1.2.3",
		"v1.20.14",
		"v1.21.0",
		"v2.0.0+incompatible",
		"v2.0.1",
	})
}

func TestGoInvalidAndNormalize(t *testing.T) {
	for _, v := range []string{"", "1.2.3.4", "v1.0.0.0", "v1.x", "master", "v1.0.0-", "latest", "v1.0.0+"} {
		if _, err := CompareGo(v, "v1.0.0"); err == nil {
			t.Errorf("CompareGo(%q): want error", v)
		}
		if Valid("Go", v) {
			t.Errorf("Valid(Go, %q) = true, want false", v)
		}
	}
	cases := map[string]string{
		"v1.21.0":                            "1.21.0",
		"1.21.0":                             "1.21.0",
		"v2.0.0+incompatible":                "2.0.0",
		"v0.0.0-20240103183307-be819d1f06fc": "0.0.0-20240103183307-be819d1f06fc",
		"v1":                                 "1.0.0",
		"v1.2.3-pre.0.20210101000000-abcdef": "1.2.3-pre.0.20210101000000-abcdef",
		"bad":                                "bad",
	}
	for in, want := range cases {
		if got := Normalize("golang", in); got != want {
			t.Errorf("Normalize(golang, %q) = %q, want %q", in, got, want)
		}
	}
}
