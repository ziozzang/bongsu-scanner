package version

import "testing"

func TestComparePyPIPairs(t *testing.T) {
	cmp := must(t, "ComparePyPI", ComparePyPI)
	checkPairs(t, "ComparePyPI", cmp, []pair{
		// examples from the specification
		{"1.0a1", "1.0b1", -1},
		{"1.0b1", "1.0rc1", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0", "1.0.post1", -1},
		{"1.0.dev1", "1.0a1", -1},
		{"2!1.0", "1.5", 1},
		{"1.0+local", "1.0", 1},
		// release padding
		{"1.0", "1.0.0", 0},
		{"1.0", "1.0.0.0", 0},
		{"1", "1.0", 0},
		{"1.0", "1.0.1", -1},
		{"1.10", "1.9", 1},
		{"2024.2.2", "2024.2.1", 1},
		{"01.02", "1.2", 0},
		// pre/post/dev interplay
		{"1.0.dev1", "1.0.dev2", -1},
		{"1.0.dev2", "1.0a1.dev1", -1},
		{"1.0a1.dev1", "1.0a1", -1},
		{"1.0a1", "1.0a1.post1", -1},
		{"1.0a1.post1", "1.0a2", -1},
		{"1.0rc1", "1.0rc1.post1.dev1", -1},
		{"1.0rc1.post1.dev1", "1.0rc1.post1", -1},
		{"1.0rc1.post1", "1.0", -1},
		{"1.0", "1.0.post1.dev1", -1},
		{"1.0.post1.dev1", "1.0.post1", -1},
		{"1.0.post1", "1.0.post2", -1},
		{"1.0.post2", "1.0.1", -1},
		{"0.0.1.post2.dev3", "0.0.1.post2", -1},
		{"0.0.1.post2.dev3", "0.0.1.post1", 1},
		{"1.26.0b1", "1.26.0", -1},
		{"1.26.0b1", "1.26.0a9", 1},
		{"1.26.0b1", "1.25.9", 1},
		// local versions
		{"1.0+abc", "1.0+abc.1", -1},
		{"1.0+abc.1", "1.0+abc.2", -1},
		{"1.0+abc.2", "1.0+1", -1},
		{"1.0+1", "1.0+2", -1},
		{"1.0+1", "1.0.post1", -1},
		{"1.0+ubuntu.1", "1.0+Ubuntu-1", 0},
		{"1.0+ubuntu.1", "1.0+ubuntu_01", 0},
		// epochs
		{"1!0.1", "2024.2.2", 1},
		{"2!0.1", "1!99", 1},
		{"0!1.0", "1.0", 0},
	})
}

func TestComparePyPIOrder(t *testing.T) {
	checkOrder(t, "ComparePyPI", must(t, "ComparePyPI", ComparePyPI), []string{
		"0.0.1.post1",
		"0.0.1.post2.dev3",
		"0.0.1.post2",
		"1.0.dev1",
		"1.0.dev2",
		"1.0a1.dev1",
		"1.0a1",
		"1.0a1.post1",
		"1.0a2",
		"1.0b1",
		"1.0rc1",
		"1.0rc1.post1.dev1",
		"1.0rc1.post1",
		"1.0",
		"1.0+abc",
		"1.0+abc.1",
		"1.0+abc.2",
		"1.0+1",
		"1.0.post1.dev1",
		"1.0.post1",
		"1.0.post2",
		"1.0.1",
		"1.1",
		"1.26.0b1",
		"1.26.0",
		"2024.2.1",
		"2024.2.2",
		"1!0.1",
		"2!0.1",
		"2!1.0",
	})
}

func TestPyPIEqualGroups(t *testing.T) {
	checkEqual(t, "ComparePyPI", must(t, "ComparePyPI", ComparePyPI), [][]string{
		{"1.0", "1.0.0", "v1.0", "V1.0", "1", " 1.0 ", "0!1.0", "01.0"},
		{"1.0a1", "1.0.a1", "1.0-a1", "1.0_a1", "1.0alpha1", "1.0.alpha.1", "1.0A1", "1.0ALPHA1", "1.0a01"},
		{"1.0b1", "1.0beta1", "1.0-beta-1"},
		{"1.0rc1", "1.0c1", "1.0pre1", "1.0preview1", "1.0.rc.1", "1.0RC1"},
		{"1.0.post1", "1.0-post1", "1.0.post.1", "1.0-1", "1.0.rev1", "1.0.r1", "1.0post1"},
		{"1.0.dev1", "1.0-dev1", "1.0dev1", "1.0_dev_1"},
		{"1.0.post", "1.0.post0"},
		{"1.0a", "1.0a0"},
		{"1.0.dev", "1.0.dev0"},
		{"1.0+ubuntu.1", "1.0+Ubuntu-1", "1.0+ubuntu_01"},
	})
}

func TestPyPIInvalid(t *testing.T) {
	for _, v := range []string{"", " ", "1.0.x", "latest", "1.0-", "1.0+", "1.0+local!", "a1", "1.0.foo", "1.0..1", "1.0a1a", "1.0+", "1.0 1", "!1.0", "1.0.post1.post2"} {
		if _, err := ComparePyPI(v, "1.0"); err == nil {
			t.Errorf("ComparePyPI(%q): want error", v)
		}
		if Valid("PyPI", v) {
			t.Errorf("Valid(PyPI, %q) = true, want false", v)
		}
		if got := Normalize("PyPI", v); got != v {
			t.Errorf("Normalize(PyPI, %q) = %q, want input unchanged", v, got)
		}
	}
}

func TestPyPINormalize(t *testing.T) {
	cases := map[string]string{
		"1.0a1":                     "1.0a1",
		"1.0.alpha.1":               "1.0a1",
		"1.0-post1":                 "1.0.post1",
		"1.0-1":                     "1.0.post1",
		"1.0dev":                    "1.0.dev0",
		"v1.0":                      "1.0",
		"1.0+Ubuntu-01":             "1.0+ubuntu.1",
		"01.02":                     "1.2",
		"0!1.0":                     "1.0",
		"2!1.0rc1.post2.dev3+abc.1": "2!1.0rc1.post2.dev3+abc.1",
		"1.0.0":                     "1.0.0",
		"1.0PRE1":                   "1.0rc1",
		"1.0c1":                     "1.0rc1",
		"1.0.post":                  "1.0.post0",
		"1.0b":                      "1.0b0",
		" 2024.2.2 ":                "2024.2.2",
		"1.26.0B1":                  "1.26.0b1",
		"0.0.1.post2.dev3":          "0.0.1.post2.dev3",
		"1.0.0-rev-2":               "1.0.0.post2",
	}
	for in, want := range cases {
		if got := Normalize("pypi", in); got != want {
			t.Errorf("Normalize(pypi, %q) = %q, want %q", in, got, want)
		}
	}
}
