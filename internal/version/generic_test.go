package version

import "testing"

func TestCompareGenericPairs(t *testing.T) {
	checkPairs(t, "CompareGeneric", CompareGeneric, []pair{
		{"1.0", "1.1", -1},
		{"1.9", "1.10", -1},
		{"1.0", "1.0.1", -1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0b", -1},
		{"1.0.1", "1.0a", -1},
		{"abc", "abd", -1},
		{"a1", "a2", -1},
		{"1", "a", 1},
		{"", "1", -1},
		{"", "", 0},
		{"2024.01.02", "2024.1.2", 0},
		{"v1.0", "v1.1", -1},
		{"v1.0", "1.0", -1},
		{"1.0-rc1", "1.0", 1},
		{"1.0", " 1.0 ", 0},
		{"10", "9", 1},
		{"1.0.0", "1.0", 1},
		{"99999999999999999999", "100000000000000000000", -1},
		{"1-2", "1.2", -1},
	})
}

func TestCompareGenericOrder(t *testing.T) {
	checkOrder(t, "CompareGeneric", CompareGeneric, []string{
		"",
		"a",
		"abc",
		"abd",
		"1",
		"1.0",
		"1.0.1",
		"1.0a",
		"1.0b",
		"1.1",
		"1.9",
		"1.10",
		"2",
		"10",
		"2024.1.2",
		"2024.1.3",
	})
}
