package selfupdate

import "testing"

func TestCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"1.2.3", "1.2.3", 0}, {"v1.2.4", "1.2.3", 1}, {"1.2.2", "1.2.3", -1}, {"1.10", "1.9.9", 1}} {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q,%q)=%d", tc.a, tc.b, got)
		}
	}
}
