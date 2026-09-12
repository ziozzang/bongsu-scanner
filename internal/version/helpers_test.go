package version

import (
	"math/rand"
	"reflect"
	"sort"
	"testing"
)

type cmpFunc func(a, b string) int

// must adapts an error-returning comparator into one that fails the test
// on a parse error.
func must(t *testing.T, name string, f func(a, b string) (int, error)) cmpFunc {
	return func(a, b string) int {
		t.Helper()
		c, err := f(a, b)
		if err != nil {
			t.Fatalf("%s(%q, %q): unexpected error: %v", name, a, b, err)
		}
		return c
	}
}

type pair struct {
	a, b string
	want int
}

// checkPairs verifies each expected result together with reflexivity and
// antisymmetry of the pair.
func checkPairs(t *testing.T, name string, cmp cmpFunc, cases []pair) {
	t.Helper()
	for _, c := range cases {
		if got := cmp(c.a, c.b); got != c.want {
			t.Errorf("%s(%q, %q) = %d, want %d", name, c.a, c.b, got, c.want)
		}
		if got := cmp(c.b, c.a); got != -c.want {
			t.Errorf("%s(%q, %q) = %d, want %d (antisymmetry)", name, c.b, c.a, got, -c.want)
		}
		for _, v := range []string{c.a, c.b} {
			if got := cmp(v, v); got != 0 {
				t.Errorf("%s(%q, %q) = %d, want 0 (reflexivity)", name, v, v, got)
			}
		}
	}
}

// checkOrder verifies that sorted is strictly increasing under cmp for
// every pair of positions, then shuffles it repeatedly and checks that
// sort.Slice restores the original order (transitivity in practice).
func checkOrder(t *testing.T, name string, cmp cmpFunc, sorted []string) {
	t.Helper()
	for i := range sorted {
		if c := cmp(sorted[i], sorted[i]); c != 0 {
			t.Errorf("%s(%q, %q) = %d, want 0", name, sorted[i], sorted[i], c)
		}
		for j := i + 1; j < len(sorted); j++ {
			if c := cmp(sorted[i], sorted[j]); c != -1 {
				t.Errorf("%s: want %q < %q, got %d", name, sorted[i], sorted[j], c)
			}
			if c := cmp(sorted[j], sorted[i]); c != 1 {
				t.Errorf("%s: want %q > %q, got %d", name, sorted[j], sorted[i], c)
			}
		}
	}
	rng := rand.New(rand.NewSource(20240910))
	for round := 0; round < 25; round++ {
		shuffled := append([]string(nil), sorted...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		sort.Slice(shuffled, func(i, j int) bool { return cmp(shuffled[i], shuffled[j]) < 0 })
		if !reflect.DeepEqual(shuffled, sorted) {
			t.Errorf("%s: sorting a shuffled list did not restore the order\n got: %q\nwant: %q", name, shuffled, sorted)
			return
		}
	}
}

// checkEqual verifies that every member of each group compares equal to
// every other member of the same group.
func checkEqual(t *testing.T, name string, cmp cmpFunc, groups [][]string) {
	t.Helper()
	for _, g := range groups {
		for _, a := range g {
			for _, b := range g {
				if c := cmp(a, b); c != 0 {
					t.Errorf("%s(%q, %q) = %d, want 0", name, a, b, c)
				}
			}
		}
	}
}
