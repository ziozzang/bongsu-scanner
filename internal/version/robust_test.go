package version

import (
	"math/rand"
	"testing"
	"testing/quick"
)

// totalComparators never return an error and must be reflexive and
// antisymmetric for every input.
var totalComparators = map[string]cmpFunc{
	"CompareDeb":     CompareDeb,
	"CompareApk":     CompareApk,
	"CompareRPM":     CompareRPM,
	"CompareMaven":   CompareMaven,
	"CompareGeneric": CompareGeneric,
}

// partialComparators may reject input; when they accept a pair they must
// still be reflexive and antisymmetric.
var partialComparators = map[string]func(a, b string) (int, error){
	"CompareSemver": CompareSemver,
	"ComparePyPI":   ComparePyPI,
	"CompareGo":     CompareGo,
}

var allEcosystems = func() []string {
	out := []string{"Debian:13", "Alpine:v3.20", "Red Hat:rhel_aus:8.4::appstream", "unknown", ""}
	for name := range ecosystems {
		out = append(out, name)
	}
	return out
}()

// randomVersions builds strings from an alphabet that exercises every
// separator and marker the comparators care about, plus a few surprises.
func randomVersions(n int, seed int64) []string {
	const alphabet = "0123456789....---___+~^:!vVaAbBcprRcgitsnapshotdevpostrcalphabetafinalga \t\x00/é"
	rng := rand.New(rand.NewSource(seed))
	out := make([]string, 0, n+3)
	out = append(out, "", " ", "\x00")
	for len(out) < n {
		l := rng.Intn(14)
		b := make([]byte, l)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		out = append(out, string(b))
	}
	return out
}

func TestRandomInputsNeverPanic(t *testing.T) {
	versions := randomVersions(1000, 1)
	for i, a := range versions {
		b := versions[(i*7+3)%len(versions)]
		for name, cmp := range totalComparators {
			for _, y := range []string{b, "", a} {
				c := cmp(a, y)
				if c < -1 || c > 1 {
					t.Fatalf("%s(%q, %q) = %d, outside [-1, 1]", name, a, y, c)
				}
				if back := cmp(y, a); back != -c {
					t.Fatalf("%s(%q, %q) = %d but %s(%q, %q) = %d", name, a, y, c, name, y, a, back)
				}
			}
			if cmp(a, a) != 0 {
				t.Fatalf("%s(%q, %q) != 0", name, a, a)
			}
		}
		for name, cmp := range partialComparators {
			for _, y := range []string{b, "", a} {
				c, err := cmp(a, y)
				if err != nil {
					continue
				}
				if c < -1 || c > 1 {
					t.Fatalf("%s(%q, %q) = %d, outside [-1, 1]", name, a, y, c)
				}
				back, err := cmp(y, a)
				if err != nil || back != -c {
					t.Fatalf("%s(%q, %q) = %d but %s(%q, %q) = %d, %v", name, a, y, c, name, y, a, back, err)
				}
			}
			if c, err := cmp(a, a); err == nil && c != 0 {
				t.Fatalf("%s(%q, %q) = %d, want 0", name, a, a, c)
			}
		}
		for _, eco := range allEcosystems {
			n := Normalize(eco, a)
			if Valid(eco, a) && !Valid(eco, n) {
				t.Fatalf("Normalize(%q, %q) = %q is not valid", eco, a, n)
			}
			if _, err := Compare(eco, a, b); err == ErrUnknownEcosystem {
				if _, known := lookup(eco); known {
					t.Fatalf("Compare(%q) reported unknown ecosystem for a known name", eco)
				}
			}
		}
	}
}

func TestQuickAntisymmetry(t *testing.T) {
	cfg := &quick.Config{MaxCount: 2000, Rand: rand.New(rand.NewSource(2))}
	for name, cmp := range totalComparators {
		prop := func(a, b string) bool {
			return cmp(a, a) == 0 && cmp(b, b) == 0 && cmp(a, b) == -cmp(b, a)
		}
		if err := quick.Check(prop, cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, cmp := range partialComparators {
		prop := func(a, b string) bool {
			c, err := cmp(a, b)
			if err != nil {
				return true
			}
			back, err := cmp(b, a)
			return err == nil && back == -c
		}
		if err := quick.Check(prop, cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestRandomTransitivity sorts random inputs with each total comparator
// and checks that the result is consistently ordered, which fails when the
// comparator is not transitive.
func TestRandomTransitivity(t *testing.T) {
	versions := randomVersions(120, 3)
	for name, cmp := range totalComparators {
		for i := range versions {
			for j := i + 1; j < len(versions); j++ {
				for k := j + 1; k < len(versions); k++ {
					a, b, c := versions[i], versions[j], versions[k]
					ab, bc, ac := cmp(a, b), cmp(b, c), cmp(a, c)
					if ab <= 0 && bc <= 0 && ac > 0 || ab >= 0 && bc >= 0 && ac < 0 {
						t.Fatalf("%s not transitive: %q %d %q %d %q but %q %d %q", name, a, ab, b, bc, c, a, ac, c)
					}
					if ab == 0 && bc == 0 && ac != 0 {
						t.Fatalf("%s equality not transitive: %q == %q == %q but cmp(a, c) = %d", name, a, b, c, ac)
					}
				}
			}
		}
	}
}
