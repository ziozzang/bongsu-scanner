package version

import "strings"

// CompareGeneric is the fallback comparator for ecosystems without a
// dedicated algorithm. The version is split into maximal runs of digits
// and non-digits; digit runs compare numerically, other runs compare as
// strings, a digit run outranks a non-digit run, and when one token list
// is a prefix of the other the shorter one is smaller.
func CompareGeneric(a, b string) int {
	ta, tb := genericTokens(strings.TrimSpace(a)), genericTokens(strings.TrimSpace(b))
	for k := 0; k < len(ta) && k < len(tb); k++ {
		x, y := ta[k], tb[k]
		xd, yd := isDigit(x[0]), isDigit(y[0])
		switch {
		case xd && yd:
			if c := cmpDigits(x, y); c != 0 {
				return c
			}
		case xd:
			return 1
		case yd:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return sign(len(ta) - len(tb))
}

func genericTokens(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		j := i + 1
		d := isDigit(s[i])
		for j < len(s) && isDigit(s[j]) == d {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}
