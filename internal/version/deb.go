package version

import "strings"

// CompareDeb compares two Debian package versions of the form
// [epoch:]upstream[-revision] with the dpkg algorithm (Debian Policy
// §5.6.12, lib/dpkg/vercmp.c). A missing epoch is 0 and a missing revision
// is the empty string. The comparison is total: any input is accepted.
func CompareDeb(a, b string) int {
	ea, ua, ra := splitDeb(a)
	eb, ub, rb := splitDeb(b)
	// verrevcmp on two digit runs is a plain numeric comparison, and it also
	// gives a deterministic answer for malformed epochs.
	if c := debVerRevCmp(ea, eb); c != 0 {
		return c
	}
	if c := debVerRevCmp(ua, ub); c != 0 {
		return c
	}
	return debVerRevCmp(ra, rb)
}

// splitDeb separates epoch, upstream version and Debian revision. The epoch
// ends at the first ':' and the revision starts at the last '-', as in dpkg.
func splitDeb(v string) (epoch, upstream, revision string) {
	v = strings.TrimSpace(cutNUL(v))
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// debOrder is dpkg's order(): '~' sorts before everything (even the end of
// the string), letters sort before non-letters, digits/end sort at 0.
func debOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

// debVerRevCmp is dpkg's verrevcmp(): alternate between comparing
// non-digit runs character by character (using debOrder) and comparing
// digit runs numerically.
func debVerRevCmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac := debOrder(byteAt(a, i))
			bc := debOrder(byteAt(b, j))
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

// validDeb mirrors the hard errors of dpkg's parseversion(): empty
// version, non-numeric or empty epoch, nothing after the colon, empty
// revision, and characters outside the allowed alphabet. dpkg only warns
// when the upstream version does not start with a digit, so that is
// accepted here too.
func validDeb(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || v != cutNUL(v) {
		return false
	}
	hasEpoch := false
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch := v[:i]
		if !allDigits(epoch) {
			return false
		}
		v = v[i+1:]
		hasEpoch = true
		if v == "" {
			return false
		}
	}
	upstream, revision := v, ""
	hasRev := false
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
		hasRev = true
		if revision == "" {
			return false
		}
	}
	if upstream == "" {
		return false
	}
	for i := 0; i < len(upstream); i++ {
		c := upstream[i]
		switch {
		case isAlnum(c), c == '.', c == '+', c == '~':
		case c == '-' && hasRev:
		case c == ':' && hasEpoch:
		default:
			return false
		}
	}
	for i := 0; i < len(revision); i++ {
		c := revision[i]
		if !isAlnum(c) && c != '.' && c != '+' && c != '~' {
			return false
		}
	}
	return true
}

// normalizeDeb trims whitespace and drops a zero epoch ("0:1.2-1" and
// "1.2-1" compare equal under dpkg). Invalid input is returned unchanged.
func normalizeDeb(v string) string {
	if !validDeb(v) {
		return v
	}
	v = strings.TrimSpace(v)
	i := strings.IndexByte(v, ':')
	if i < 0 {
		return v
	}
	epoch, rest := strings.TrimLeft(v[:i], "0"), v[i+1:]
	if epoch == "" {
		if strings.Contains(rest, ":") {
			// dpkg only permits ':' in the upstream version when an epoch is
			// present; dropping the epoch would move the split point.
			return "0:" + rest
		}
		return rest
	}
	return epoch + v[i:]
}
