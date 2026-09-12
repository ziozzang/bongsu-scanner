package version

import "strings"

// CompareRPM compares two RPM labels of the form [epoch:]version[-release]
// using rpmvercmp() on each part in turn. A missing epoch is 0; a missing
// release is the empty string, which sorts before any release.
func CompareRPM(a, b string) int {
	ea, va, ra := splitRPM(a)
	eb, vb, rb := splitRPM(b)
	if c := rpmvercmp(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	return rpmvercmp(ra, rb)
}

func splitRPM(v string) (epoch, ver, rel string) {
	v = strings.TrimSpace(cutNUL(v))
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if epoch == "" {
		epoch = "0"
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// rpmvercmp is a port of rpm's lib/rpmvercmp.c. Segments of digits or
// letters are compared in turn; separators are skipped; '~' sorts before
// everything (including the end of the string) and '^' sorts after the end
// of the string but before any other segment. A numeric segment always
// beats an alphabetic one.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ca, cb := byteAt(a, i), byteAt(b, j)
		if ca == '~' || cb == '~' {
			if ca != '~' {
				return 1
			}
			if cb != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if ca == '^' || cb == '^' {
			if ca == 0 {
				return -1
			}
			if cb == 0 {
				return 1
			}
			if ca != '^' {
				return 1
			}
			if cb != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if ca == 0 || cb == 0 {
			break
		}
		si, sj := i, j
		isnum := isDigit(ca)
		if isnum {
			for si < len(a) && isDigit(a[si]) {
				si++
			}
			for sj < len(b) && isDigit(b[sj]) {
				sj++
			}
		} else {
			for si < len(a) && isAlpha(a[si]) {
				si++
			}
			for sj < len(b) && isAlpha(b[sj]) {
				sj++
			}
		}
		segA, segB := a[i:si], b[j:sj]
		if segB == "" {
			// Different segment types: numeric is newer than alphabetic.
			if isnum {
				return 1
			}
			return -1
		}
		if isnum {
			if c := cmpDigits(segA, segB); c != 0 {
				return c
			}
		} else if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
		i, j = si, sj
	}
	if i >= len(a) && j >= len(b) {
		return 0
	}
	if i >= len(a) {
		return -1
	}
	return 1
}

// validRPM accepts non-empty labels whose epoch (if any) is numeric, whose
// version is non-empty, and that contain neither whitespace nor a second
// '-' or ':' (rpm forbids those characters inside version and release).
func validRPM(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if !allDigits(v[:i]) {
			return false
		}
		v = v[i+1:]
	}
	if v == "" || strings.Count(v, "-") > 1 || strings.ContainsRune(v, ':') {
		return false
	}
	if i := strings.IndexByte(v, '-'); i == 0 || i == len(v)-1 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] >= 0x7f {
			return false
		}
	}
	return true
}

// normalizeRPM trims whitespace and drops a zero epoch, which rpm treats
// as absent. Invalid input is returned unchanged.
func normalizeRPM(v string) string {
	if !validRPM(v) {
		return v
	}
	v = strings.TrimSpace(v)
	i := strings.IndexByte(v, ':')
	if i < 0 {
		return v
	}
	epoch := strings.TrimLeft(v[:i], "0")
	if epoch == "" {
		return v[i+1:]
	}
	return epoch + v[i:]
}
