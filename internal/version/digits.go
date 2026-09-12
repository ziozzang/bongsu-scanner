package version

import "strings"

// cmpDigits compares two runs of ASCII digits numerically. It never converts
// to an integer, so arbitrarily long runs cannot overflow. An empty string
// counts as zero.
func cmpDigits(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

// stripZeros removes leading zeros from a digit run, keeping at least "0".
func stripZeros(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// cutNUL truncates s at its first NUL byte, mirroring the C string
// semantics of the dpkg and rpm reference implementations.
func cutNUL(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}

// byteAt returns s[i], or 0 when i is past the end of s.
func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}
