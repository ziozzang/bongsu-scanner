package version

import "strings"

// Alpine version grammar (apk-tools src/version.c):
//
//	number ('.' number)* [letter] ('_' suffix [number])* ['-r' number]
//
// where suffix is one of the pre-release markers alpha, beta, pre, rc
// (sorting before the bare version) or the post-release markers cvs, svn,
// git, hg, p (sorting after it).
//
// apk-tools compares a stream of typed tokens. This implementation parses
// the same grammar, compares the numeric components and the letter as
// fields, and then compares the remaining suffix/number/revision tokens
// lexicographically under a total order on tokens, which reproduces the
// answers of apk-tools 2.14 (checked against `apk version -t`) while
// guaranteeing antisymmetry and transitivity.

type apkNum struct {
	zeros  int    // count of leading zeros (components after the first only)
	digits string // remaining digits, may be empty when the component is all zeros
}

// apkToken is one element of the suffix/revision stream.
type apkToken struct {
	kind  int    // apkSuffixPre, apkEnd, apkRevision, apkSuffixNo, apkSuffixPost
	rank  int    // suffix marker rank (suffix tokens only)
	value string // digits (number and revision tokens)
}

// Token kinds in the order apk-tools ranks them when two versions diverge
// in token type: a pre-release marker sorts below the end of the string,
// a revision above it, an explicit suffix number above a revision, and a
// post-release marker above everything.
const (
	apkSuffixPre = iota
	apkEnd
	apkRevision
	apkSuffixNo
	apkSuffixPost
)

type apkVersion struct {
	nums   []apkNum
	letter byte // 0 when absent
	tokens []apkToken
	tail   string // unparsed remainder, "" for a well-formed version
}

// apkSuffixes lists the markers in the order apk-tools probes them. "pre"
// precedes "p" on purpose: apk matches by prefix in this order.
var apkSuffixes = []struct {
	name string
	rank int
}{
	{"alpha", -4}, {"beta", -3}, {"pre", -2}, {"rc", -1},
	{"cvs", 0}, {"svn", 1}, {"git", 2}, {"hg", 3}, {"p", 4},
}

func parseApk(v string) apkVersion {
	s := strings.TrimSpace(v)
	var p apkVersion
	i := 0
	j := i
	for j < len(s) && isDigit(s[j]) {
		j++
	}
	if j == i {
		p.tail = s
		return p
	}
	// The first component is read as a plain number (TOKEN_DIGIT); the
	// leading-zero rule below only applies after a '.' (TOKEN_DIGIT_OR_ZERO).
	p.nums = append(p.nums, apkNum{digits: s[i:j]})
	i = j
	for i+1 < len(s) && s[i] == '.' && isDigit(s[i+1]) {
		i++
		j = i
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		comp := s[i:j]
		n := apkNum{}
		if comp[0] == '0' {
			for n.zeros < len(comp) && comp[n.zeros] == '0' {
				n.zeros++
			}
			n.digits = comp[n.zeros:]
		} else {
			n.digits = comp
		}
		p.nums = append(p.nums, n)
		i = j
	}
	if i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
		p.letter = s[i]
		i++
	}
	for i < len(s) && s[i] == '_' {
		rest := s[i+1:]
		found := false
		for _, sf := range apkSuffixes {
			if strings.HasPrefix(rest, sf.name) {
				i += 1 + len(sf.name)
				kind := apkSuffixPost
				if sf.rank < 0 {
					kind = apkSuffixPre
				}
				p.tokens = append(p.tokens, apkToken{kind: kind, rank: sf.rank})
				j = i
				for j < len(s) && isDigit(s[j]) {
					j++
				}
				if j > i {
					p.tokens = append(p.tokens, apkToken{kind: apkSuffixNo, value: s[i:j]})
				}
				i = j
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	if i+1 < len(s) && s[i] == '-' && s[i+1] == 'r' {
		j = i + 2
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		p.tokens = append(p.tokens, apkToken{kind: apkRevision, value: s[i+2 : j]})
		i = j
	}
	p.tail = s[i:]
	return p
}

// cmpApkNum reproduces apk's token values: a component with n leading
// zeros is worth -n followed by the remaining digits, so "1.0" < "1.01" and
// "1.00" < "1.0" < "1.1".
func cmpApkNum(x, y apkNum) int {
	if x.zeros != y.zeros {
		if x.zeros == 0 {
			return 1
		}
		if y.zeros == 0 {
			return -1
		}
		return sign(y.zeros - x.zeros)
	}
	return cmpDigits(x.digits, y.digits)
}

func cmpApkToken(x, y apkToken) int {
	if x.kind != y.kind {
		return sign(x.kind - y.kind)
	}
	switch x.kind {
	case apkSuffixPre, apkSuffixPost:
		return sign(x.rank - y.rank)
	case apkSuffixNo, apkRevision:
		return cmpDigits(x.value, y.value)
	}
	return 0
}

// CompareApk compares two Alpine (apk-tools) package versions. Unparsable
// trailing text is kept as a tail that sorts after a clean version.
func CompareApk(a, b string) int {
	pa, pb := parseApk(a), parseApk(b)
	for k := 0; k < len(pa.nums) && k < len(pb.nums); k++ {
		if c := cmpApkNum(pa.nums[k], pb.nums[k]); c != 0 {
			return c
		}
	}
	if len(pa.nums) != len(pb.nums) {
		return sign(len(pa.nums) - len(pb.nums))
	}
	if pa.letter != pb.letter {
		return sign(int(pa.letter) - int(pb.letter))
	}
	end := apkToken{kind: apkEnd}
	for k := 0; k < len(pa.tokens) || k < len(pb.tokens); k++ {
		x, y := end, end
		if k < len(pa.tokens) {
			x = pa.tokens[k]
		}
		if k < len(pb.tokens) {
			y = pb.tokens[k]
		}
		if c := cmpApkToken(x, y); c != 0 {
			return c
		}
	}
	return strings.Compare(pa.tail, pb.tail)
}

func validApk(v string) bool {
	p := parseApk(v)
	return len(p.nums) > 0 && p.tail == ""
}

func normalizeApk(v string) string {
	if !validApk(v) {
		return v
	}
	return strings.TrimSpace(v)
}
