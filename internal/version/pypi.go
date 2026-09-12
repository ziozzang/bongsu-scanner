package version

import (
	"fmt"
	"regexp"
	"strings"
)

// pep440Pattern is the reference regular expression from PEP 440
// (Appendix B) with a leading 'v' and surrounding whitespace tolerated.
var pep440Pattern = regexp.MustCompile(`(?i)^v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<preL>alpha|beta|preview|pre|a|b|c|rc)[-_.]?(?P<preN>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<postN1>[0-9]+))|(?:[-_.]?(?P<postL>post|rev|r)[-_.]?(?P<postN2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?(?P<devL>dev)[-_.]?(?P<devN>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

var pep440Groups = func() map[string]int {
	m := map[string]int{}
	for i, name := range pep440Pattern.SubexpNames() {
		if name != "" {
			m[name] = i
		}
	}
	return m
}()

type pep440Version struct {
	epoch   string   // digits, "0" by default
	release []string // digit strings with leading zeros stripped
	hasPre  bool
	preL    string // "a", "b" or "rc"
	preN    string
	hasPost bool
	postN   string
	hasDev  bool
	devN    string
	local   []string // normalized local segments, nil when absent
}

func parsePyPI(v string) (pep440Version, error) {
	var out pep440Version
	m := pep440Pattern.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return out, fmt.Errorf("pypi: invalid PEP 440 version %q", v)
	}
	get := func(name string) string { return m[pep440Groups[name]] }
	out.epoch = stripZeros(get("epoch"))
	for _, r := range strings.Split(get("release"), ".") {
		out.release = append(out.release, stripZeros(r))
	}
	if get("pre") != "" {
		out.hasPre = true
		switch strings.ToLower(get("preL")) {
		case "a", "alpha":
			out.preL = "a"
		case "b", "beta":
			out.preL = "b"
		default: // c, rc, pre, preview
			out.preL = "rc"
		}
		out.preN = stripZeros(get("preN"))
	}
	if get("post") != "" {
		out.hasPost = true
		if n := get("postN1"); n != "" {
			out.postN = stripZeros(n)
		} else {
			out.postN = stripZeros(get("postN2"))
		}
	}
	if get("dev") != "" {
		out.hasDev = true
		out.devN = stripZeros(get("devN"))
	}
	if local := get("local"); local != "" {
		for _, seg := range strings.FieldsFunc(strings.ToLower(local), func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		}) {
			if allDigits(seg) {
				seg = stripZeros(seg)
			}
			out.local = append(out.local, seg)
		}
	}
	return out, nil
}

// String returns the PEP 440 normalized form:
// [N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local].
func (p pep440Version) String() string {
	var b strings.Builder
	if p.epoch != "0" {
		b.WriteString(p.epoch)
		b.WriteByte('!')
	}
	b.WriteString(strings.Join(p.release, "."))
	if p.hasPre {
		b.WriteString(p.preL)
		b.WriteString(p.preN)
	}
	if p.hasPost {
		b.WriteString(".post")
		b.WriteString(p.postN)
	}
	if p.hasDev {
		b.WriteString(".dev")
		b.WriteString(p.devN)
	}
	if p.local != nil {
		b.WriteByte('+')
		b.WriteString(strings.Join(p.local, "."))
	}
	return b.String()
}

// preRank orders the pre-release segment as packaging's _cmpkey does: a
// dev-only version sorts below every pre-release, a version without a
// pre-release segment sorts above every pre-release.
func (p pep440Version) preRank() int {
	switch {
	case !p.hasPre && !p.hasPost && p.hasDev:
		return -1
	case !p.hasPre:
		return 3
	case p.preL == "a":
		return 0
	case p.preL == "b":
		return 1
	default:
		return 2
	}
}

func comparePyPI(x, y pep440Version) int {
	if c := cmpDigits(x.epoch, y.epoch); c != 0 {
		return c
	}
	xr, yr := trimTrailingZeros(x.release), trimTrailingZeros(y.release)
	for k := 0; k < len(xr) && k < len(yr); k++ {
		if c := cmpDigits(xr[k], yr[k]); c != 0 {
			return c
		}
	}
	if c := sign(len(xr) - len(yr)); c != 0 {
		return c
	}
	if c := sign(x.preRank() - y.preRank()); c != 0 {
		return c
	}
	if x.hasPre && y.hasPre {
		if c := cmpDigits(x.preN, y.preN); c != 0 {
			return c
		}
	}
	// post: absent sorts first.
	if x.hasPost != y.hasPost {
		if x.hasPost {
			return 1
		}
		return -1
	}
	if x.hasPost {
		if c := cmpDigits(x.postN, y.postN); c != 0 {
			return c
		}
	}
	// dev: absent sorts last.
	if x.hasDev != y.hasDev {
		if x.hasDev {
			return -1
		}
		return 1
	}
	if x.hasDev {
		if c := cmpDigits(x.devN, y.devN); c != 0 {
			return c
		}
	}
	return compareLocal(x.local, y.local)
}

func trimTrailingZeros(r []string) []string {
	for len(r) > 0 && r[len(r)-1] == "0" {
		r = r[:len(r)-1]
	}
	return r
}

// compareLocal orders local version labels: absent sorts first, numeric
// segments beat alphanumeric ones, and a prefix sorts before a longer list.
func compareLocal(x, y []string) int {
	if x == nil || y == nil {
		switch {
		case x == nil && y == nil:
			return 0
		case x == nil:
			return -1
		}
		return 1
	}
	for k := 0; k < len(x) && k < len(y); k++ {
		xd, yd := allDigits(x[k]), allDigits(y[k])
		switch {
		case xd && yd:
			if c := cmpDigits(x[k], y[k]); c != 0 {
				return c
			}
		case xd:
			return 1
		case yd:
			return -1
		default:
			if c := strings.Compare(x[k], y[k]); c != 0 {
				return c
			}
		}
	}
	return sign(len(x) - len(y))
}

// ComparePyPI compares two PEP 440 versions. An unparsable input is an
// error.
func ComparePyPI(a, b string) (int, error) {
	x, err := parsePyPI(a)
	if err != nil {
		return 0, err
	}
	y, err := parsePyPI(b)
	if err != nil {
		return 0, err
	}
	return comparePyPI(x, y), nil
}

func normalizePyPI(v string) string {
	p, err := parsePyPI(v)
	if err != nil {
		return v
	}
	return p.String()
}
