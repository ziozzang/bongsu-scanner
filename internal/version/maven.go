package version

import (
	"strconv"
	"strings"
)

// Maven's ComparableVersion (org.apache.maven.artifact.versioning, as of
// maven-artifact 3.9.6) parses a version into a tree of integer, string
// and list items. '.' separates items, '-' opens a nested list, a
// transition between digits and letters acts like '-', and a qualifier
// that follows '.' is treated as if it followed '-' ("1.0.alpha1" ==
// "1.0-alpha1"). Trailing "null" items (0, empty qualifier, empty list)
// are dropped so that "1.0" == "1" and "1-0" == "1".

const (
	mavenInt = iota
	mavenString
	mavenList
)

type mavenItem struct {
	kind  int
	value string // digits without leading zeros, or the (aliased) qualifier
	list  []*mavenItem
}

// mavenQualifiers is Maven's QUALIFIERS list; the empty string stands for
// a release ("", "ga", "final", "release").
var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

var mavenAliases = map[string]string{
	"ga":      "",
	"final":   "",
	"release": "",
	"cr":      "rc",
}

const mavenReleaseIndex = "5"

// mavenQualifier is ComparableVersion.StringItem.comparableQualifier():
// known qualifiers map to their index, unknown ones sort after all known
// ones, lexically among themselves.
func mavenQualifier(q string) string {
	for i, k := range mavenQualifiers {
		if k == q {
			return strconv.Itoa(i)
		}
	}
	return strconv.Itoa(len(mavenQualifiers)) + "-" + q
}

func newMavenInt(s string) *mavenItem {
	return &mavenItem{kind: mavenInt, value: stripZeros(s)}
}

func newMavenString(s string, followedByDigit bool) *mavenItem {
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	if alias, ok := mavenAliases[s]; ok {
		s = alias
	}
	return &mavenItem{kind: mavenString, value: s}
}

func (it *mavenItem) isNull() bool {
	switch it.kind {
	case mavenInt:
		return it.value == "0"
	case mavenString:
		return mavenQualifier(it.value) == mavenReleaseIndex
	default:
		return len(it.list) == 0
	}
}

// normalize drops trailing null items, stopping at the first non-null
// item that is not a list.
func (it *mavenItem) normalize() {
	for i := len(it.list) - 1; i >= 0; i-- {
		last := it.list[i]
		if last.isNull() {
			it.list = append(it.list[:i], it.list[i+1:]...)
		} else if last.kind != mavenList {
			break
		}
	}
}

func parseMaven(v string) *mavenItem {
	s := strings.ToLower(strings.TrimSpace(v))
	root := &mavenItem{kind: mavenList}
	list := root
	stack := []*mavenItem{root}
	push := func() {
		nl := &mavenItem{kind: mavenList}
		list.list = append(list.list, nl)
		list = nl
		stack = append(stack, nl)
	}
	digits := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if i == start {
				list.list = append(list.list, newMavenInt("0"))
			} else {
				list.list = append(list.list, mavenParseItem(digits, s[start:i]))
			}
			start = i + 1
		case c == '-':
			if i == start {
				list.list = append(list.list, newMavenInt("0"))
			} else {
				list.list = append(list.list, mavenParseItem(digits, s[start:i]))
			}
			start = i + 1
			push()
		case isDigit(c):
			if !digits && i > start {
				// 1.0.0.X1 < 1.0.0-X2: treat .X as -X for any qualifier X
				if len(list.list) > 0 {
					push()
				}
				list.list = append(list.list, newMavenString(s[start:i], true))
				start = i
				push()
			}
			digits = true
		default:
			if digits && i > start {
				list.list = append(list.list, mavenParseItem(true, s[start:i]))
				start = i
				push()
			}
			digits = false
		}
	}
	if len(s) > start {
		// a trailing qualifier also gets the .X -> -X treatment
		if !digits && len(list.list) > 0 {
			push()
		}
		list.list = append(list.list, mavenParseItem(digits, s[start:]))
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].normalize()
	}
	return root
}

func mavenParseItem(digits bool, s string) *mavenItem {
	if digits {
		return newMavenInt(s)
	}
	return newMavenString(s, false)
}

// mavenCompare is Item.compareTo(); y may be nil, meaning "no item".
func mavenCompare(x, y *mavenItem) int {
	switch x.kind {
	case mavenInt:
		if y == nil {
			if x.value == "0" {
				return 0
			}
			return 1
		}
		switch y.kind {
		case mavenInt:
			return cmpDigits(x.value, y.value)
		default: // 1.1 > 1-sp, 1.1 > 1-1
			return 1
		}
	case mavenString:
		if y == nil { // 1-rc < 1, 1-ga == 1, 1-sp > 1
			return strings.Compare(mavenQualifier(x.value), mavenReleaseIndex)
		}
		switch y.kind {
		case mavenString:
			return strings.Compare(mavenQualifier(x.value), mavenQualifier(y.value))
		default: // 1.any < 1.1, 1.any < 1-1
			return -1
		}
	default:
		if y == nil {
			for _, it := range x.list {
				if c := mavenCompare(it, nil); c != 0 {
					return c
				}
			}
			return 0
		}
		switch y.kind {
		case mavenInt: // 1-1 < 1.0.x
			return -1
		case mavenString: // 1-1 > 1-sp
			return 1
		}
		for k := 0; k < len(x.list) || k < len(y.list); k++ {
			var l, r *mavenItem
			if k < len(x.list) {
				l = x.list[k]
			}
			if k < len(y.list) {
				r = y.list[k]
			}
			var c int
			switch {
			case l == nil && r == nil:
				c = 0
			case l == nil:
				c = -mavenCompare(r, nil)
			default:
				c = mavenCompare(l, r)
			}
			if c != 0 {
				return c
			}
		}
		return 0
	}
}

// String renders Maven's canonical form ("1.0-alpha1" -> "1-alpha-1").
// It differs from ComparableVersion.getCanonical() in two details that
// make the result parse back to the same tree: a nested list in first
// position keeps its '-', and an empty (release) qualifier that survives
// normalization is written as "ga".
func (it *mavenItem) String() string {
	if it.kind == mavenString && it.value == "" {
		return "ga"
	}
	if it.kind != mavenList {
		return it.value
	}
	var b strings.Builder
	for i, sub := range it.list {
		switch {
		case sub.kind == mavenList:
			b.WriteByte('-')
		case i > 0:
			b.WriteByte('.')
		}
		b.WriteString(sub.String())
	}
	return b.String()
}

// CompareMaven compares two versions with Maven's ComparableVersion rules.
// Qualifiers are case-insensitive and ordered
// alpha < beta < milestone < rc(cr) < snapshot < release(ga, final, "") < sp,
// with any other qualifier sorting after "sp" in lexical order.
func CompareMaven(a, b string) int {
	return mavenCompare(parseMaven(a), parseMaven(b))
}

// normalizeMaven returns the canonical item form. Input whose canonical
// form is blank (for example "-" or "0.0") is returned unchanged so that a
// valid version never normalizes to an invalid one.
func normalizeMaven(v string) string {
	if strings.TrimSpace(v) == "" {
		return v
	}
	if n := parseMaven(v).String(); n != "" {
		return n
	}
	return v
}
