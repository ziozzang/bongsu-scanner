package sbom

import (
	"regexp"
	"strings"
)

// licenseTokenRE admits the identifier alphabet and a trailing '+' operator.
var licenseTokenRE = regexp.MustCompile(`^[A-Za-z0-9.+-]+$`)

// Bound tokenization work and recursive parser depth for untrusted metadata.
const (
	maxLicenseExpressionBytes = 4 * 1024
	maxLicenseTokens          = 512
)

// licenseExpression validates s against the SPDX 2.3 license expression
// grammar (Annex D) and returns it with whitespace collapsed and operators
// upper-cased:
//
//	expression := term { ("AND" | "OR") term }
//	term       := "(" expression ")" | id [ "WITH" id ]
//	id         := [A-Za-z0-9.+-]+ that is not an operator
//
// Operators are matched case-insensitively because lockfiles frequently
// carry "MIT and Apache-2.0"; the returned expression is canonical. IDs and
// exceptions must appear in the checked-in SPDX list. Custom LicenseRef
// values fall back to text because scan results do not supply the extracted
// licensing information needed to define those references in the document.
func licenseExpression(s string) (string, bool) {
	toks, ok := tokenizeLicense(s)
	if !ok || len(toks) == 0 {
		return "", false
	}
	p := licenseParser{toks: toks}
	p.out.Grow(len(s))
	if !p.expr() || p.pos != len(toks) {
		return "", false
	}
	return p.out.String(), true
}

// validLicenseExpression reports whether s parses as an SPDX expression.
func validLicenseExpression(s string) bool {
	_, ok := licenseExpression(s)
	return ok
}

func tokenizeLicense(s string) ([]string, bool) {
	if len(s) > maxLicenseExpressionBytes {
		return nil, false
	}
	var toks []string
	appendToken := func(t string) bool {
		if len(toks) >= maxLicenseTokens {
			return false
		}
		toks = append(toks, t)
		return true
	}
	var cur strings.Builder
	flush := func() bool {
		if cur.Len() == 0 {
			return true
		}
		t := cur.String()
		cur.Reset()
		if !licenseTokenRE.MatchString(t) || !strings.ContainsAny(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") {
			return false
		}
		return appendToken(t)
	}
	for _, r := range s {
		switch {
		case r == '(' || r == ')':
			if !flush() {
				return nil, false
			}
			if !appendToken(string(r)) {
				return nil, false
			}
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if !flush() {
				return nil, false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if !flush() {
		return nil, false
	}
	return toks, true
}

func isLicenseOperator(t string) bool {
	switch strings.ToUpper(t) {
	case "AND", "OR", "WITH":
		return true
	}
	return false
}

type licenseParser struct {
	toks []string
	pos  int
	out  strings.Builder
}

func (p *licenseParser) peek() string {
	if p.pos >= len(p.toks) {
		return ""
	}
	return p.toks[p.pos]
}

func (p *licenseParser) expr() bool {
	if !p.term() {
		return false
	}
	for {
		op := strings.ToUpper(p.peek())
		if op != "AND" && op != "OR" {
			return true
		}
		p.pos++
		p.out.WriteByte(' ')
		p.out.WriteString(op)
		p.out.WriteByte(' ')
		if !p.term() {
			return false
		}
	}
}

func (p *licenseParser) term() bool {
	t := p.peek()
	switch {
	case t == "":
		return false
	case t == "(":
		p.pos++
		p.out.WriteByte('(')
		if !p.expr() || p.peek() != ")" {
			return false
		}
		p.pos++
		p.out.WriteByte(')')
		return true
	case t == ")" || isLicenseOperator(t):
		return false
	}
	canonical := spdxLicenseIDs[strings.ToLower(t)]
	if canonical == "" && strings.HasSuffix(t, "+") && strings.Count(t, "+") == 1 {
		if base := spdxLicenseIDs[strings.ToLower(strings.TrimSuffix(t, "+"))]; base != "" {
			canonical = base + "+"
		}
	}
	if canonical == "" {
		return false
	}
	p.out.WriteString(canonical)
	p.pos++
	if !strings.EqualFold(p.peek(), "WITH") {
		return true
	}
	p.pos++
	e := p.peek()
	e = spdxExceptionIDs[strings.ToLower(e)]
	if e == "" {
		return false
	}
	p.pos++
	p.out.WriteString(" WITH ")
	p.out.WriteString(e)
	return true
}
