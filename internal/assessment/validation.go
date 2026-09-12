package assessment

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
func validateInput(in Input) error {
	if strings.TrimSpace(in.AdvisoryID) == "" || strings.TrimSpace(in.Package) == "" || strings.TrimSpace(in.Version) == "" {
		return errors.New("assessment: advisory, package and version are required")
	}
	for _, s := range []string{in.AdvisoryID, in.Package, in.Version, in.Ecosystem, in.Environment.OS, in.Environment.OSVersion, in.Environment.Arch} {
		if len(s) > 1024 || !utf8.ValidString(s) {
			return errors.New("assessment: invalid input field")
		}
	}
	if len(in.Summary) > MaxSummaryBytes || len(in.Description) > MaxDescriptionBytes || !utf8.ValidString(in.Summary) || !utf8.ValidString(in.Description) || len(in.Environment.Facts) > 64 || len(in.References) > MaxReferences {
		return errors.New("assessment: input exceeds field limits")
	}
	for k, v := range in.Environment.Facts {
		if len(k) > 128 || len(v) > 2048 || !utf8.ValidString(k) || !utf8.ValidString(v) {
			return errors.New("assessment: invalid environment fact")
		}
	}
	for _, s := range in.References {
		if len(s) > MaxReferenceBytes || !utf8.ValidString(s) {
			return errors.New("assessment: invalid reference")
		}
	}
	return nil
}

// strictObject rejects unknown, missing and duplicate keys. Decoder's ordinary
// struct mode alone accepts duplicate JSON members, including conflicting status.
func strictObject(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("invalid object")
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	result := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok || !allowed[key] || result[key] != nil {
			return nil, errors.New("invalid object keys")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		result[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content")
	}
	if len(result) != len(keys) {
		return nil, errors.New("missing object keys")
	}
	return result, nil
}

func decodeResult(raw []byte, in Input) (Result, error) {
	var r Result
	if len(raw) > maxResponseBytes {
		return r, errors.New("assessment: assessment exceeds size limit")
	}
	fields, err := strictObject(raw, "status", "reason", "evidence", "preconditions", "checks")
	if err != nil {
		return r, errors.New("assessment: invalid assessment JSON schema")
	}
	for _, key := range []string{"status", "reason"} {
		if len(fields[key]) == 0 || fields[key][0] != '"' {
			return r, errors.New("assessment: invalid assessment field type")
		}
	}
	for _, key := range []string{"evidence", "preconditions", "checks"} {
		if len(fields[key]) == 0 || fields[key][0] != '[' {
			return r, errors.New("assessment: invalid assessment field type")
		}
	}
	if json.Unmarshal(raw, &r) != nil {
		return Result{}, errors.New("assessment: invalid assessment field type")
	}
	return validateResult(r, in)
}

func validateResult(r Result, in Input) (Result, error) {
	switch r.Status {
	case LikelyAffected, LikelyNotAffected, NeedsReview:
	default:
		return Result{}, errors.New("assessment: unsupported assessment status")
	}
	if strings.TrimSpace(r.Reason) == "" || utf8.RuneCountInString(r.Reason) > 1200 || !utf8.ValidString(r.Reason) || hasControl(r.Reason) {
		return Result{}, errors.New("assessment: invalid assessment reason")
	}
	for _, items := range [][]string{r.Evidence, r.Preconditions, r.Checks} {
		if items == nil || len(items) > 12 {
			return Result{}, errors.New("assessment: invalid assessment list")
		}
		for _, s := range items {
			if strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > 1000 || !utf8.ValidString(s) {
				return Result{}, errors.New("assessment: invalid assessment list item")
			}
			for _, ch := range s {
				if unicode.IsControl(ch) && ch != '\n' && ch != '\r' && ch != '\t' {
					return Result{}, errors.New("assessment: control characters in assessment")
				}
			}
		}
	}
	grounded := make([]string, 0, len(r.Evidence))
	invalid := false
	for _, snippet := range r.Evidence {
		if strings.Contains(in.Summary, snippet) || strings.Contains(in.Description, snippet) {
			grounded = append(grounded, snippet)
		} else {
			invalid = true
		}
	}
	r.Evidence = grounded
	switch {
	case invalid:
		r.Status = NeedsReview
		r.Reason = "The model cited evidence absent from the supplied advisory; manual review is required."
	case len(grounded) == 0 && r.Status != NeedsReview:
		r.Status = NeedsReview
		r.Reason = "No advisory evidence supports the model's applicability suggestion; manual review is required."
	case r.Status == LikelyNotAffected && (unknownOS(in.Environment.OS) || in.DescriptionTruncated):
		r.Status = NeedsReview
		r.Reason = "Missing operating-system context or a truncated advisory prevents a likely-not-affected assessment."
	}
	return r, nil
}

func unknownOS(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown", "unspecified", "n/a":
		return true
	}
	return false
}
