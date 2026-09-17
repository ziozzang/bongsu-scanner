package match

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

func Write(w io.Writer, format string, r Report, d Document) error {
	switch format {
	case "json":
		return writeJSONReport(w, r)
	case "table":
		t := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		withAssessment := false
		for _, finding := range r.Findings {
			if finding.Assessment != nil {
				withAssessment = true
				break
			}
		}
		header := "PACKAGE\tVERSION\tECOSYSTEM\tVULN-ID\tSEVERITY\tSCORE\tFIXED-IN\tMATCHED-BY\tDISTRO-SEVERITY\tDISTRO-STATUS"
		if withAssessment {
			header += "\tLLM-APPLICABILITY\tLLM-REASON"
		}
		if _, e := fmt.Fprintln(t, header); e != nil {
			return e
		}
		for _, f := range r.Findings {
			score := "-"
			if f.Score > 0 {
				score = fmt.Sprintf("%.1f", f.Score)
			}
			cells := []string{f.Subject.Name, f.Subject.Version, f.Subject.Ecosystem, f.ID, f.Severity, score, strings.Join(f.FixedIn, ","), f.MatchedBy, f.DistroSeverity, f.DistroStatus}
			if withAssessment {
				status, reason := "not_assessed", ""
				if f.Assessment != nil {
					status, reason = f.Assessment.Status, f.Assessment.Reason
				}
				cells = append(cells, status, reason)
			}
			for i := range cells {
				cells[i] = httpx.Sanitize(cells[i])
			}
			if _, e := fmt.Fprintln(t, strings.Join(cells, "\t")); e != nil {
				return e
			}
		}
		if e := t.Flush(); e != nil {
			return e
		}
		if _, e := fmt.Fprintf(w, "%d subjects, %d matched, %d vulnerabilities\n", r.Subjects, r.Matched, len(r.Findings)); e != nil {
			return e
		}
		if _, err := fmt.Fprintln(w, reportSeverityPolicy(r)); err != nil {
			return err
		}
		keys := make([]string, 0, len(r.Skipped))
		for k := range r.Skipped {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, e := fmt.Fprintf(w, "Skipped %s: %d\n", httpx.Sanitize(k), r.Skipped[k]); e != nil {
				return e
			}
		}
		for _, warning := range r.MissingCoverage {
			if _, err := fmt.Fprintln(w, "WARNING: "+httpx.Sanitize(warning)); err != nil {
				return err
			}
		}
		return nil
	case "cyclonedx":
		return writeCycloneDX(w, r, d)
	default:
		return fmt.Errorf("unsupported match output format %q", format)
	}
}

// Encode findings individually so encoding/json does not retain a second
// report-sized buffer alongside the command's atomic output buffer.
func writeJSONReport(w io.Writer, r Report) error {
	// The command intentionally buffers output before atomic publication. Size
	// that buffer once to avoid retaining geometrically growing intermediate
	// copies; other writers still receive each finding directly.
	if buffer, ok := w.(*bytes.Buffer); ok {
		var size jsonSizeWriter
		if err := encodeJSONReport(&size, r); err != nil {
			return err
		}
		buffer.Grow(int(size))
	}
	return encodeJSONReport(w, r)
}

type jsonSizeWriter int

func (w *jsonSizeWriter) Write(p []byte) (int, error) {
	*w += jsonSizeWriter(len(p))
	return len(p), nil
}

func encodeJSONReport(w io.Writer, r Report) error {
	if r.Findings == nil {
		return json.NewEncoder(w).Encode(r)
	}
	if _, err := io.WriteString(w, `{"Findings":[`); err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	for i := range r.Findings {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := encoder.Encode(&r.Findings[i]); err != nil {
			return err
		}
	}
	type reportFields Report
	tail := struct {
		*reportFields
		Findings []Finding `json:"Findings,omitempty"`
	}{reportFields: (*reportFields)(&r)}
	data, err := json.Marshal(tail)
	if err != nil {
		return err
	}
	if _, err = io.WriteString(w, "],"); err != nil {
		return err
	}
	if _, err = w.Write(data[1:]); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n")
	return err
}

func writeCycloneDX(w io.Writer, r Report, d Document) error {
	// Preserve the historical compact-file encoder byte for byte, including
	// generated refs, float64 numbers and sorted keys. Only CycloneDX pays for
	// materializing unknown fields; table/JSON retain no copy of the source.
	if d.Format == "cyclonedx" && d.sourcePath != "" {
		data, err := os.ReadFile(d.sourcePath)
		if err != nil {
			return err
		}
		if sha256.Sum256(data) != d.sourceHash {
			return fmt.Errorf("SBOM changed after loading: %s", d.sourcePath)
		}
		d, err = loadCompactFile(data)
		if err != nil {
			return err
		}
	}

	out := map[string]any{}
	if d.Format == "cyclonedx" {
		for k, v := range d.Raw {
			out[k] = v
		}
	} else {
		out["bomFormat"] = "CycloneDX"
		out["specVersion"] = "1.6"
		out["version"] = 1
		components := []any{}
		seen := map[string]bool{}
		for _, f := range r.Findings {
			s := f.Subject
			if seen[s.Ref] {
				continue
			}
			seen[s.Ref] = true
			c := map[string]any{"type": "library", "bom-ref": s.Ref, "name": s.Name, "version": s.Version}
			if p := s.PURL.String(); p != "" {
				c["purl"] = p
			}
			components = append(components, c)
		}
		out["components"] = components
	}
	// The vulnerability representation targets 1.6, including CVSSv4.
	out["specVersion"] = "1.6"
	if d.Format == "cyclonedx" {
		if v, ok := out["version"].(float64); ok {
			out["version"] = v + 1
		} else {
			out["version"] = 2
		}
	}
	out["$schema"] = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	// Any embedded signature authenticated the original bytes/content.
	delete(out, "signature")

	// Stream top-level arrays, including vulnerabilities, so neither the
	// object tree nor encoding/json needs a report-sized temporary buffer.
	if len(r.MissingCoverage) > 0 {
		properties := append([]any(nil), arr(out["properties"])...)
		for _, warning := range r.MissingCoverage {
			properties = append(properties, map[string]any{"name": "bscan:coverage-warning", "value": warning})
		}
		out["properties"] = properties
	}
	properties := append([]any(nil), arr(out["properties"])...)
	out["properties"] = append(properties, map[string]any{"name": "bscan:severity-policy", "value": reportSeverityPolicy(r)})
	out["vulnerabilities"] = nil
	// The CLI uses an atomic output buffer. Avoid retaining its geometrically
	// growing intermediate copies alongside the CycloneDX compatibility tree.
	if buffer, ok := w.(*bytes.Buffer); ok {
		var size jsonSizeWriter
		if err := encodeCycloneDX(&size, r, out); err != nil {
			return err
		}
		buffer.Grow(int(size))
	}
	return encodeCycloneDX(w, r, out)
}

func encodeCycloneDX(w io.Writer, r Report, out map[string]any) error {
	keys := make([]string, 0, len(out))
	for key := range out {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	for i, key := range keys {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		name, err := json.Marshal(key)
		if err != nil {
			return err
		}
		if _, err = w.Write(name); err != nil {
			return err
		}
		if _, err = io.WriteString(w, ":"); err != nil {
			return err
		}
		values, array := out[key].([]any)
		if key != "vulnerabilities" && !array {
			if err := enc.Encode(out[key]); err != nil {
				return err
			}
			continue
		}
		if _, err := io.WriteString(w, "["); err != nil {
			return err
		}
		n := len(values)
		if key == "vulnerabilities" {
			n = len(r.Findings)
		}
		for j := 0; j < n; j++ {
			if j > 0 {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			var value any
			if key == "vulnerabilities" {
				value = cycloneDXFinding(r.Findings[j])
			} else {
				value = values[j]
			}
			if err := enc.Encode(value); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "]"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "}\n")
	return err
}

func cycloneDXFinding(f Finding) map[string]any {

	source := map[string]any{"name": f.Record.Source}
	if len(f.Record.References) > 0 {
		source["url"] = f.Record.References[0]
	}
	level := strings.ToLower(f.Severity)
	if level == "negligible" {
		level = "none"
	}
	method := "other"
	switch {
	case strings.HasPrefix(f.Vector, "CVSS:3.1/"):
		method = "CVSSv31"
	case strings.HasPrefix(f.Vector, "CVSS:3.0/"):
		method = "CVSSv3"
	case strings.HasPrefix(f.Vector, "CVSS:4.0/"):
		method = "CVSSv4"
	case f.Vector != "":
		method = "CVSSv2"
	}
	rating := map[string]any{"source": source, "severity": level, "method": method}
	if f.Vector != "" {
		rating["vector"] = f.Vector
	}
	if f.Score > 0 || level == "none" {
		rating["score"] = f.Score
	}
	description := []rune(f.Record.Summary)
	if len(description) > 500 {
		description = description[:500]
	}
	v := map[string]any{"id": f.ID, "source": source, "ratings": []any{rating}, "description": string(description), "affects": []any{map[string]any{"ref": f.Subject.Ref, "versions": []any{map[string]any{"version": f.Subject.Version, "status": "affected"}}}}, "properties": []any{map[string]any{"name": "bscan:fixed-in", "value": strings.Join(f.FixedIn, ",")}, map[string]any{"name": "bscan:matched-by", "value": f.MatchedBy}, map[string]any{"name": "bscan:confidence", "value": f.Confidence}}}
	for _, property := range []struct{ name, value string }{{"distro-severity", f.DistroSeverity}, {"distro-status", f.DistroStatus}} {
		if property.value != "" {
			v["properties"] = append(arr(v["properties"]), map[string]any{"name": "bscan:" + property.name, "value": property.value})
		}
	}
	if f.Assessment != nil {
		properties := arr(v["properties"])
		appendProperty := func(name, value string) {
			if value != "" {
				properties = append(properties, map[string]any{"name": "bscan:assessment:" + name, "value": value})
			}
		}
		appendProperty("method", "llm")
		appendProperty("status", f.Assessment.Status)
		appendProperty("reason", f.Assessment.Reason)
		appendProperty("model", f.Assessment.Model)
		appendProperty("input-sha256", f.Assessment.InputSHA256)
		appendProperty("cached", fmt.Sprint(f.Assessment.Cached))
		for _, list := range []struct {
			name   string
			values []string
		}{{"evidence", f.Assessment.Evidence}, {"preconditions", f.Assessment.Preconditions}, {"checks", f.Assessment.Checks}} {
			if len(list.values) > 0 {
				encoded, _ := json.Marshal(list.values)
				appendProperty(list.name, string(encoded))
			}
		}
		v["properties"] = properties
		// LLM advice is not verified VEX: keep affects.status=affected and
		// never emit a formal vulnerability analysis.state from this advice.
	}
	refs := []any{}
	for _, id := range f.RelatedIDs {
		if id != f.ID {
			refs = append(refs, map[string]any{"id": id, "source": source})
		}
	}
	if len(refs) > 0 {
		v["references"] = refs
	}
	if f.Record.Published != "" {
		v["published"] = f.Record.Published
	}
	if f.Record.Modified != "" {
		v["updated"] = f.Record.Modified
	}
	return v
}

func reportSeverityPolicy(r Report) string {
	if r.SeverityPolicy != "" {
		return httpx.Sanitize(r.SeverityPolicy)
	}
	return SeverityPolicy("")
}
