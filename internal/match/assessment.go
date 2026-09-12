package match

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/ziozzang/bongsu-scanner/internal/assessment"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

// Enrich attaches optional LLM applicability advice. It never changes the
// deterministic version finding, severity, counts or exit-threshold behavior.
// maxFindings caps distinct inputs, including failed attempts; zero permits no
// calls. Identical inputs share an analysis even after the cap is reached.
func Enrich(ctx context.Context, report *Report, doc Document, analyzer assessment.Analyzer, env assessment.Environment, maxFindings int) error {
	if report == nil {
		return errors.New("cannot enrich a nil report")
	}
	environment := assessmentEnvironment(doc, env)
	outcomes := map[string]assessment.Result{}
	attempts := 0
	var errs []error
	var cancellation error
	for i := range report.Findings {
		finding := &report.Findings[i]
		packageName, matchedVersion := assessmentMatchIdentity(finding)
		text := finding.Record.assessmentText
		if text == nil {
			text = &advisoryText{summary: finding.Record.Summary, details: finding.Record.Details,
				truncated: vulndb.DetailsMayBeTruncated(vulndb.Record{Details: finding.Record.Details, DetailsTruncated: finding.Record.DetailsTruncated})}
			for _, ref := range finding.Record.References {
				text.references = append(text.references, vulndb.Reference{URL: ref})
			}
		}
		input := assessment.Input{
			AdvisoryID: finding.ID, Summary: text.summary, Description: text.details,
			DescriptionTruncated: text.truncated,
			Package:              packageName, Version: matchedVersion, Ecosystem: finding.Subject.Ecosystem,
			Environment: cloneEnvironment(environment), References: assessmentReferences(text.references),
		}
		summary, summaryTruncated := boundedAssessmentText(input.Summary, assessment.MaxSummaryBytes)
		description, descriptionTruncated := boundedAssessmentText(input.Description, assessment.MaxDescriptionBytes)
		input.Summary, input.Description = summary, description
		input.DescriptionTruncated = input.DescriptionTruncated || summaryTruncated || descriptionTruncated
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode assessment input: %w", err)
		}
		sum := sha256.Sum256(encoded)
		key := hex.EncodeToString(sum[:])
		if outcome, ok := outcomes[key]; ok {
			finding.Assessment = cloneAssessment(outcome)
			continue
		}
		if err := ctx.Err(); err != nil {
			outcome := assessment.Result{Status: "needs_review", Reason: "Assessment canceled: " + httpx.Sanitize(err.Error())}
			finding.Assessment = cloneAssessment(outcome)
			if cancellation == nil {
				cancellation = err
				errs = append(errs, err)
			}
			continue
		}
		if attempts >= maxFindings {
			finding.Assessment = &assessment.Result{Status: "not_assessed", Reason: "Distinct assessment limit reached"}
			continue
		}
		attempts++
		var outcome assessment.Result
		if analyzer == nil {
			err = errors.New("assessment analyzer is unavailable")
		} else {
			outcome, err = analyzer.Analyze(ctx, input)
		}
		if err != nil {
			outcome = assessment.Result{Status: "needs_review", Reason: "Assessment failed: " + httpx.Sanitize(err.Error())}
			errs = append(errs, fmt.Errorf("assess %s: %w", httpx.Sanitize(finding.ID), err))
		}
		outcomes[key] = outcome
		finding.Assessment = cloneAssessment(outcome)
	}
	return errors.Join(errs...)
}

// assessmentMatchIdentity describes the package/version that produced the
// deterministic match. Subject retains the scanned binary identity, while an
// upstream match must be explained to the analyzer using its source package
// and version. Binary findings use the source version when it is available
// because that is the version compared against the advisory.
func assessmentMatchIdentity(f *Finding) (string, string) {
	if f == nil {
		return "", ""
	}
	name, ver := f.Subject.Name, f.Subject.Version
	if f.MatchedBy == "upstream" {
		if f.Subject.Upstream != "" {
			name = f.Subject.Upstream
		}
		if f.Subject.UpstreamVersion != "" {
			ver = f.Subject.UpstreamVersion
		}
	} else if f.MatchedBy == "binary-name" && f.Subject.UpstreamVersion != "" {
		ver = f.Subject.UpstreamVersion
	}
	return name, ver
}

func cloneAssessment(r assessment.Result) *assessment.Result {
	r.Evidence = append([]string(nil), r.Evidence...)
	r.Preconditions = append([]string(nil), r.Preconditions...)
	r.Checks = append([]string(nil), r.Checks...)
	return &r
}
func cloneEnvironment(e assessment.Environment) assessment.Environment {
	facts := map[string]string{}
	for k, v := range e.Facts {
		facts[k] = v
	}
	e.Facts = facts
	return e
}

// assessmentEnvironment uses only scanned target metadata and declared user
// facts. The OS of the machine running bscan is deliberately never consulted.
func assessmentEnvironment(doc Document, override assessment.Environment) assessment.Environment {
	out := assessment.Environment{Facts: map[string]string{}}
	if doc.Context.MixedOS {
		// Conflicting target OS components cannot safely support a
		// platform-specific applicability conclusion.
		out.OS = "unknown"
	} else if doc.Context.OS != nil {
		out.OS = doc.Context.OS.ID
		out.OSVersion = doc.Context.OS.VersionID
	}
	switch doc.Format {
	case "cyclonedx":
		root := obj(obj(doc.Raw["metadata"])["component"])
		p := props(root["properties"])
		if !doc.Context.MixedOS && out.OS == "" {
			out.OS = p["bscan:host:operating-system"]
		}
		if !doc.Context.MixedOS && out.OSVersion == "" {
			out.OSVersion = p["bscan:host:os-version"]
		}
		if !doc.Context.MixedOS {
			out.Arch = p["bscan:host:architecture"]
		}
		if !doc.Context.MixedOS {
			if imageOS := p["bscan:image:os"]; imageOS != "" {
				if out.OS != "" && out.OS != imageOS {
					out.Facts["distribution"] = out.OS
				}
				out.OS = imageOS
			}
			if arch := p["bscan:image:architecture"]; arch != "" {
				out.Arch = arch
			}
		}
	case "spdx":
		if !doc.Context.MixedOS {
			for _, entry := range arr(doc.Raw["packages"]) {
				root := obj(entry)
				if ref := str(root, "SPDXID"); ref != "SPDXRef-Root" && ref != doc.Context.Root {
					continue
				}
				host := metadataEnvironment(str(root, "packageComment"), "bscan host metadata: ")
				if out.OS == "" {
					out.OS = host.OS
				}
				if out.OSVersion == "" {
					out.OSVersion = host.OSVersion
				}
				out.Arch = host.Arch
				for _, annotation := range arr(root["annotations"]) {
					image := metadataEnvironment(str(obj(annotation), "comment"), "bscan image metadata: ")
					if image.OS != "" {
						if out.OS != "" && out.OS != image.OS {
							out.Facts["distribution"] = out.OS
						}
						out.OS = image.OS
					}
					if image.Arch != "" {
						out.Arch = image.Arch
					}
				}
			}
		}
	}
	out.OS, out.Facts = normalizedAssessmentOS(out.OS, out.Facts)
	if override.OS != "" {
		declaredOS, declaredFacts := normalizedAssessmentOS(override.OS, map[string]string{})
		distributionChanged := declaredFacts["distribution"] != "" && declaredFacts["distribution"] != out.Facts["distribution"]
		if !strings.EqualFold(declaredOS, out.OS) || distributionChanged {
			out.OSVersion = ""
			delete(out.Facts, "distribution")
		}
		out.OS = declaredOS
		if distribution := declaredFacts["distribution"]; distribution != "" {
			out.Facts["distribution"] = distribution
		}
	}
	if override.OSVersion != "" {
		out.OSVersion = override.OSVersion
	}
	if override.Arch != "" {
		out.Arch = override.Arch
	}
	// Facts originate only from explicit user declarations, never from the
	// arbitrary properties, paths, host identity or addresses in an SBOM.
	for k, v := range override.Facts {
		if assessmentFactAllowed(k) {
			out.Facts[k] = v
		}
	}
	return out
}
func metadataEnvironment(text, prefix string) assessment.Environment {
	if !strings.HasPrefix(text, prefix) {
		return assessment.Environment{}
	}
	var m struct {
		OS              string `json:"os"`
		OperatingSystem string `json:"operating_system"`
		OSVersion       string `json:"os_version"`
		Architecture    string `json:"architecture"`
	}
	if json.Unmarshal([]byte(strings.TrimPrefix(text, prefix)), &m) != nil {
		return assessment.Environment{}
	}
	if m.OS == "" {
		m.OS = m.OperatingSystem
	}
	return assessment.Environment{OS: m.OS, OSVersion: m.OSVersion, Arch: m.Architecture}
}
func assessmentFactAllowed(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.NewReplacer("-", "_", ".", "_", ":", "_").Replace(key)
	if key == "" {
		return false
	}
	for _, part := range strings.Split(key, "_") {
		switch part {
		case "hostname", "host", "ip", "ips", "address", "addresses", "path", "paths", "file", "files", "source", "sources", "token", "password", "secret":
			return false
		}
	}
	return true
}
func assessmentReferences(refs []vulndb.Reference) []string {
	var out []string
	for _, ref := range refs {
		if len(ref.URL) > assessment.MaxReferenceBytes || !utf8.ValidString(ref.URL) {
			continue
		}
		u, err := url.Parse(ref.URL)
		if err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil {
			// Query strings and fragments can contain bearer tokens or other
			// deployment-specific data. They are not needed for applicability
			// reasoning and must not be sent to the model.
			u.RawQuery = ""
			u.ForceQuery = false
			u.Fragment = ""
			u.RawFragment = ""
			out = append(out, u.String())
		}
	}
	out = unique(out)
	if len(out) > assessment.MaxReferences {
		out = out[:assessment.MaxReferences]
	}
	return out
}

func boundedAssessmentText(text string, limit int) (string, bool) {
	truncated := !utf8.ValidString(text)
	text = strings.ToValidUTF8(text, "�")
	if len(text) <= limit {
		return text, truncated
	}
	text = text[:limit]
	for !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text, true
}
func normalizedAssessmentOS(os string, facts map[string]string) (string, map[string]string) {
	normalized := strings.ToLower(strings.TrimSpace(os))
	switch normalized {
	case "debian", "ubuntu", "alpine", "wolfi", "chainguard", "fedora", "rhel", "redhat", "centos", "rocky", "rockylinux", "almalinux", "arch", "archlinux", "opensuse", "sles", "suse", "amzn", "amazonlinux", "ol", "oraclelinux", "gentoo", "nixos", "linuxmint", "photon":
		facts["distribution"] = normalized
		return "linux", facts
	case "linux", "windows", "freebsd", "openbsd", "netbsd":
		return normalized, facts
	case "darwin", "macos", "mac os x":
		return "macos", facts
	default:
		return os, facts
	}
}
