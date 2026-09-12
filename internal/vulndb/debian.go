package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/purl"
)

type debianSource struct{}

var debianReleaseVersions = map[string]string{"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14", "unstable": "sid"}

// NormalizeDebianRelease maps tracker codenames and aliases to OSV release
// suffixes. Debian's rolling development release is spelled "sid".
func NormalizeDebianRelease(release string) string {
	release = strings.TrimSpace(release)
	if mapped := debianReleaseVersions[release]; mapped != "" {
		return mapped
	}
	return release
}

func (debianSource) Name() string { return SourceDebian }

func (debianSource) Feeds(opts *Options) ([]Feed, error) {
	u := strings.TrimSpace(opts.DebianURL)
	if u == "" {
		u = DefaultDebianURL
	}
	max := opts.MaxFeedBytes
	if max <= 0 {
		max = DefaultMaxFeedBytes
	}
	return []Feed{{Source: SourceDebian, Key: "debian", URL: u, File: "debian.json",
		Ecosystems: []string{"Debian"}, MaxBytes: max,
		Parse: func(ctx context.Context, path string, _ int64, emit Emit, _ func(string)) error {
			return parseDebianTracker(ctx, path, emit)
		},
	}}, nil
}

type debianIssue struct {
	Description string                   `json:"description"`
	Scope       string                   `json:"scope"`
	Releases    map[string]debianRelease `json:"releases"`
}

type debianRelease struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
	NoDSA        string `json:"nodsa"`
	NoDSAReason  string `json:"nodsa_reason"`
}

// parseDebianTracker reads the tracker JSON one source package at a time.
// Known tracker codenames map to Debian release versions (e.g. Debian:12);
// the original codename is retained in database metadata.
// A resolved fixed_version of "0" means not affected. Undetermined entries
// and resolved entries lacking a concrete fixed version do not establish
// an affected range and are omitted, rather than asserting all versions
// vulnerable. See the official export implementation in lib/python/security_db.py:
// https://salsa.debian.org/security-tracker-team/security-tracker
func parseDebianTracker(ctx context.Context, path string, emit Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("debian tracker: %w", err)
	}
	if tok != json.Delim('{') {
		return fmt.Errorf("debian tracker: expected package object")
	}
	records := map[string]*Record{}
	for dec.More() {
		if err := ctx.Err(); err != nil {
			return err
		}
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("debian tracker package: %w", err)
		}
		name, ok := tok.(string)
		if !ok {
			return fmt.Errorf("debian tracker: expected package name")
		}
		var issues map[string]debianIssue
		if err := dec.Decode(&issues); err != nil {
			return fmt.Errorf("debian tracker %q: %w", name, terminalSafeError{err})
		}
		if strings.TrimSpace(name) == "" {
			continue
		}
		for id, issue := range issues {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !validID(id) {
				continue
			}
			for release, state := range issue.Releases {
				if strings.TrimSpace(release) == "" {
					continue
				}
				fixed := strings.TrimSpace(state.FixedVersion)
				events := []Event{{Introduced: "0"}}
				switch state.Status {
				case "resolved":
					if fixed == "" || fixed == "0" || fixed == "undetermined" || strings.HasPrefix(fixed, "<") {
						continue
					}
					events = append(events, Event{Fixed: fixed})
				case "open":
					if fixed != "" { // Contradictory input cannot establish a range.
						continue
					}
				default:
					continue
				}
				r := records[id]
				if r == nil {
					r = &Record{ID: id, Source: SourceDebian,
						References: []Reference{{Type: "ADVISORY", URL: "https://security-tracker.debian.org/tracker/" + id}}}
					records[id] = r
				}
				// Select deterministically when one CVE spans multiple packages.
				mergeDetails(r, &Record{Details: truncateDetails(issue.Description), DetailsTruncated: len(issue.Description) > MaxDetails})
				metadata := map[string]any{"status": state.Status}
				for key, value := range map[string]string{"urgency": state.Urgency, "scope": issue.Scope, "nodsa": state.NoDSA, "nodsa_reason": state.NoDSAReason} {
					if value != "" {
						metadata[key] = value
					}
				}
				version := NormalizeDebianRelease(release)
				metadata["release"] = release
				r.Affected = append(r.Affected, Affected{Ecosystem: "Debian:" + version, Package: name,
					PURL:   (purl.PURL{Type: "deb", Namespace: "debian", Name: name, Qualifiers: map[string]string{"distro": release}}).String(),
					Ranges: []Range{{Type: "ECOSYSTEM", Events: events}}, Database: metadata})
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("debian tracker: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("debian tracker: trailing JSON data")
		}
		return fmt.Errorf("debian tracker: %w", err)
	}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := records[id]
		sortAffected(r.Affected)
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}
