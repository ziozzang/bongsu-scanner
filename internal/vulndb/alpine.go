package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/version"
)

// alpineSecDB is the shape of https://secdb.alpinelinux.org/<rel>/<repo>.json.
type alpineSecDB struct {
	DistroVersion string `json:"distroversion"`
	RepoName      string `json:"reponame"`
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

var alpineReleasePattern = regexp.MustCompile(`^(v[0-9]+\.[0-9]+|edge)$`)

// alpineSource fetches main.json and community.json for each release.
type alpineSource struct{}

func (alpineSource) Name() string { return SourceAlpine }

func (alpineSource) Feeds(opts *Options) ([]Feed, error) {
	base := strings.TrimRight(opts.AlpineBaseURL, "/")
	if base == "" {
		base = DefaultAlpineBaseURL
	}
	rels := opts.AlpineReleases
	if len(rels) == 0 {
		rels = DefaultAlpineReleases
	}
	var feeds []Feed
	for _, rel := range rels {
		rel = strings.TrimSpace(rel)
		if rel == "" {
			continue
		}
		if !alpineReleasePattern.MatchString(rel) {
			return nil, fmt.Errorf("invalid Alpine release %q (want v3.20 or edge)", rel)
		}
		for _, repo := range []string{"main", "community"} {
			release, repository := rel, repo
			feeds = append(feeds, Feed{
				Source:     SourceAlpine,
				Key:        release + "-" + repository,
				URL:        base + "/" + release + "/" + repository + ".json",
				File:       release + "-" + repository + ".json",
				Ecosystems: []string{"Alpine:" + release},
				MaxBytes:   opts.MaxFeedBytes,
				Parse: func(ctx context.Context, p string, _ int64, emit Emit, progress func(string)) error {
					return parseAlpineSecDB(ctx, p, release, repository, emit)
				},
			})
		}
	}
	return feeds, nil
}

// ParseAlpineSecDB converts one secdb JSON file. Every CVE becomes a Record
// whose Affected entries carry ECOSYSTEM ranges [introduced 0, fixed VER]
// for ecosystem "Alpine:<release>". The secfixes key "0" means "not
// affected" and is skipped. Records are emitted sorted by ID.
func parseAlpineSecDB(ctx context.Context, p, release, repo string, emit Emit) error {
	b, err := os.ReadFile(p) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if err != nil {
		return err
	}
	var db alpineSecDB
	if err := json.Unmarshal(b, &db); err != nil {
		return fmt.Errorf("alpine secdb: %w", err)
	}
	if db.DistroVersion != "" {
		release = db.DistroVersion
	}
	if db.RepoName != "" {
		repo = db.RepoName
	}
	eco := "Alpine:" + release
	records := map[string]*Record{}
	for _, pkg := range db.Packages {
		name := strings.TrimSpace(pkg.Pkg.Name)
		if name == "" {
			continue
		}
		fixes := make([]string, 0, len(pkg.Pkg.Secfixes))
		for fixed := range pkg.Pkg.Secfixes {
			fixes = append(fixes, fixed)
		}
		sort.Slice(fixes, func(i, j int) bool {
			if c := version.CompareApk(fixes[i], fixes[j]); c != 0 {
				return c < 0
			}
			return fixes[i] < fixes[j]
		})
		for _, fixed := range fixes {
			ids := pkg.Pkg.Secfixes[fixed]
			fixed = strings.TrimSpace(fixed)
			if fixed == "" || fixed == "0" {
				continue
			}
			for _, raw := range ids {
				id := alpineIssueID(raw)
				if id == "" {
					continue
				}
				rec := records[id]
				if rec == nil {
					rec = &Record{ID: id, Source: SourceAlpine}
					records[id] = rec
				}
				a := Affected{
					Ecosystem: eco,
					Package:   name,
					PURL:      "pkg:apk/alpine/" + name + "?distro=" + strings.TrimPrefix(release, "v"),
					Ranges:    []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: fixed}}}},
					Database:  map[string]any{"repository": repo},
				}
				rec.Affected = append(rec.Affected, a)
			}
		}
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
		rec := records[id]
		sortAffected(rec.Affected)
		if err := emit(rec); err != nil {
			return err
		}
	}
	return nil
}

// alpineIssueID extracts the identifier from a secfixes entry such as
// "CVE-2021-27219 GHSL-2021-045" (first token) and validates its shape.
func alpineIssueID(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	id := fields[0]
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		id = "CVE-" + id[4:]
	}
	if !validID(id) {
		return ""
	}
	return id
}
