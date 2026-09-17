package vulndb

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

const SourceRedHatVEX = "redhat-vex"
const redHatVEXBaseURL = "https://security.access.redhat.com/data/csaf/v2/vex/"
const vexMaxAffected = 100_000

var vexArchiveName = regexp.MustCompile(`^csaf_vex_[0-9]{4}-[0-9]{2}-[0-9]{2}\.tar\.zst$`)
var vexCVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
var vexCPE = regexp.MustCompile(`^cpe:/[oa]:redhat:(enterprise_linux|rhel_eus|rhel_aus|rhel_e4s|rhel_tus|rhel_els):[0-9]+(?:\.[0-9]+)*(?:::[a-z0-9_]+)?$`)
var vexNEVRA = regexp.MustCompile(`^(.+)-([0-9]+:[^-:]+-[^:]+)\.([a-zA-Z0-9_]+)$`)

// The Source interface has no context. Only the tiny index is fetched here,
// with an independent deadline; the archive uses the update engine's context,
// conditional requests, hashing and download bound. baseURL is a test seam.
type redHatVEXSource struct{ baseURL string }

func (redHatVEXSource) Name() string { return SourceRedHatVEX }
func (s redHatVEXSource) Feeds(opts *Options) ([]Feed, error) {
	if opts.Offline {
		return nil, errors.New("redhat-vex: index unavailable offline")
	}
	base := s.baseURL
	if base == "" {
		base = redHatVEXBaseURL
	}
	base = strings.TrimRight(base, "/") + "/"
	client := opts.Client
	if client == nil {
		client = httpx.New(30 * time.Second)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var index bytes.Buffer
	if _, _, _, err := client.Download(ctx, base+"archive_latest.txt", nil, &index, 4096); err != nil {
		return nil, fmt.Errorf("redhat-vex index: %w", err)
	}
	name := strings.TrimSpace(index.String())
	if !vexArchiveName.MatchString(name) {
		return nil, errors.New("redhat-vex: invalid archive name in index")
	}
	maxBytes := opts.MaxFeedBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFeedBytes
	}
	expanded := opts.maxFeedUncompressedBytes()
	return []Feed{{Source: SourceRedHatVEX, Key: "vex", URL: base + name, File: "vex.tar.zst", Ecosystems: []string{"Red Hat"}, MaxBytes: maxBytes,
		Parse: func(ctx context.Context, path string, _ int64, emit Emit, progress func(string)) error {
			return parseRedHatVEX(ctx, path, expanded, osvEntryMaxBytes, emit, progress)
		}}}, nil
}

// selectedOSVSource changes only feed assembly, never the persisted selection.
type selectedOSVSource struct{ osvSource }

func (s selectedOSVSource) Feeds(opts *Options) ([]Feed, error) {
	feeds, err := s.osvSource.Feeds(opts)
	if err != nil {
		return nil, err
	}
	for _, source := range opts.Sources {
		if CanonicalSource(source) != SourceRedHatVEX {
			continue
		}
		out := feeds[:0]
		for _, feed := range feeds {
			if len(feed.Ecosystems) == 1 && feed.Ecosystems[0] == "Red Hat" {
				if opts.Progress != nil {
					opts.Progress("skipping OSV Red Hat feed: redhat-vex supplies authoritative per-CVE data")
				}
				continue
			}
			out = append(out, feed)
		}
		return out, nil
	}
	return feeds, nil
}

type vexProduct struct {
	ID     string `json:"product_id"`
	Name   string `json:"name"`
	Helper struct {
		CPE string `json:"cpe"`
	} `json:"product_identification_helper"`
}
type vexBranch struct {
	Product  vexProduct  `json:"product"`
	Branches []vexBranch `json:"branches"`
}
type vexRelationship struct {
	Category  string     `json:"category"`
	Product   vexProduct `json:"full_product_name"`
	Component string     `json:"product_reference"`
	Parent    string     `json:"relates_to_product_reference"`
}
type vexStatement struct {
	Category string   `json:"category"`
	Details  string   `json:"details"`
	URL      string   `json:"url"`
	Products []string `json:"product_ids"`
}
type vexScore struct {
	CVSS struct {
		Vector string `json:"vectorString"`
	} `json:"cvss_v3"`
	Products []string `json:"products"`
}
type vexVulnerability struct {
	CVE    string `json:"cve"`
	Status struct {
		Fixed         []string `json:"fixed"`
		Affected      []string `json:"known_affected"`
		NotAffected   []string `json:"known_not_affected"`
		Investigating []string `json:"under_investigation"`
	} `json:"product_status"`
	Remediations []vexStatement `json:"remediations"`
	Threats      []vexStatement `json:"threats"`
	Scores       []vexScore     `json:"scores"`
	References   []Reference    `json:"references"`
}
type vexDocument struct {
	Document struct {
		Title    string `json:"title"`
		Severity struct {
			Text string `json:"text"`
		} `json:"aggregate_severity"`
		Tracking struct {
			ID        string `json:"id"`
			Published string `json:"initial_release_date"`
			Modified  string `json:"current_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	Tree struct {
		Branches      []vexBranch       `json:"branches"`
		Relationships []vexRelationship `json:"relationships"`
	} `json:"product_tree"`
	Vulnerabilities []vexVulnerability `json:"vulnerabilities"`
}

func parseRedHatVEX(ctx context.Context, path string, maxExpanded uint64, maxDocument int64, emit Emit, progress func(string)) error {
	f, err := os.Open(path) // #nosec G304 -- The update engine supplies its bounded downloaded feed path; archive paths are never extracted.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	z, err := zstd.NewReader(contextReader{ctx: ctx, r: f}, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(128<<20))
	if err != nil {
		return err
	}
	defer z.Close()
	// Count headers, skipped members and trailers too. Restrict the uint64 bound
	// before converting it so even a programmatic caller cannot overflow int64.
	limit := int64(min(maxExpanded, uint64(1<<63-2)))
	expanded := &archiveExpansionReader{limited: io.LimitedReader{R: contextReader{ctx: ctx, r: z}, N: limit + 1}, max: limit}
	tr := tar.NewReader(expanded)
	records, affected, malformed, oversized, filtered := 0, 0, 0, 0, 0
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("redhat-vex tar: %w", err)
		}
		if entries >= osvMaxEntries {
			return errors.New("redhat-vex: too many archive entries")
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(strings.ToLower(h.Name), ".json") {
			continue
		}
		if h.Size > maxDocument {
			oversized++
			continue
		}
		data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, r: tr}, maxDocument+1))
		if err != nil {
			return err
		}
		var doc vexDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			malformed++
			continue
		}
		rec, err := convertRedHatVEX(ctx, &doc)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			malformed++
			continue
		}
		if rec == nil {
			filtered++
			continue
		}
		if err := emit(rec); err != nil {
			return err
		}
		records++
		affected += len(rec.Affected)
		if progress != nil && records%5000 == 0 {
			progress(fmt.Sprintf("redhat-vex: %d records parsed", records))
		}
	}
	// Consume through zstd EOF to verify the final frame/checksum and bound
	// trailing data that tar.Reader deliberately stops before.
	if _, err := io.Copy(io.Discard, expanded); err != nil {
		return err
	}
	if progress != nil {
		progress(fmt.Sprintf("redhat-vex: records=%d affected=%d skipped_malformed=%d skipped_oversized=%d skipped_non_rhel=%d", records, affected, malformed, oversized, filtered))
	}
	return nil
}

type vexScope struct{ ecosystem, module string }

func vexModule(id string) string {
	// Module product IDs are <product>:<name>:<stream>:<build>:<context>.
	parts := strings.Split(id, ":")
	if len(parts) >= 5 && parts[1] != "" && parts[2] != "" {
		return parts[1] + ":" + parts[2]
	}
	return ""
}
func vexStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "affected":
		return "affected"
	case "will not fix":
		return "will-not-fix"
	case "fix deferred":
		return "fix-deferred"
	case "out of support scope":
		return "out-of-support-scope"
	case "under investigation":
		return "under-investigation"
	}
	return ""
}
func vexPackage(component string) (name, fixed string) {
	if len(component) > 1024 {
		return "", ""
	}
	component, _, _ = strings.Cut(component, "::")
	if m := vexNEVRA.FindStringSubmatch(component); m != nil {
		return m[1], m[2]
	}
	// Source package IDs have no EVR; .src is also used in package states.
	name = strings.TrimSuffix(component, ".src")
	if name == "" || strings.ContainsAny(name, ":/ @\t\r\n") {
		return "", ""
	}
	return name, ""
}

func convertRedHatVEX(ctx context.Context, doc *vexDocument) (*Record, error) {
	return convertRedHatVEXBounded(ctx, doc, vexMaxAffected, osvEntryMaxBytes-(1<<20))
}

// Leave room for bounded record metadata and ingestion provenance below the
// catalog writer's 64 MiB per-record ceiling. Never truncate affected scopes.
func convertRedHatVEXBounded(ctx context.Context, doc *vexDocument, maxAffected, maxAffectedBytes int) (*Record, error) {
	if len(doc.Vulnerabilities) != 1 {
		return nil, errors.New("redhat-vex: expected one CVE")
	}
	v := &doc.Vulnerabilities[0]
	if !vexCVE.MatchString(v.CVE) || !validID(v.CVE) || doc.Document.Tracking.ID != v.CVE {
		return nil, errors.New("redhat-vex: invalid CVE identity")
	}
	scopes := map[string]vexScope{}
	var walk func([]vexBranch, int) error
	walk = func(branches []vexBranch, depth int) error {
		if depth > 64 {
			return errors.New("redhat-vex: product tree too deep")
		}
		for _, b := range branches {
			if err := ctx.Err(); err != nil {
				return err
			}
			p := b.Product
			if len(p.ID) <= 1024 && len(p.Helper.CPE) <= 1024 && vexCPE.MatchString(p.Helper.CPE) {
				scopes[p.ID] = vexScope{ecosystem: "Red Hat:" + strings.SplitN(p.Helper.CPE, ":", 4)[3], module: vexModule(p.ID)}
			}
			if err := walk(b.Branches, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(doc.Tree.Branches, 0); err != nil {
		return nil, err
	}
	relations := map[string]vexRelationship{}
	for _, rel := range doc.Tree.Relationships {
		if rel.Category != "default_component_of" {
			continue
		}
		if scope, ok := scopes[rel.Parent]; ok && len(rel.Product.ID) <= 2048 && len(rel.Component) <= 1024 {
			relations[rel.Product.ID] = rel
			if _, module, ok := strings.Cut(rel.Component, "::"); ok {
				parts := strings.Split(module, ":")
				if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
					scope.module = parts[0] + ":" + parts[1]
				}
			}
			scopes[rel.Product.ID] = scope
		}
	}
	r := &Record{ID: v.CVE, Summary: truncateText(doc.Document.Title, osvMaxSummary), Published: truncateText(doc.Document.Tracking.Published, 128), Modified: truncateText(doc.Document.Tracking.Modified, 128), Source: SourceRedHatVEX, Database: map[string]any{"severity": truncateText(doc.Document.Severity.Text, 64)}, References: boundedOSVReferences(v.References)}
	var fallback []Severity
	for _, score := range v.Scores {
		vector := score.CVSS.Vector
		if len(vector) > 1024 || !strings.HasPrefix(vector, "CVSS:3.") {
			continue
		}
		sev := Severity{Type: "CVSS_V3", Score: vector}
		if len(fallback) == 0 {
			fallback = []Severity{sev}
		}
		for _, id := range score.Products {
			if _, ok := scopes[id]; ok {
				r.Severity = []Severity{sev}
				break
			}
		}
		if len(r.Severity) > 0 {
			break
		}
	}
	if len(r.Severity) == 0 {
		r.Severity = fallback
	}
	statuses, advisories, ratings := map[string]string{}, map[string]string{}, map[string]string{}
	for _, rem := range v.Remediations {
		status := vexStatus(rem.Details)
		for _, id := range rem.Products {
			if _, ok := relations[id]; !ok {
				continue
			}
			if rem.Category == "vendor_fix" && len(rem.URL) <= 2048 {
				if _, tail, ok := strings.Cut(rem.URL, "/errata/"); ok && strings.HasPrefix(tail, "RHSA-") {
					advisories[id] = tail
				}
			} else if (rem.Category == "no_fix_planned" || rem.Category == "none_available" || rem.Category == "workaround") && status != "" {
				statuses[id] = status
			}
		}
	}
	for _, threat := range v.Threats {
		if threat.Category != "impact" || len(threat.Details) > 64 {
			continue
		}
		for _, id := range threat.Products {
			if _, ok := relations[id]; ok {
				ratings[id] = threat.Details
			}
		}
	}
	// A source NEVRA sharing scope and EVR identifies the corresponding binary's
	// source. Do not guess from binary prefixes or ambiguous source builds.
	sources := map[string]string{}
	for id, rel := range relations {
		component, _, _ := strings.Cut(rel.Component, "::")
		if !strings.HasSuffix(component, ".src") {
			continue
		}
		name, evr := vexPackage(rel.Component)
		if evr == "" {
			continue
		}
		scope := scopes[id]
		key := scope.ecosystem + "\x00" + scope.module + "\x00" + evr
		if old, ok := sources[key]; ok && old != name {
			sources[key] = ""
		} else if !ok {
			sources[key] = name
		}
	}
	seen := map[string]bool{}
	affectedBytes := 0
	add := func(id, status string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, ok := relations[id]
		if !ok {
			return nil
		}
		scope := scopes[id]
		name, evr := vexPackage(rel.Component)
		if name == "" || status == "fixed" && evr == "" {
			return nil
		}
		a := Affected{Ecosystem: scope.ecosystem, Package: name, Database: map[string]any{}}
		if scope.module != "" {
			a.Database["modularity"] = scope.module
		}
		if rating := ratings[id]; rating != "" && rating != doc.Document.Severity.Text {
			a.Database["severity"] = rating
		}
		if status == "fixed" {
			a.Ranges = []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: evr}}}}
			if advisory := advisories[id]; advisory != "" {
				a.Database["advisory"] = advisory
			}
			if source := sources[scope.ecosystem+"\x00"+scope.module+"\x00"+evr]; source != "" {
				a.Database["source_package"] = source
			}
		} else {
			if status == "affected" && statuses[id] != "" {
				status = statuses[id]
			}
			a.Database["redhat_status"] = status
			if status != "not-affected" {
				a.Ranges = []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}}}}
			}
		}
		key, _ := json.Marshal(a)
		if seen[string(key)] {
			return nil
		}
		seen[string(key)] = true
		if len(r.Affected) >= maxAffected || len(key)+1 > maxAffectedBytes-affectedBytes {
			return errors.New("redhat-vex: affected entries exceed record limit")
		}
		affectedBytes += len(key) + 1
		r.Affected = append(r.Affected, a)
		return nil
	}
	explicit := map[string]bool{}
	for _, group := range []struct {
		ids    []string
		status string
	}{{v.Status.Fixed, "fixed"}, {v.Status.Affected, "affected"}, {v.Status.Investigating, "under-investigation"}, {v.Status.NotAffected, "not-affected"}} {
		for _, id := range group.ids {
			explicit[id] = true
			if err := add(id, group.status); err != nil {
				return nil, err
			}
		}
	}
	var unstated []string
	for id := range statuses {
		if !explicit[id] {
			unstated = append(unstated, id)
		}
	}
	sort.Strings(unstated)
	for _, id := range unstated {
		if err := add(id, statuses[id]); err != nil {
			return nil, err
		}
	}
	if len(r.Affected) == 0 {
		return nil, nil
	}
	sortAffected(r.Affected)
	return r, nil
}
