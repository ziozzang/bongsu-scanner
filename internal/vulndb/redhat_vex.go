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
type redHatVEXSource struct {
	baseURL string
	ctx     context.Context
}

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
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
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
	feeds := []Feed{{Source: SourceRedHatVEX, Key: "vex", URL: base + name, File: "vex.tar.zst", Ecosystems: []string{"Red Hat"}, MaxBytes: maxBytes,
		Parse: func(ctx context.Context, path string, _ int64, emit Emit, progress func(string)) error {
			return parseRedHatVEX(ctx, path, expanded, vexMaxDocument, emit, progress)
		}}}
	archiveDate, err := time.Parse(time.DateOnly, strings.TrimSuffix(strings.TrimPrefix(name, "csaf_vex_"), ".tar.zst"))
	if err != nil {
		return nil, errors.New("redhat-vex: invalid archive date")
	}
	delta := &vexDeltaFeed{baseURL: base, archiveDate: archiveDate, client: client, budget: 2 << 30, maxDocuments: 20_000, maxDocument: vexMaxDocument, retryDelay: 250 * time.Millisecond}
	feeds = append(feeds, Feed{Source: SourceRedHatVEX, Key: "vex-changes", URL: base + "changes.csv", File: "changes.csv", Ecosystems: []string{"Red Hat"}, MaxBytes: vexListMaxBytes, Parse: delta.parse, vexDelta: delta})
	return feeds, nil
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
	_, err := parseRedHatVEXExpanded(ctx, path, maxExpanded, maxDocument, emit, progress)
	return err
}

func parseRedHatVEXExpanded(ctx context.Context, path string, maxExpanded uint64, maxDocument int64, emit Emit, progress func(string)) (uint64, error) {
	maxDocument = min(maxDocument, vexMaxDocument)
	f, err := os.Open(path) // #nosec G304 -- The update engine supplies its bounded downloaded feed path; archive paths are never extracted.
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	z, err := zstd.NewReader(contextReader{ctx: ctx, r: f}, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(128<<20))
	if err != nil {
		return 0, err
	}
	defer z.Close()
	// Count headers, skipped members and trailers too. Restrict the uint64 bound
	// before converting it so even a programmatic caller cannot overflow int64.
	limit := int64(min(maxExpanded, uint64(1<<63-2)))
	expanded := &archiveExpansionReader{limited: io.LimitedReader{R: contextReader{ctx: ctx, r: z}, N: limit + 1}, max: limit}
	tr := tar.NewReader(expanded)
	// Reuse one bounded disk spool; never retain a full JSON document in RAM.
	document, err := os.CreateTemp("", "bongsu-vex-*.json")
	if err != nil {
		return 0, err
	}
	defer func() { _ = document.Close(); _ = os.Remove(document.Name()) }()
	records, affected, malformed, oversized, filtered := 0, 0, 0, 0, 0
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("redhat-vex tar (--max-feed-uncompressed): %w", err)
		}
		if entries >= osvMaxEntries {
			return 0, errors.New("redhat-vex: too many archive entries")
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(strings.ToLower(h.Name), ".json") {
			continue
		}
		if h.Size > maxDocument {
			oversized++
			continue
		}
		if err := document.Truncate(0); err != nil {
			return 0, err
		}
		if _, err := document.Seek(0, io.SeekStart); err != nil {
			return 0, err
		}
		if _, err := io.Copy(document, contextReader{ctx: ctx, r: tr}); err != nil {
			return 0, fmt.Errorf("redhat-vex (--max-feed-uncompressed): %w", err)
		}
		doc, err := decodeRedHatVEX(ctx, document)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			malformed++
			continue
		}
		rec, err := convertRedHatVEX(ctx, doc)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			malformed++
			continue
		}
		if rec == nil {
			filtered++
			continue
		}
		if err := emit(rec); err != nil {
			return 0, err
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
		return 0, fmt.Errorf("redhat-vex (--max-feed-uncompressed): %w", err)
	}
	if progress != nil {
		progress(fmt.Sprintf("redhat-vex: records=%d affected=%d skipped_malformed=%d skipped_oversized=%d skipped_non_rhel=%d", records, affected, malformed, oversized, filtered))
	}
	// Include entry sizes, skipped members, headers, padding and trailers so a
	// cached feed is held to exactly the same expansion budget as a fresh one.
	return uint64(limit + 1 - expanded.limited.N), nil // #nosec G115 -- LimitedReader starts at limit+1, only decrements on reads, and successful EOF implies the count is in [0, limit].
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
			if err := ctx.Err(); err != nil {
				return nil, err
			}
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
	priorities := map[string]int{}
	// Remediation precedence is vendor_fix > workaround-only > no_fix_planned
	// > none_available. Equal-priority details/advisories use lexical order so
	// reversing the input cannot change a record. A vendor fix clears terminal
	// no-fix details; only product_status.fixed can assert a fixed EVR.
	for _, rem := range v.Remediations {
		status := vexStatus(rem.Details)
		priority := 0
		switch rem.Category {
		case "vendor_fix":
			priority, status = 4, ""
		case "workaround":
			priority, status = 3, "workaround-only"
		case "no_fix_planned":
			priority = 2
		case "none_available":
			priority = 1
		}
		for _, id := range rem.Products {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if _, ok := relations[id]; !ok {
				continue
			}
			if priority > priorities[id] || priority == priorities[id] && status < statuses[id] {
				priorities[id], statuses[id] = priority, status
			}
			if rem.Category == "vendor_fix" && len(rem.URL) <= 2048 {
				if _, tail, ok := strings.Cut(rem.URL, "/errata/"); ok && strings.HasPrefix(tail, "RHSA-") && (advisories[id] == "" || tail < advisories[id]) {
					advisories[id] = tail
				}
			}
		}
	}
	for _, threat := range v.Threats {
		if threat.Category != "impact" || len(threat.Details) > 64 {
			continue
		}
		for _, id := range threat.Products {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
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
			if status == "not-affected" && evr != "" {
				a.Versions = []string{evr}
			} else if status != "not-affected" {
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
	// Product status precedence: fixed > known_not_affected > known_affected
	// > under_investigation. Emit a product once and count contradictory claims.
	explicit := map[string]string{}
	conflicts := map[string]bool{}
	for _, group := range []struct {
		ids    []string
		status string
	}{{v.Status.Fixed, "fixed"}, {v.Status.NotAffected, "not-affected"}, {v.Status.Affected, "affected"}, {v.Status.Investigating, "under-investigation"}} {
		for _, id := range group.ids {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if _, ok := relations[id]; !ok {
				continue
			}
			if old, exists := explicit[id]; exists {
				if old != group.status {
					conflicts[id] = true
				}
				continue
			}
			explicit[id] = group.status
			if err := add(id, group.status); err != nil {
				return nil, err
			}
		}
	}
	if len(conflicts) > 0 {
		r.Database["redhat_status_conflicts"] = len(conflicts)
	}
	var unstated []string
	for id := range statuses {
		if explicit[id] == "" && statuses[id] != "" {
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

// These are decoding limits, checked before retaining the next element.
// Documents are spooled to disk and decoded token by token, so memory follows
// the retained RHEL entries rather than the document size; the ceiling bounds
// parse time only. Red Hat's broadest CVEs are large: on 2026-09-17
// CVE-2023-39325 (HTTP/2 rapid reset) measured 75,392,762 bytes and
// CVE-2026-33186 106,439,389 bytes with 43,266 branches and 43,137
// relationships, and both must be ingested. Larger documents are counted in
// skipped_oversized rather than failing the update.
const (
	vexMaxDocument      = 256 << 20
	vexMaxBranches      = 100_000
	vexMaxRelationships = 100_000
	vexMaxProductIDs    = 200_000
	vexMaxStatements    = 100_000
)

// vexTokens visits one token at a time, including ignored fields. It never
// decodes an array into a temporary slice. Branch paths are normalized while
// their actual depth and total count remain bounded, including empty branches.
type vexTokens struct {
	ctx      context.Context
	dec      *json.Decoder
	branches int
	counts   map[string]int
	visit    func(string, json.Token)
}

func (s *vexTokens) value(path string, depth, branchDepth int, element bool) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if depth > 144 || branchDepth > 64 {
		return errors.New("redhat-vex: JSON too deep")
	}
	tok, err := s.dec.Token()
	if err != nil {
		return err
	}
	shape := vexJSONShape(path, element)
	if tok != nil || path == "" {
		if shape == '"' {
			if _, ok := tok.(string); !ok {
				return fmt.Errorf("redhat-vex: expected string at %s", path)
			}
		} else if shape != 0 && tok != json.Delim(shape) {
			return fmt.Errorf("redhat-vex: invalid structure at %s", path)
		}
	}
	s.visit(path, tok)
	switch tok {
	case json.Delim('{'):
		for s.dec.More() {
			if err := s.ctx.Err(); err != nil {
				return err
			}
			key, err := s.dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("redhat-vex: expected field name")
			}
			child := name
			if path != "" {
				child = path + "." + name
			}
			nextBranchDepth := branchDepth
			if child == "product_tree.branches.branches" {
				child = "product_tree.branches"
				nextBranchDepth++
			}
			// Unknown keys cannot impersonate a dotted schema path, and their
			// names need not be retained while descending through ignored data.
			if path == "#" || strings.Contains(name, ".") || vexJSONShape(child, false) == 0 {
				child = "#"
			}
			if err := s.value(child, depth+1, nextBranchDepth, false); err != nil {
				return err
			}
		}
	case json.Delim('['):
		limit := vexMaxProductIDs
		switch path {
		case "product_tree.branches":
			limit = vexMaxBranches
		case "product_tree.relationships":
			limit = vexMaxRelationships
		case "vulnerabilities":
			limit = 1
		case "vulnerabilities.remediations", "vulnerabilities.threats", "vulnerabilities.scores":
			limit = vexMaxStatements
		}
		for n := 0; s.dec.More(); n++ {
			if n >= limit {
				return fmt.Errorf("redhat-vex: too many entries in %s", path)
			}
			if path == "product_tree.branches" {
				s.branches++
				if s.branches > vexMaxBranches {
					return errors.New("redhat-vex: too many branches")
				}
			}
			switch path {
			case "product_tree.relationships", "vulnerabilities", "vulnerabilities.remediations", "vulnerabilities.threats", "vulnerabilities.scores":
				if s.counts == nil {
					s.counts = map[string]int{}
				}
				s.counts[path]++
				if s.counts[path] > limit {
					return fmt.Errorf("redhat-vex: too many entries in %s", path)
				}
			}
			if err := s.value(path, depth+1, branchDepth, true); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	end, err := s.dec.Token()
	if err != nil {
		return err
	}
	s.visit(path, end)
	return nil
}

// Three streaming passes make field order irrelevant: retain only RHEL scope
// products, then their relationships, then metadata referring to those IDs.
// The seekable document is spooled on disk; non-RHEL arrays never occupy RAM.
func decodeRedHatVEX(ctx context.Context, input io.ReadSeeker) (*vexDocument, error) {
	doc := new(vexDocument)
	retained := map[string]bool{}
	for pass := 0; pass < 3; pass++ {
		if _, err := input.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		var product vexProduct
		var relation vexRelationship
		var statement vexStatement
		var score vexScore
		var reference Reference
		var ids map[string]bool
		visit := func(path string, tok json.Token) {
			text, isText := tok.(string)
			if pass == 0 {
				switch path {
				case "product_tree.branches.product":
					if tok == json.Delim('{') {
						product = vexProduct{}
					}
					if tok == json.Delim('}') && len(product.ID) <= 1024 && len(product.Helper.CPE) <= 1024 && vexCPE.MatchString(product.Helper.CPE) {
						doc.Tree.Branches = append(doc.Tree.Branches, vexBranch{Product: product})
						retained[product.ID] = true
					}
				case "product_tree.branches.product.product_id":
					product.ID = text
				case "product_tree.branches.product.product_identification_helper.cpe":
					product.Helper.CPE = text
				}
				return
			}
			if pass == 1 {
				switch path {
				case "product_tree.relationships":
					if tok == json.Delim('{') {
						relation = vexRelationship{}
					}
					if tok == json.Delim('}') && relation.Category == "default_component_of" && retained[relation.Parent] && len(relation.Product.ID) <= 2048 && len(relation.Component) <= 1024 {
						doc.Tree.Relationships = append(doc.Tree.Relationships, relation)
						retained[relation.Product.ID] = true
					}
				case "product_tree.relationships.category":
					relation.Category = text
				case "product_tree.relationships.full_product_name.product_id":
					relation.Product.ID = text
				case "product_tree.relationships.product_reference":
					relation.Component = text
				case "product_tree.relationships.relates_to_product_reference":
					relation.Parent = text
				}
				return
			}
			// Scalar metadata is bounded as it is retained, not after conversion.
			switch path {
			case "document.title":
				doc.Document.Title = truncateText(text, osvMaxSummary)
			case "document.aggregate_severity.text":
				doc.Document.Severity.Text = truncateText(text, 64)
			case "document.tracking.id":
				doc.Document.Tracking.ID = truncateText(text, 128)
			case "document.tracking.initial_release_date":
				doc.Document.Tracking.Published = truncateText(text, 128)
			case "document.tracking.current_release_date":
				doc.Document.Tracking.Modified = truncateText(text, 128)
			case "vulnerabilities":
				if tok == json.Delim('{') {
					doc.Vulnerabilities = append(doc.Vulnerabilities, vexVulnerability{})
				}
			}
			if len(doc.Vulnerabilities) != 1 {
				return
			}
			v := &doc.Vulnerabilities[0]
			switch path {
			case "vulnerabilities.cve":
				v.CVE = truncateText(text, 128)
			case "vulnerabilities.product_status.fixed", "vulnerabilities.product_status.known_affected", "vulnerabilities.product_status.known_not_affected", "vulnerabilities.product_status.under_investigation",
				"vulnerabilities.remediations.product_ids", "vulnerabilities.threats.product_ids", "vulnerabilities.scores.products":
				if tok == json.Delim('[') {
					ids = map[string]bool{}
				}
				if !isText || !retained[text] || ids[text] {
					return
				}
				if ids == nil {
					return
				}
				ids[text] = true
				switch path {
				case "vulnerabilities.product_status.fixed":
					v.Status.Fixed = append(v.Status.Fixed, text)
				case "vulnerabilities.product_status.known_affected":
					v.Status.Affected = append(v.Status.Affected, text)
				case "vulnerabilities.product_status.known_not_affected":
					v.Status.NotAffected = append(v.Status.NotAffected, text)
				case "vulnerabilities.product_status.under_investigation":
					v.Status.Investigating = append(v.Status.Investigating, text)
				case "vulnerabilities.scores.products":
					score.Products = append(score.Products, text)
				default:
					statement.Products = append(statement.Products, text)
				}
			case "vulnerabilities.remediations", "vulnerabilities.threats":
				if tok == json.Delim('{') {
					statement = vexStatement{}
				}
				if tok == json.Delim('}') && len(statement.Products) > 0 {
					if path == "vulnerabilities.remediations" {
						v.Remediations = append(v.Remediations, statement)
					} else {
						v.Threats = append(v.Threats, statement)
					}
				}
			case "vulnerabilities.remediations.category", "vulnerabilities.threats.category":
				statement.Category = truncateText(text, 64)
			case "vulnerabilities.remediations.details", "vulnerabilities.threats.details":
				statement.Details = truncateText(text, 65)
			case "vulnerabilities.remediations.url", "vulnerabilities.threats.url":
				statement.URL = truncateText(text, 2049)
			case "vulnerabilities.scores":
				if tok == json.Delim('{') {
					score = vexScore{}
				}
				if tok == json.Delim('}') && len(score.CVSS.Vector) <= 1024 && strings.HasPrefix(score.CVSS.Vector, "CVSS:3.") && (len(score.Products) > 0 || len(v.Scores) == 0) {
					v.Scores = append(v.Scores, score)
				}
			case "vulnerabilities.scores.cvss_v3.vectorString":
				score.CVSS.Vector = truncateText(text, 1025)
			case "vulnerabilities.references":
				if tok == json.Delim('{') {
					reference = Reference{}
				}
				if tok == json.Delim('}') && len(v.References) < osvMaxReferences && len(reference.URL) <= 2048 && len(reference.Type) <= 128 {
					v.References = append(v.References, reference)
				}
			case "vulnerabilities.references.url":
				reference.URL = truncateText(text, 2049)
			case "vulnerabilities.references.type":
				reference.Type = truncateText(text, 129)
			}
		}
		dec := json.NewDecoder(&vexScalarReader{r: contextReader{ctx: ctx, r: input}})
		dec.UseNumber()
		stream := vexTokens{ctx: ctx, dec: dec, visit: visit}
		if err := stream.value("", 0, 0, false); err != nil {
			return nil, err
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, errors.New("redhat-vex: trailing JSON")
		}
	}
	return doc, nil
}

// Decoder.Token buffers a complete scalar. Bound even ignored strings/numbers
// before they reach it, keeping temporary decoding memory independent of the
// document size. 64 KiB allows vendor prose but IDs are retained much tighter.
type vexScalarReader struct {
	r               io.Reader
	quoted, escaped bool
	length          int
}

func (r *vexScalarReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	for i, b := range p[:n] {
		if r.quoted {
			r.length++
			if r.escaped {
				r.escaped = false
			} else if b == '\\' {
				r.escaped = true
			} else if b == '"' {
				r.quoted = false
				r.length = 0
			}
		} else {
			switch b {
			case '"':
				r.quoted = true
				r.length = 0
			case '{', '}', '[', ']', ',', ':', ' ', '\t', '\r', '\n':
				r.length = 0
			default:
				r.length++
			}
		}
		if r.length > 64<<10 {
			return i, errors.New("redhat-vex: JSON scalar exceeds 64 KiB")
		}
	}
	return n, err
}

// Arrays and their elements have separate shapes even though the visitor uses
// the same path for both. Unknown CSAF extensions are traversed but not retained.
func vexJSONShape(path string, element bool) byte {
	switch path {
	case "", "document", "document.aggregate_severity", "document.tracking", "product_tree",
		"product_tree.branches.product", "product_tree.branches.product.product_identification_helper",
		"product_tree.relationships.full_product_name", "vulnerabilities.product_status", "vulnerabilities.scores.cvss_v3":
		return '{'
	case "product_tree.branches", "product_tree.relationships", "vulnerabilities", "vulnerabilities.remediations", "vulnerabilities.threats", "vulnerabilities.scores", "vulnerabilities.references":
		if element {
			return '{'
		}
		return '['
	case "vulnerabilities.product_status.fixed", "vulnerabilities.product_status.known_affected", "vulnerabilities.product_status.known_not_affected", "vulnerabilities.product_status.under_investigation",
		"vulnerabilities.remediations.product_ids", "vulnerabilities.threats.product_ids", "vulnerabilities.scores.products":
		if element {
			return '"'
		}
		return '['
	case "document.title", "document.aggregate_severity.text", "document.tracking.id", "document.tracking.initial_release_date", "document.tracking.current_release_date",
		"product_tree.branches.product.product_id", "product_tree.branches.product.product_identification_helper.cpe",
		"product_tree.relationships.category", "product_tree.relationships.full_product_name.product_id", "product_tree.relationships.product_reference", "product_tree.relationships.relates_to_product_reference",
		"vulnerabilities.cve", "vulnerabilities.remediations.category", "vulnerabilities.remediations.details", "vulnerabilities.remediations.url",
		"vulnerabilities.threats.category", "vulnerabilities.threats.details", "vulnerabilities.threats.url", "vulnerabilities.scores.cvss_v3.vectorString", "vulnerabilities.references.url", "vulnerabilities.references.type":
		return '"'
	}
	return 0
}
