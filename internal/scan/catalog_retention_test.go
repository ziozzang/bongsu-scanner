package scan

import (
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// legacyRetentionCatalog freezes the pre-optimization algorithm as an oracle.
// It deliberately keeps every declaration and clones every incoming field.
// Differential tests exercise filtering and order-sensitive metadata merges.
type legacyRetentionCatalog struct {
	cataloger
	legacyPending []Package
}

func (c *legacyRetentionCatalog) addPackage(p Package) {
	if p.Evidence == "" && p.Type == "rpm" {
		p.Evidence = "installed"
	}
	c.observePath(p.Source)
	if c.sourceOrder == nil {
		c.sourceOrder = map[string]int{}
	}
	if _, ok := c.sourceOrder[p.Source]; !ok {
		c.sourceOrder[strings.Clone(p.Source)] = len(c.sourceOrder)
	}
	if p.Evidence == "lockfile" && strings.TrimSpace(p.Name) != "" {
		c.legacyPending = append(c.legacyPending, legacyRetentionClone(p))
		return
	}
	if p.Evidence == "installed" {
		if c.installed == nil {
			c.installed = map[string][]installedLocation{}
		}
		key := packageNameKey(p)
		// Keep every installation location until declarations are resolved;
		// merged inventory sources are capped and can span projects.
		c.installed[key] = append(c.installed[key], installedLocation{version: strings.Clone(p.Version), source: strings.Clone(p.Source)})
	}
	c.addInventoryPackage(p)
}

func (c *legacyRetentionCatalog) addInventoryPackage(p Package) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return
	}
	switch p.Type {
	case "npm":
		if p.Namespace == "" && strings.HasPrefix(p.Name, "@") {
			p.Namespace, p.Name = splitLast(p.Name, "/")
		}
	case "golang":
		if p.Namespace == "" && p.Name != "stdlib" {
			p.Namespace, p.Name = splitLast(p.Name, "/")
		}
		if p.Name == "stdlib" && p.CPE == "" && p.Version != "" {
			p.CPE = "cpe:2.3:a:golang:go:" + p.Version + ":*:*:*:*:*:*:*"
		}
	}
	// A trailing separator ("@scope/", "github.com/x/") leaves no name once
	// the namespace is split off; such an entry has no identity to report.
	if p.Name == "" {
		return
	}
	isOS := p.Type == "deb" || p.Type == "apk" || p.Type == "rpm"
	if !isOS && p.PURL == "" {
		p.PURL = buildPURL(p)
	}
	key := packageKey(p)
	if isJavaRuntimePackage(p) {
		// Runtime manifests can omit the vendor; merge those with a more
		// specific OpenJDK discovery instead of emitting one per JAR.
		key = "java-runtime\x00" + p.Version
	}
	if isOS && p.Namespace == "" {
		// An unspecified namespace may resolve differently from an explicit
		// debian/alpine namespace when os-release arrives later.
		key += "\x00os-default"
	}
	// Text parsers return substrings of a whole-file string. Copy every
	// stored field so even a tiny package cannot pin a large metadata buffer.
	p = legacyRetentionClone(p)
	if c.seen == nil {
		c.seen = make(map[string]Package)
	}
	if prev, ok := c.seen[key]; ok {
		pendingPURL := isOS && (prev.PURL == "" || (prev.SourceName == "" && p.SourceName != ""))
		sources := prev.Source
		deferred := p.Evidence == "lockfile" || p.Evidence == "declared"
		firstSource, _, _ := strings.Cut(sources, ";")
		if deferred && c.sourceOrder[p.Source] < c.sourceOrder[firstSource] {
			merged := p
			mergePackage(&merged, prev)
			prev = merged
		} else {
			mergePackage(&prev, p)
		}
		if deferred {
			// Deferred declarations keep their original discovery order,
			// including when the installed source list is already full.
			ordered := strings.Split(sources, ";")
			if sources == "" {
				ordered = nil
			}
			if p.Source != "" && !slices.Contains(ordered, p.Source) {
				ordered = append(ordered, p.Source)
			}
			sort.SliceStable(ordered, func(i, j int) bool { return c.sourceOrder[ordered[i]] < c.sourceOrder[ordered[j]] })
			prev.Source = strings.Join(ordered[:min(len(ordered), maxPackageSources)], ";")
		}
		if pendingPURL {
			prev.PURL = "" // mergePackage may have generated it before OS resolution.
		}
		c.seen[key] = prev
		return
	}
	c.seen[key] = p
	c.order = append(c.order, key)
}

func legacyRetentionClone(p Package) Package {
	p.Name = strings.Clone(p.Name)
	p.Version = strings.Clone(p.Version)
	p.Type = strings.Clone(p.Type)
	p.Namespace = strings.Clone(p.Namespace)
	p.PURL = strings.Clone(p.PURL)
	p.CPE = strings.Clone(p.CPE)
	p.License = strings.Clone(p.License)
	p.Source = strings.Clone(p.Source)
	p.Arch = strings.Clone(p.Arch)
	p.Distro = strings.Clone(p.Distro)
	p.SourceName = strings.Clone(p.SourceName)
	p.SourceVersion = strings.Clone(p.SourceVersion)
	p.Layer = strings.Clone(p.Layer)
	p.Evidence = strings.Clone(p.Evidence)
	p.VersionOriginal = strings.Clone(p.VersionOriginal)
	return p
}

func (c *legacyRetentionCatalog) finish() ([]Package, *OSRelease) {
	skipped := map[string]int{}
	for _, p := range c.legacyPending {
		declared := c.internalDeclaration(p.Source)
		if declared {
			if !c.includeDeclared {
				c.declaredSkipped++
				skipped[p.Source]++
				continue
			}
			p.Evidence = "declared"
		}
		if !c.includeDeclared && p.Evidence == "lockfile" && c.replacedByInstallation(p) {
			c.declaredSkipped++
			report(c.opts, "catalog", fmt.Sprintf("dropped lockfile version %s@%s from %s: installed version takes precedence in the same project", p.Name, p.Version, p.Source), true)
			continue
		}
		c.addInventoryPackage(p)
	}
	c.legacyPending = nil
	c.installed = nil
	sources := make([]string, 0, len(skipped))
	for source := range skipped {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		report(c.opts, "catalog", fmt.Sprintf("skipped %d declared dependencies from %s", skipped[source], source), false)
	}
	out := make([]Package, 0, len(c.order))
	resolved := make(map[string]int, len(c.order))
	for _, key := range c.order {
		p := c.seen[key]
		if p.Type == "deb" || p.Type == "apk" || p.Type == "rpm" {
			if p.Namespace == "" {
				if c.osr != nil {
					p.Namespace = c.osr.ID
				} else if p.Type == "deb" {
					p.Namespace = "debian"
				} else if p.Type == "apk" {
					p.Namespace = "alpine"
				}
			}
			if p.Distro == "" && c.osr != nil {
				p.Distro = c.osr.Distro()
			}
			if p.PURL == "" {
				p.PURL = buildPURL(p)
			}
		}
		key = packageKey(p)
		if i, ok := resolved[key]; ok {
			mergePackage(&out[i], p)
		} else {
			resolved[key] = len(out)
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Arch < b.Arch
	})
	return out, c.osr
}

func TestCatalogRetentionDifferential(t *testing.T) {
	for _, include := range []bool{false, true} {
		for seed := int64(0); seed < 64; seed++ {
			t.Run(fmt.Sprintf("include=%t/seed=%d", include, seed), func(t *testing.T) {
				// Keep both source sets and both declaration policies in short mode.
				if testing.Short() && seed != 0 && seed != 32 {
					t.Skip("repetitive differential seed; run without -short")
				}
				var got cataloger
				var want legacyRetentionCatalog
				got.includeDeclared, want.includeDeclared = include, include
				rng := rand.New(rand.NewSource(seed))
				sources := []string{"app/requirements.txt", "other/requirements.txt", "app/site-packages/owner/requirements.txt", "app/node_modules/owner/yarn.lock", "home/u/go/pkg/mod/example.com/owner@v1/go.mod", "vendor/bundle/owner/Gemfile.lock", "app/pnpm-lock.yaml", ""}
				if seed >= 32 {
					sources = append(sources, "first;second", "first")
				}
				for i := 0; i < 1500; i++ {
					p := Package{Type: "npm", Name: fmt.Sprintf("dep%d", rng.Intn(8)), Version: fmt.Sprint(rng.Intn(3)), Source: sources[rng.Intn(len(sources))], Evidence: "lockfile", Dev: rng.Intn(2) == 0, Indirect: rng.Intn(2) == 0}
					if rng.Intn(3) == 0 {
						p.License = []string{"MIT", "ISC"}[rng.Intn(2)]
					}
					if rng.Intn(5) == 0 {
						p.Layer = "layer"
					}
					if rng.Intn(7) == 0 {
						p.VersionOriginal = "original"
					}
					if rng.Intn(5) == 0 {
						p.Evidence = "installed"
						p.Source = fmt.Sprintf("%s/node_modules/%s/package.json", []string{"app", "other"}[rng.Intn(2)], p.Name)
					}
					got.addPackage(p)
					want.addPackage(p)
					if rng.Intn(3) == 0 {
						got.addPackage(p)
						want.addPackage(p)
					}
				}
				// Confirmation can arrive after every declaration and can change the
				// nearest npm owner. Display-source caps must not cap policy evidence.
				for _, p := range []string{"app/node_modules/owner/package.json", "app/site-packages/owner-1.dist-info/METADATA"} {
					got.observePath(p)
					want.observePath(p)
				}
				actual, actualOS := got.finish()
				expected, expectedOS := want.finish()
				if !reflect.DeepEqual(actual, expected) || !reflect.DeepEqual(actualOS, expectedOS) || got.declaredSkipped != want.declaredSkipped {
					for i := range min(len(actual), len(expected)) {
						if actual[i] != expected[i] {
							t.Fatalf("package %d:\n got %+v\nwant %+v", i, actual[i], expected[i])
						}
					}
					t.Fatalf("packages=%d/%d skipped=%d/%d", len(actual), len(expected), got.declaredSkipped, want.declaredSkipped)
				}
			})
		}
	}
}

func TestCatalogRetentionDeduplicatesBodiesAndOccurrences(t *testing.T) {
	var c cataloger
	p := Package{Type: "npm", Name: "dep", Version: "1", Evidence: "lockfile"}
	for i := 0; i < 10000; i++ {
		p.Source = fmt.Sprintf("app%d/package-lock.json", i%10)
		c.addPackage(p)
	}
	if len(c.pending) != 1 || len(c.pendingOrder) != 10 || len(c.pendingIndex) != 10 {
		t.Fatalf("retained keys=%d occurrences=%d index=%d", len(c.pending), len(c.pendingOrder), len(c.pendingIndex))
	}
	for _, variants := range c.pending {
		if len(variants) != 1 {
			t.Fatalf("retained %d bodies", len(variants))
		}
	}
	out, _ := c.finish()
	if len(out) != 1 || out[0].Source != "app0/package-lock.json;app1/package-lock.json;app2/package-lock.json;app3/package-lock.json;app4/package-lock.json" {
		t.Fatalf("unexpected merged sources: %+v", out)
	}
	if c.pending != nil || c.pendingIndex != nil || c.pendingOrder != nil || c.pendingCounts != nil {
		t.Fatal("retained deferred state after finish")
	}
}

func TestCatalogRetentionBoundedInterning(t *testing.T) {
	var c cataloger
	for i := 0; i < 2000; i++ {
		s := fmt.Sprintf("ns%d", i)
		p := c.retainPackage(Package{Namespace: s, Name: "a", Version: "bc", License: "d\x00e", Source: strings.Repeat("source", 20)})
		if p.Namespace != s || p.Name != "a" || p.Version != "bc" || p.License != "d\x00e" {
			t.Fatalf("altered fields: %+v", p)
		}
	}
	if len(c.shortStrings) > 1024 {
		t.Fatalf("unbounded strings: %d", len(c.shortStrings))
	}
}

func BenchmarkCatalogRetention(b *testing.B) {
	for _, legacy := range []bool{true, false} {
		b.Run(fmt.Sprintf("legacy=%t", legacy), func(b *testing.B) {
			packages := make([]Package, 100000)
			for i := range packages {
				source := fmt.Sprintf("app%d/package-lock.json", i/1000)
				if i%5 != 0 {
					source = fmt.Sprintf("home/u/go/pkg/mod/example.com/p%d@v1/go.mod", i/1000)
				}
				packages[i] = Package{Type: "npm", Name: fmt.Sprintf("dep%d", i%1000), Version: "1", Source: source, Evidence: "lockfile"}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if legacy {
					var c legacyRetentionCatalog
					for _, p := range packages {
						c.addPackage(p)
					}
					c.finish()
				} else {
					var c cataloger
					for _, p := range packages {
						c.addPackage(p)
					}
					c.finish()
				}
			}
		})
	}
}
