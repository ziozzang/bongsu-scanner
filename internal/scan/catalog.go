package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// maxPackageSources bounds how many discovery paths are joined into
// Package.Source when the same package is found in several files.
const maxPackageSources = 5

// normPath lowercases p and strips a leading "/" so host scans (absolute
// paths) and archive scans (relative paths) compare the same way.
func normPath(p string) string {
	return strings.TrimPrefix(strings.ToLower(strings.ReplaceAll(p, "\\", "/")), "/")
}

// osReleaseRank returns the priority of an os-release path: 2 for
// etc/os-release, 1 for usr/lib/os-release and 0 for anything else. Nested
// copies (container layers under var/lib/docker, test fixtures, chroots) are
// ignored so they can never override the scanned root's own identity.
func osReleaseRank(p string) int {
	switch normPath(p) {
	case "etc/os-release":
		return 2
	case "usr/lib/os-release":
		return 1
	}
	return 0
}

// parseOSRelease parses os-release key=value content.
func parseOSRelease(b []byte) OSRelease {
	vals := keyValues(b, "=")
	get := func(k string) string { return strings.Clone(strings.TrimSpace(trimQuotes(strings.TrimSpace(vals[k])))) }
	return OSRelease{
		ID:         strings.ToLower(get("ID")),
		IDLike:     get("ID_LIKE"),
		VersionID:  get("VERSION_ID"),
		Codename:   get("VERSION_CODENAME"),
		PrettyName: get("PRETTY_NAME"),
	}
}

// findOSRelease picks the root's os-release out of files using osReleaseRank.
func findOSRelease(files []File) *OSRelease {
	best, bestRank := (*OSRelease)(nil), 0
	for _, f := range files {
		r := osReleaseRank(f.Path)
		if r == 0 || r <= bestRank || len(f.Data) == 0 {
			continue
		}
		o := parseOSRelease(f.Data)
		if o.ID == "" {
			continue
		}
		best, bestRank = &o, r
	}
	return best
}

// cataloger parses inputs immediately and retains only deduplicated packages.
// OS package defaults are resolved in finish so a late (or higher-priority)
// os-release has the same effect as the archive catalog's original two passes.
// The zero value is ready for use.
type cataloger struct {
	osr               *OSRelease
	osRank            int
	seen              map[string]Package
	order             []string
	npmFiles          int
	metadataSkipped   int
	declaredSkipped   int
	includeDeclared   bool
	npmBundlePrefixes []string
	opts              Options
	pending           []Package
	sourceOrder       map[string]int
	npmDirs           map[string]bool
	npmPackages       map[string]bool
	pythonPackages    map[string]bool
	gemPackages       map[string]bool
	installed         map[string][]installedLocation
	hasDir            func(string) bool
}

type installedLocation struct {
	version string
	source  string
}

func (c *cataloger) addFile(f File) {
	c.observePath(f.Path)
	if isNPMPackageJSON(f.Path) {
		if c.npmFiles >= maxInstalledNPM {
			c.metadataSkipped++
			return
		}
		c.npmFiles++
	}
	if isJavaArchive(f.Path) {
		skipped, _ := scanJavaFile(f, "", c.addPackage)
		c.metadataSkipped += skipped
		return
	}
	if len(f.Data) == 0 {
		return
	}
	if rank := osReleaseRank(f.Path); rank > c.osRank {
		if o := parseOSRelease(f.Data); o.ID != "" {
			c.osr, c.osRank = &o, rank
		}
	}
	scanFileWithPrefixes(f, c.npmBundlePrefixes, c.addPackage)
}

// addRPMFile catalogs a trusted disk path without retaining database bytes.
// The caller owns the file and removes temporary copies after this returns.
func (c *cataloger) addRPMFile(f File, diskPath string) int {
	return scanRPMDatabase(f, diskPath, c.addPackage)
}

func (c *cataloger) addPackages(packages []Package) {
	for _, p := range packages {
		c.addPackage(p)
	}
}

func packageKey(p Package) string {
	typ, ns, name, version, quals := purlParts(p)
	if typ == "rpm" && quals["epoch"] != "" {
		version = quals["epoch"] + ":" + version
	}
	return strings.Join([]string{typ, ns, name, version, p.Arch}, "\x00")
}

func (c *cataloger) addPackage(p Package) {
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
		c.pending = append(c.pending, clonePackage(p))
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

func (c *cataloger) addInventoryPackage(p Package) {
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
	p = clonePackage(p)
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

func clonePackage(p Package) Package {
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

func (c *cataloger) finish() ([]Package, *OSRelease) {
	skipped := map[string]int{}
	for _, p := range c.pending {
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
	c.pending = nil
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

// catalog preserves the in-memory entry point used by image/archive scans.
func catalog(files []File, extra []Package) ([]Package, *OSRelease) {
	var c cataloger
	for _, f := range files {
		c.addFile(f)
	}
	c.addPackages(extra)
	return c.finish()
}

// mergePackage folds a duplicate discovery into prev: the first Source is
// kept, additional distinct paths are appended with ';' (up to
// maxPackageSources), and empty descriptive fields are filled in.
func mergePackage(prev *Package, p Package) {
	mergeJavaEvidence(prev, p)
	if evidenceRank(p.Evidence) > evidenceRank(prev.Evidence) {
		prev.Evidence = p.Evidence
	}
	if prev.VersionOriginal == "" {
		prev.VersionOriginal = p.VersionOriginal
	}
	if p.Source != "" {
		srcs := strings.Split(prev.Source, ";")
		dup := false
		for _, s := range srcs {
			if s == p.Source {
				dup = true
				break
			}
		}
		if !dup {
			if prev.Source == "" {
				prev.Source = p.Source
			} else if len(srcs) < maxPackageSources {
				prev.Source += ";" + p.Source
			}
		}
	}
	if prev.License == "" {
		prev.License = p.License
	}
	if prev.SourceName == "" {
		prev.SourceName, prev.SourceVersion = p.SourceName, p.SourceVersion
		if prev.SourceName != "" {
			prev.PURL = buildPURL(*prev)
		}
	} else if prev.SourceName == p.SourceName && prev.SourceVersion == "" && p.SourceVersion != "" {
		prev.SourceVersion = p.SourceVersion
		prev.PURL = buildPURL(*prev)
	}
	if prev.CPE == "" {
		prev.CPE = p.CPE
	}
	if prev.Layer == "" {
		prev.Layer = p.Layer
	}
	// A package that is a direct, non-dev dependency anywhere is reported as such.
	if !p.Indirect {
		prev.Indirect = false
	}
	if !p.Dev {
		prev.Dev = false
	}
}

// scanFile dispatches one metadata file to the matching parser.
func scanFile(f File, add func(Package)) {
	scanFileWithPrefixes(f, nil, add)
}

func scanFileWithPrefixes(f File, prefixes []string, add func(Package)) {
	emit := add
	add = func(p Package) {
		if isDeclarationFile(f.Path) {
			p.Evidence = "lockfile"
		} else if p.Evidence == "" {
			p.Evidence = "installed"
		}
		emit(p)
	}
	p := normPath(f.Path)
	base := path.Base(p)
	src, layer := f.Path, f.Layer
	switch {
	case isJavaArchive(f.Path):
		scanJavaFile(f, "", add)
	case isNPMPackageJSON(f.Path):
		scanInstalledNPMWithPrefixes(f, prefixes, add)
	case isInstalledGemspec(f.Path):
		scanInstalledGemspec(f, add)
	case isRPMDatabase(p):
		scanRPMDatabase(f, "", add)
	case p == "var/lib/dpkg/status", strings.HasPrefix(p, "var/lib/dpkg/status.d/"):
		if strings.HasSuffix(base, ".md5sums") {
			return
		}
		scanDpkgStatus(f.Data, src, layer, add)
	case p == "lib/apk/db/installed", p == "usr/lib/apk/db/installed":
		for _, e := range apkParagraphs(f.Data) {
			add(Package{Name: e["P"], Version: e["V"], Arch: e["A"], License: e["L"], SourceName: e["o"], Type: "apk", Source: src, Layer: layer})
		}
	case base == "package-lock.json", base == "npm-shrinkwrap.json", base == ".package-lock.json":
		scanPackageLock(f.Data, src, layer, add)
	case base == "yarn.lock":
		scanYarnLock(string(f.Data), src, layer, add)
	case base == "pnpm-lock.yaml":
		scanPnpmLock(string(f.Data), src, layer, add)
	case base == "go.mod":
		scanGoMod(string(f.Data), src, layer, add)
	case isRequirementsFile(base):
		scanRequirements(string(f.Data), src, layer, add)
	case strings.HasSuffix(p, ".dist-info/metadata"), base == "pkg-info", strings.HasSuffix(p, ".egg-info"):
		scanPythonMetadata(f.Data, src, layer, add)
	case base == "poetry.lock", base == "uv.lock":
		for _, e := range tomlPackages(string(f.Data)) {
			if s := e["source"]; base == "uv.lock" && (strings.Contains(s, "editable") || strings.Contains(s, "virtual")) {
				continue
			}
			add(Package{Name: normalizePyPIName(e["name"]), Version: e["version"], Type: "pypi", Source: src, Layer: layer, Dev: e["category"] == "dev"})
		}
	case base == "pipfile.lock":
		scanPipfileLock(f.Data, src, layer, add)
	case base == "cargo.lock":
		for _, e := range tomlPackages(string(f.Data)) {
			add(Package{Name: e["name"], Version: e["version"], Type: "cargo", Source: src, Layer: layer})
		}
	case base == "pom.properties":
		v := keyValues(f.Data, "=")
		add(Package{Name: v["artifactId"], Namespace: v["groupId"], Version: v["version"], Type: "maven", Source: src, Layer: layer})
	case base == "gemfile.lock":
		scanGemfileLock(string(f.Data), src, layer, add)
	case base == "composer.lock":
		scanComposerLock(f.Data, src, layer, add)
	case base == "packages.lock.json":
		scanNuGetLock(f.Data, src, layer, add)
	case strings.HasSuffix(base, ".deps.json"):
		scanDepsJSON(f.Data, src, layer, add)
	}
}

// scanDpkgStatus parses /var/lib/dpkg/status and distroless status.d files.
// status.d entries carry no Status field and are treated as installed.
func scanDpkgStatus(b []byte, src, layer string, add func(Package)) {
	for _, e := range paragraphs(b) {
		if st, ok := e["Status"]; ok {
			fields := strings.Fields(st)
			if len(fields) != 3 || fields[1] != "ok" || fields[2] != "installed" {
				continue
			}
		}
		name, arch := e["Package"], e["Architecture"]
		if i := strings.IndexByte(name, ':'); i >= 0 {
			// "name:arch"; a leading ':' leaves no package name at all.
			if arch == "" {
				arch = name[i+1:]
			}
			name = name[:i]
		}
		if name == "" {
			continue
		}
		p := Package{Name: name, Version: e["Version"], Arch: arch, Type: "deb", Source: src, Layer: layer}
		p.SourceName, p.SourceVersion = parseDpkgSource(e["Source"])
		add(p)
	}
}

// parseDpkgSource splits "openssl (1.1.1n-0+deb11u5)" into name and version.
func parseDpkgSource(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '('); i >= 0 {
		version = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s[i+1:]), ")"))
		s = strings.TrimSpace(s[:i])
	}
	return s, version
}

// npmPackage records a package from any npm-family lockfile. Scoped names
// are split into namespace and name.
func npmPackage(name, version, src, layer string, dev bool) Package {
	p := Package{Name: strings.TrimSpace(name), Version: strings.TrimSpace(version), Type: "npm", Source: src, Layer: layer, Dev: dev}
	if strings.HasPrefix(p.Name, "@") {
		p.Namespace, p.Name = splitLast(p.Name, "/")
	}
	return p
}

// npmVersionOK rejects versions that are really URLs, file links or
// workspace references rather than registry versions.
func npmVersionOK(v string) bool {
	if v == "" {
		return false
	}
	for _, bad := range []string{"file:", "link:", "workspace:", "git+", "github:", "http://", "https://", "git://", "ssh://"} {
		if strings.HasPrefix(v, bad) {
			return false
		}
	}
	return !strings.Contains(v, "://")
}

type npmLockDep struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

// scanPackageLock parses package-lock.json, npm-shrinkwrap.json and the
// hidden node_modules/.package-lock.json for lockfile versions 1, 2 and 3.
// The "packages" map is authoritative when present; otherwise the v1
// "dependencies" tree is walked recursively.
func scanPackageLock(b []byte, src, layer string, add func(Package)) {
	var lock struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
			Link    bool   `json:"link"`
			License any    `json:"license"`
		} `json:"packages"`
		Dependencies map[string]npmLockDep `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return
	}
	if len(lock.Packages) > 0 {
		for loc, v := range lock.Packages {
			if loc == "" || v.Link || !npmVersionOK(v.Version) {
				continue
			}
			name := v.Name
			if name == "" {
				if i := strings.LastIndex(loc, "node_modules/"); i >= 0 {
					name = loc[i+len("node_modules/"):]
				} else {
					name = path.Base(loc)
				}
			}
			p := npmPackage(name, v.Version, src, layer, v.Dev)
			if s, ok := v.License.(string); ok {
				p.License = s
			}
			add(p)
		}
		return
	}
	var walk func(deps map[string]npmLockDep)
	walk = func(deps map[string]npmLockDep) {
		for name, d := range deps {
			version := d.Version
			if strings.HasPrefix(version, "npm:") { // alias: "npm:real-name@1.2.3"
				spec := strings.TrimPrefix(version, "npm:")
				if i := strings.LastIndex(spec, "@"); i > 0 {
					name, version = spec[:i], spec[i+1:]
				}
			}
			if npmVersionOK(version) {
				add(npmPackage(name, version, src, layer, d.Dev))
			}
			if len(d.Dependencies) > 0 {
				walk(d.Dependencies)
			}
		}
	}
	walk(lock.Dependencies)
}

// yarnSpecName extracts the package name from a yarn.lock header spec such
// as "@babel/core@^7.0.0" or "lodash@npm:^4.17.0".
func yarnSpecName(spec string) string {
	spec = trimQuotes(strings.TrimSpace(spec))
	if i := strings.Index(spec, "@npm:"); i > 0 {
		// Aliases carry a second name after npm:; ordinary selectors do not.
		target := spec[i+len("@npm:"):]
		if at := strings.LastIndex(target, "@"); at > 0 {
			return target[:at]
		}
		return spec[:i]
	}
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i]
	}
	return spec
}

// scanYarnLock parses yarn.lock in both the classic v1 text format and the
// berry YAML-like format using a line scanner.
func scanYarnLock(s, src, layer string, add func(Package)) {
	name, version := "", ""
	skip := false
	flush := func() {
		if name != "" && npmVersionOK(version) && !strings.HasSuffix(version, "-use.local") {
			add(npmPackage(name, version, src, layer, false))
		}
		name, version = "", ""
	}
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			skip = false
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			first := header
			if i := strings.Index(header, ","); i >= 0 {
				first = header[:i]
			}
			if strings.HasPrefix(first, "__metadata") || strings.Contains(first, "@workspace:") || strings.Contains(first, "@file:") || strings.Contains(first, "@link:") || strings.Contains(first, "@patch:") {
				skip = true
				continue
			}
			name = yarnSpecName(first)
			continue
		}
		if skip || len(line)-len(strings.TrimLeft(line, " ")) != 2 {
			continue
		}
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "resolution:") {
			resolution := trimQuotes(strings.TrimSpace(strings.TrimPrefix(t, "resolution:")))
			if strings.Contains(resolution, "@npm:") {
				name = yarnSpecName(resolution)
			}
		}
		if strings.HasPrefix(t, "version ") || strings.HasPrefix(t, "version:") {
			rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(t, "version")), ":"))
			version = trimQuotes(rest)
		}
	}
	flush()
}

// scanPnpmLock parses the "packages:" section of pnpm-lock.yaml (v5, v6 and
// v9 key layouts) without a full YAML parser.
func scanPnpmLock(s, src, layer string, add func(Package)) {
	inPackages := false
	legacy := false // lockfileVersion < 6 uses "/name/version_peers" keys
	name, version := "", ""
	dev := false
	flush := func() {
		if name != "" && version != "" {
			add(npmPackage(name, version, src, layer, dev))
		}
		name, version, dev = "", "", false
	}
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		t := strings.TrimSpace(raw)
		if indent == 0 {
			flush()
			inPackages = t == "packages:"
			if strings.HasPrefix(t, "lockfileVersion:") {
				v := trimQuotes(strings.TrimSpace(strings.TrimPrefix(t, "lockfileVersion:")))
				legacy = v != "" && v[0] < '6'
			}
			continue
		}
		if !inPackages {
			continue
		}
		if indent == 2 && strings.HasSuffix(t, ":") {
			flush()
			key := strings.TrimPrefix(trimQuotes(strings.TrimSuffix(t, ":")), "/")
			if legacy { // v5: name/version[_peers]
				name, version = splitLast(key, "/")
				if i := strings.Index(version, "_"); i > 0 {
					version = version[:i]
				}
			} else { // v6/v9: name@version[(peers)]
				if i := strings.Index(key, "("); i > 0 {
					key = key[:i]
				}
				name, version = "", ""
				if i := strings.LastIndex(key, "@"); i > 0 {
					name, version = key[:i], key[i+1:]
				}
			}
			continue
		}
		if indent == 4 && t == "dev: true" {
			dev = true
		}
	}
	flush()
}

// isLocalModulePath reports whether a go.mod replace target is a filesystem
// path rather than a module path.
func isLocalModulePath(p string) bool {
	return strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") || p == "." || p == ".."
}

type goRequire struct {
	path, version string
	indirect      bool
}

// scanGoMod parses require/replace/exclude directives from go.mod.
// go and toolchain directives describe constraints, not the compiled stdlib.
// Replacements are applied to requirements; modules replaced by a local
// directory are dropped, since their version is unknown.
func scanGoMod(s, src, layer string, add func(Package)) {
	var reqs []goRequire
	replaces := map[string][2]string{} // "path" or "path@version" -> {newPath, newVersion}
	excludes := map[string]bool{}      // "path@version" -> excluded requirement
	block := ""
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		code, comment := raw, ""
		if i := strings.Index(raw, "//"); i >= 0 {
			code, comment = raw[:i], raw[i+2:]
		}
		line := strings.TrimSpace(code)
		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
		} else {
			f := strings.Fields(line)
			directive := f[0]
			if len(f) == 2 && f[1] == "(" {
				block = directive
				continue
			}
			switch directive {
			case "module", "retract", "go", "toolchain":
				continue
			case "require", "replace", "exclude":
				block = ""
				line = strings.TrimSpace(strings.TrimPrefix(line, directive))
				parseGoModLine(directive, line, comment, &reqs, replaces, excludes)
				continue
			default:
				continue
			}
		}
		parseGoModLine(block, line, comment, &reqs, replaces, excludes)
	}
	for _, r := range reqs {
		if excludes[r.path+"@"+r.version] {
			continue
		}
		p, v := r.path, r.version
		if rep, ok := replaces[p+"@"+v]; ok {
			p, v = rep[0], rep[1]
		} else if rep, ok := replaces[p]; ok {
			p, v = rep[0], rep[1]
		}
		if p == "" || isLocalModulePath(p) {
			continue
		}
		add(Package{Name: p, Version: v, Type: "golang", Source: src, Layer: layer, Indirect: r.indirect})
	}
}

// parseGoModLine handles one require, replace or exclude entry body.
func parseGoModLine(directive, line, comment string, reqs *[]goRequire, replaces map[string][2]string, excludes map[string]bool) {
	f := strings.Fields(line)
	for i := range f {
		if strings.HasPrefix(f[i], `"`) || strings.HasPrefix(f[i], "`") {
			v, err := strconv.Unquote(f[i])
			if err != nil {
				return
			}
			f[i] = v
		}
	}
	switch directive {
	case "exclude":
		if len(f) >= 2 {
			excludes[f[0]+"@"+f[1]] = true
		}
	case "require":
		if len(f) >= 2 {
			*reqs = append(*reqs, goRequire{path: f[0], version: f[1], indirect: strings.Contains(comment, "indirect")})
		}
	case "replace":
		arrow := -1
		for i, w := range f {
			if w == "=>" {
				arrow = i
				break
			}
		}
		if arrow < 1 || arrow+1 >= len(f) {
			return
		}
		left, right := f[:arrow], f[arrow+1:]
		key := left[0]
		if len(left) >= 2 {
			key += "@" + left[1]
		}
		newPath, newVersion := right[0], ""
		if len(right) >= 2 {
			newVersion = right[1]
		}
		replaces[key] = [2]string{newPath, newVersion}
	}
}

// scanRequirements parses pip requirements.txt. Only exact pins (== or ===)
// produce a version; ranges are recorded with an empty version. Options,
// comments, hashes, environment markers, extras and URL/VCS references are
// stripped or skipped, and backslash continuations are joined.
func scanRequirements(s, src, layer string, add func(Package)) {
	joined := strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\\\n", " ")
	for _, line := range strings.Split(joined, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, ";"); i >= 0 { // environment marker
			line = strings.TrimSpace(line[:i])
		}
		var kept []string
		fields := strings.Fields(line)
		for i := 0; i < len(fields); i++ {
			tok := fields[i]
			switch tok {
			case "--hash", "--index-url", "--extra-index-url", "--find-links", "-i", "-f", "-c", "-r", "-e":
				i++ // Consume the separate option argument as well.
				continue
			}
			if strings.HasPrefix(tok, "--") {
				continue
			}
			kept = append(kept, tok)
		}
		line = strings.Join(kept, " ")
		if line == "" {
			continue
		}
		if strings.Contains(line, "://") || strings.Contains(line, " @ ") || strings.Contains(line, "@ file:") ||
			strings.HasPrefix(line, ".") || strings.HasPrefix(line, "/") ||
			strings.HasPrefix(line, "git+") || strings.HasPrefix(line, "hg+") || strings.HasPrefix(line, "svn+") || strings.HasPrefix(line, "bzr+") {
			continue
		}
		name, spec := line, ""
		if i := strings.IndexAny(line, "<>=!~[( "); i >= 0 {
			name, spec = line[:i], line[i:]
		}
		if i := strings.IndexByte(spec, '['); i >= 0 { // extras
			end := strings.IndexByte(spec, ']')
			if end > i {
				spec = spec[:i] + spec[end+1:]
			} else {
				spec = spec[:i]
			}
		}
		spec = strings.TrimSpace(spec)
		if strings.HasPrefix(spec, "(") && strings.HasSuffix(spec, ")") {
			spec = strings.TrimSpace(spec[1 : len(spec)-1])
		}
		if name == "" {
			continue
		}
		version := ""
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			switch {
			case strings.HasPrefix(part, "==="):
				version = strings.TrimSpace(part[3:])
			case strings.HasPrefix(part, "==") && !strings.HasSuffix(part, "*"):
				version = strings.TrimSpace(part[2:])
			default:
				continue
			}
			break
		}
		add(Package{Name: normalizePyPIName(name), Version: version, Type: "pypi", Source: src, Layer: layer})
	}
}

// scanPythonMetadata parses dist-info METADATA, egg-info PKG-INFO and
// single-file *.egg-info headers.
func scanPythonMetadata(b []byte, src, layer string, add func(Package)) {
	ps := paragraphs(b)
	if len(ps) == 0 {
		return
	}
	h := ps[0]
	license := firstLine(h["License-Expression"])
	if license == "" {
		license = firstLine(h["License"])
	}
	if license == "UNKNOWN" {
		license = ""
	}
	add(Package{Name: normalizePyPIName(h["Name"]), Version: strings.TrimSpace(h["Version"]), License: license, Type: "pypi", Source: src, Layer: layer})
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// scanPipfileLock parses Pipfile.lock "default" and "develop" sections.
func scanPipfileLock(b []byte, src, layer string, add func(Package)) {
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return
	}
	for name, v := range lock.Default {
		if ver := strings.TrimPrefix(v.Version, "=="); ver != "" {
			add(Package{Name: normalizePyPIName(name), Version: ver, Type: "pypi", Source: src, Layer: layer})
		}
	}
	for name, v := range lock.Develop {
		if ver := strings.TrimPrefix(v.Version, "=="); ver != "" {
			add(Package{Name: normalizePyPIName(name), Version: ver, Type: "pypi", Source: src, Layer: layer, Dev: true})
		}
	}
}

// scanGemfileLock parses the "specs:" blocks of Gemfile.lock. Only the
// four-space indented "name (version)" entries are packages; deeper lines
// are their dependencies.
func scanGemfileLock(s, src, layer string, add func(Package)) {
	inSpecs := false
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" || line[0] != ' ' {
			inSpecs = false
			continue
		}
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		t := strings.TrimSpace(line)
		name, version := t, ""
		if i := strings.IndexByte(t, '('); i > 0 && strings.HasSuffix(t, ")") {
			name, version = strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:len(t)-1])
		}
		if name != "" && version != "" {
			add(Package{Name: name, Version: version, Type: "gem", Source: src, Layer: layer})
		}
	}
}

// scanComposerLock parses composer.lock packages and packages-dev.
func scanComposerLock(b []byte, src, layer string, add func(Package)) {
	type entry struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var lock struct {
		Packages    []entry `json:"packages"`
		PackagesDev []entry `json:"packages-dev"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return
	}
	emit := func(es []entry, dev bool) {
		for _, e := range es {
			if e.Name == "" || e.Version == "" {
				continue
			}
			p := Package{Name: e.Name, Version: e.Version, Type: "composer", Source: src, Layer: layer, Dev: dev}
			p.Namespace, p.Name = splitLast(e.Name, "/")
			add(p)
		}
	}
	emit(lock.Packages, false)
	emit(lock.PackagesDev, true)
}

// scanNuGetLock parses NuGet packages.lock.json: dependencies.<tfm>.<name>.resolved.
func scanNuGetLock(b []byte, src, layer string, add func(Package)) {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return
	}
	for _, tfm := range lock.Dependencies {
		for name, d := range tfm {
			if d.Resolved == "" || strings.EqualFold(d.Type, "Project") {
				continue
			}
			add(Package{Name: name, Version: d.Resolved, Type: "nuget", Source: src, Layer: layer, Indirect: strings.EqualFold(d.Type, "Transitive")})
		}
	}
}

// scanDepsJSON parses .NET *.deps.json "libraries" entries keyed "name/version".
func scanDepsJSON(b []byte, src, layer string, add func(Package)) {
	var deps struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}
	if json.Unmarshal(b, &deps) != nil {
		return
	}
	for key, lib := range deps.Libraries {
		if lib.Type != "" && !strings.EqualFold(lib.Type, "package") {
			continue
		}
		name, version := splitLast(key, "/")
		if name == "" || version == "" {
			continue
		}
		add(Package{Name: name, Version: version, Type: "nuget", Source: src, Layer: layer})
	}
}

// paragraphScanErrors counts truncated metadata parses. Catalog has no Options
// or Progress callback; callers still receive the successfully parsed prefix.
var paragraphScanErrors atomic.Uint64

func paragraphs(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	last := ""
	s := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(string(b), "\r\n", "\n")))
	// Allow a full metadata-sized line plus the scanner delimiter overhead.
	s.Buffer(make([]byte, 0, 64*1024), maxMetadata+1)
	for s.Scan() {
		line := s.Text()
		if line == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			last = ""
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && last != "" {
			cur[last] += "\n" + strings.TrimSpace(line)
			continue
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			last = line[:i]
			cur[last] = strings.TrimSpace(line[i+1:])
		}
	}
	if s.Err() != nil {
		paragraphScanErrors.Add(1)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

func apkParagraphs(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if line == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
		} else if len(line) > 2 && line[1] == ':' {
			cur[line[:1]] = line[2:]
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// tomlPackages collects the key/value pairs of every [[package]] table in a
// Cargo.lock, poetry.lock or uv.lock. Any other table header ends the
// current package so sub-tables such as [package.dependencies] or
// [[patch.unused]] cannot leak keys into it.
func tomlPackages(s string) []map[string]string {
	var out []map[string]string
	var cur map[string]string
	var multiline byte
	for _, line := range strings.Split(s, "\n") {
		var skip bool
		line, skip = tomlContentLine(line, &multiline)
		if skip {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			if cur != nil {
				out = append(out, cur)
			}
			cur = map[string]string{}
			continue
		}
		if strings.HasPrefix(line, "[") {
			if cur != nil {
				out = append(out, cur)
			}
			cur = nil
			continue
		}
		if cur != nil {
			if i := strings.IndexByte(line, '='); i > 0 {
				value := strings.TrimSpace(line[i+1:])
				switch {
				case len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"':
					if decoded, err := strconv.Unquote(value); err == nil {
						value = decoded
					} else {
						value = trimQuotes(value)
					}
				case len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'':
					value = value[1 : len(value)-1]
				default:
					value = trimQuotes(value)
				}
				cur[strings.TrimSpace(line[:i])] = value
			}
		}
	}
	if cur != nil {
		out = append(out, cur)
	}
	return out
}

// tomlContentLine strips comments outside strings and skips every line that
// touches a multiline string, whose contents are irrelevant to package identity.
// String state is tracked even outside package tables to avoid fake headers.
func tomlContentLine(line string, multiline *byte) (string, bool) {
	skip := *multiline != 0
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if *multiline != 0 {
			if *multiline == '"' && c == '\\' {
				i++ // An escaped quote cannot close a basic string.
				continue
			}
			if c == *multiline && i+2 < len(line) && line[i+1] == c && line[i+2] == c {
				*multiline = 0
				i += 2
				// TOML permits one or two literal quotes before the closing trio.
				for i+1 < len(line) && line[i+1] == c {
					i++
				}
			}
			continue
		}
		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '#':
			return line[:i], skip
		case '"', '\'':
			if i+2 < len(line) && line[i+1] == c && line[i+2] == c {
				*multiline, skip = c, true
				i += 2
			} else {
				quote = c
			}
		}
	}
	return line, skip
}

func keyValues(b []byte, sep string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, sep); i > 0 {
			if key := strings.TrimSpace(line[:i]); key != "" {
				out[key] = strings.TrimSpace(line[i+len(sep):])
			}
		}
	}
	return out
}

func trimQuotes(s string) string { return strings.Trim(s, `"'`) }

// A scan-wide count complements the byte budget for tiny installed manifests.
var maxInstalledNPM = 50000

func isInstalledNPMPackage(p string) bool {
	return path.Base(p) == "package.json" && strings.Contains("/"+p, "/node_modules/")
}
func scanInstalledNPM(f File, add func(Package)) {
	scanInstalledNPMWithPrefixes(f, nil, add)
}

func scanInstalledNPMWithPrefixes(f File, prefixes []string, add func(Package)) {
	var v struct {
		Name    string
		Version string
		Link    bool
		Private bool
		Bin     json.RawMessage
	}
	if json.Unmarshal(f.Data, &v) != nil || v.Link || strings.TrimSpace(v.Name) == "" || !npmVersionOK(strings.TrimSpace(v.Version)) {
		return
	}
	pkg := npmPackage(v.Name, v.Version, f.Path, f.Layer, false)
	if isInstalledNPMPackage(f.Path) {
		pkg.Evidence = "installed"
	} else {
		if v.Private || (!hasNPMBin(v.Bin) && !npmBundlePath(f.Path, prefixes)) {
			return
		}
		pkg.Evidence = "package.json"
	}
	add(pkg)
}
func isInstalledGemspec(p string) bool {
	if !strings.HasSuffix(p, ".gemspec") {
		return false
	}
	dir := path.Dir(p)
	return path.Base(dir) == "specifications" || (path.Base(dir) == "default" && path.Base(path.Dir(dir)) == "specifications")
}

var gemspecAssignment = regexp.MustCompile(`(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\.(name|version)\s*=\s*(?:Gem::Version\.new\(\s*)?["']([^"'\r\n]+)["']`)

func scanInstalledGemspec(f File, add func(Package)) {
	name, version := archiveNameVersion(path.Base(f.Path))
	for _, m := range gemspecAssignment.FindAllSubmatch(f.Data, -1) {
		if string(m[1]) == "name" {
			name = string(m[2])
		} else {
			version = string(m[2])
		}
	}
	if name != "" && version != "" {
		add(Package{Name: name, Version: version, Type: "gem", Source: f.Path, Layer: f.Layer, Evidence: "installed"})
	}
}

// packageNameKey includes the namespace: two npm scopes or Maven groups are
// distinct packages even when their final name is the same.
func packageNameKey(p Package) string {
	typ, ns, name, _, _ := purlParts(p)
	return strings.Join([]string{typ, ns, name}, "\x00")
}

func evidenceRank(e string) int {
	switch e {
	case "installed":
		return 4
	case "package.json":
		return 3
	case "lockfile":
		return 2
	case "declared":
		return 1
	}
	return 0
}

func isRequirementsFile(base string) bool {
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}

func isDeclarationFile(p string) bool {
	base := path.Base(normPath(p))
	switch base {
	case "gemfile.lock", "poetry.lock", "uv.lock", "pipfile.lock", "package-lock.json", ".package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "cargo.lock", "composer.lock", "packages.lock.json":
		return true
	}
	return isRequirementsFile(base)
}

// policyPath preserves case: project paths on Linux are case-sensitive.
func policyPath(p string) string {
	return strings.TrimPrefix(path.Clean(strings.ReplaceAll(p, "\\", "/")), "/")
}

func pathWithin(p, dir string) bool {
	return dir == "." || p == dir || strings.HasPrefix(p, dir+"/")
}

func (c *cataloger) replacedByInstallation(p Package) bool {
	if p.Source == "" {
		return false
	}
	lock := policyPath(p.Source)
	replace := false
	for _, installed := range c.installed[packageNameKey(p)] {
		for _, source := range strings.Split(installed.source, ";") {
			if source == "" {
				continue
			}
			location := policyPath(source)
			site := installationSite(location)
			if !pathWithin(location, path.Dir(lock)) && (site == "" || !pathWithin(lock, site)) {
				continue
			}
			if installed.version == p.Version {
				return false
			}
			replace = true
		}
	}
	return replace
}

func installationSite(p string) string {
	parts := strings.Split(p, "/")
	for i := len(parts) - 2; i >= 0; i-- {
		switch parts[i] {
		case "site-packages", "dist-packages", "node_modules":
			return strings.Join(parts[:i+1], "/")
		case "specifications":
			return path.Dir(strings.Join(parts[:i+1], "/"))
		}
	}
	return ""
}

func (c *cataloger) internalDeclaration(p string) bool {
	p = policyPath(p)
	if strings.Contains("/"+p, "/vendor/bundle/") || strings.Contains("/"+p, "/go/pkg/mod/") {
		return true
	}
	parts := strings.Split(p, "/")
	for i := 0; i < len(parts)-2; i++ {
		switch parts[i] {
		case "site-packages", "dist-packages":
			if c.pythonPackages[strings.Join(parts[:i+1], "/")+"/"+pythonOwnerName(parts[i+1])] {
				return true
			}
		case "gems":
			if c.gemPackages[strings.Join(parts[:i+2], "/")] {
				return true
			}
		}
	}
	if owner := c.npmDeclarationDirectory(p); owner != "" {
		return !c.npmDirs[path.Join(owner, "node_modules")]
	}
	return false
}

// A nested workspace belongs to its nearest confirmed enclosing package.
// Hidden locks directly in node_modules do not name a package owner.
func (c *cataloger) npmDeclarationDirectory(p string) string {
	parts := strings.Split(policyPath(p), "/")
	for i := len(parts) - 2; i >= 0; i-- {
		if parts[i] != "node_modules" {
			continue
		}
		end := i + 2
		if strings.HasPrefix(parts[i+1], "@") {
			end++
		}
		if end < len(parts) {
			owner := strings.Join(parts[:end], "/")
			if c.npmPackages[owner] {
				return owner
			}
		}
	}
	return ""
}

var pythonMetadataVersion = regexp.MustCompile(`-[0-9]`)

func pythonOwnerName(name string) string {
	if strings.HasSuffix(name, ".dist-info") || strings.HasSuffix(name, ".egg-info") {
		name = strings.TrimSuffix(strings.TrimSuffix(name, ".dist-info"), ".egg-info")
		if loc := pythonMetadataVersion.FindStringIndex(name); loc != nil {
			name = name[:loc[0]]
		}
	}
	return normalizePyPIName(name)
}

// Remember installation metadata only. Directory observations supplied by
// archive/walk callers cannot establish an installation by themselves.
func (c *cataloger) observePath(p string) {
	p = policyPath(p)
	parts := strings.Split(p, "/")
	if path.Base(p) == "package.json" {
		owner := path.Dir(p)
		site := path.Dir(owner)
		if strings.HasPrefix(path.Base(site), "@") {
			site = path.Dir(site)
		}
		if path.Base(site) == "node_modules" {
			if c.npmPackages == nil {
				c.npmPackages, c.npmDirs = map[string]bool{}, map[string]bool{}
			}
			c.npmPackages[owner], c.npmDirs[site] = true, true
		}
	}
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] != "site-packages" && parts[i] != "dist-packages" {
			continue
		}
		metadata := parts[i+1]
		if (strings.HasSuffix(metadata, ".dist-info") && i+3 == len(parts) && parts[i+2] == "METADATA") ||
			(strings.HasSuffix(metadata, ".egg-info") && (i+2 == len(parts) || (i+3 == len(parts) && parts[i+2] == "PKG-INFO"))) {
			if c.pythonPackages == nil {
				c.pythonPackages = map[string]bool{}
			}
			c.pythonPackages[strings.Join(parts[:i+1], "/")+"/"+pythonOwnerName(metadata)] = true
		}
	}
	if isInstalledGemspec(p) {
		site := path.Dir(p)
		if path.Base(site) == "default" {
			site = path.Dir(site)
		}
		if c.gemPackages == nil {
			c.gemPackages = map[string]bool{}
		}
		c.gemPackages[path.Join(path.Dir(site), "gems", strings.TrimSuffix(path.Base(p), ".gemspec"))] = true
	}
}

// DeclaredSkipped is a policy exclusion, never evidence of an incomplete scan.
func reportDeclaredPolicy(opts Options, meta *ScanMetadata, skipped int) {
	meta.DeclaredSkipped = skipped
	if skipped == 0 {
		return
	}
	report(opts, "catalog", fmt.Sprintf("skipped %d declared dependencies by policy (use --include-declared to keep them)", skipped), false)
	if meta.Partial {
		report(opts, "catalog", fmt.Sprintf("warning: partial scan (denied=%d errors=%d metadata-skipped=%d limit=%q); declared-skipped=%d (policy exclusions); the inventory may be incomplete",
			meta.PermissionDenied, meta.SkippedErrors, meta.MetadataSkipped, meta.LimitReached, skipped), false)
	}
}

func isNPMPackageJSON(p string) bool { return path.Base(p) == "package.json" }

func hasNPMBin(raw json.RawMessage) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single != ""
	}
	var bins map[string]string
	if json.Unmarshal(raw, &bins) == nil {
		for _, bin := range bins {
			if bin != "" {
				return true
			}
		}
	}
	return false
}

func npmBundlePath(p string, prefixes []string) bool {
	if prefixes == nil {
		prefixes = []string{"/opt", "/usr/lib", "/usr/local/lib", "/usr/share", "/srv", "/app"}
	}
	p = "/" + strings.TrimPrefix(path.Clean(p), "/")
	for _, prefix := range prefixes {
		prefix = "/" + strings.Trim(path.Clean(prefix), "/")
		if prefix != "/." && strings.HasPrefix(p, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

// interestingPackageMetadata extends the shared selector for application
// bundles and requirements variants without changing other input classes.
func interestingPackageMetadata(p string) bool {
	return interesting(p) || isNPMPackageJSON(p) || isDeclarationFile(p)
}
