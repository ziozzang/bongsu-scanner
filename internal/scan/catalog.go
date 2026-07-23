package scan

import (
	"bufio"
	"encoding/json"
	"net/url"
	"path"
	"sort"
	"strings"
)

func catalog(files []File) ([]Package, string, string) {
	seen := map[string]Package{}
	osName, osVersion := "", ""
	add := func(p Package) {
		if p.Name == "" {
			return
		}
		if p.PURL == "" {
			p.PURL = makePURL(p.Type, p.Name, p.Version)
		}
		seen[p.Type+"\x00"+p.Name+"\x00"+p.Version] = p
	}
	for _, f := range files {
		if len(f.Data) == 0 {
			continue
		}
		lower := strings.ToLower(f.Path)
		switch {
		case lower == "var/lib/dpkg/status" || strings.HasSuffix(lower, "/var/lib/dpkg/status"):
			for _, p := range paragraphs(f.Data) {
				if strings.HasPrefix(p["Status"], "install ok installed") {
					add(Package{Name: p["Package"], Version: p["Version"], Arch: p["Architecture"], Type: "deb", Source: f.Path})
				}
			}
		case lower == "lib/apk/db/installed" || strings.HasSuffix(lower, "/lib/apk/db/installed"):
			for _, p := range apkParagraphs(f.Data) {
				add(Package{Name: p["P"], Version: p["V"], Arch: p["A"], License: p["L"], Type: "apk", Source: f.Path})
			}
		case strings.HasSuffix(lower, "/os-release") || lower == "etc/os-release":
			vals := keyValues(f.Data, "=")
			osName, osVersion = trimQuotes(vals["ID"]), trimQuotes(vals["VERSION_ID"])
		case path.Base(lower) == "package-lock.json" || path.Base(lower) == "npm-shrinkwrap.json":
			var lock struct {
				Packages map[string]struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					License any    `json:"license"`
				} `json:"packages"`
				Dependencies map[string]struct {
					Version string `json:"version"`
				} `json:"dependencies"`
			}
			if json.Unmarshal(f.Data, &lock) == nil {
				for loc, v := range lock.Packages {
					name := v.Name
					if name == "" && strings.Contains(loc, "node_modules/") {
						name = loc[strings.LastIndex(loc, "node_modules/")+len("node_modules/"):]
					}
					if loc != "" {
						add(Package{Name: name, Version: v.Version, Type: "npm", Source: f.Path})
					}
				}
				if len(lock.Packages) == 0 {
					for name, v := range lock.Dependencies {
						add(Package{Name: name, Version: v.Version, Type: "npm", Source: f.Path})
					}
				}
			}
		case path.Base(lower) == "go.mod":
			scanGoMod(string(f.Data), f.Path, add)
		case path.Base(lower) == "requirements.txt":
			scanRequirements(string(f.Data), f.Path, add)
		case strings.HasSuffix(lower, ".dist-info/metadata"):
			p := paragraphs(f.Data)
			if len(p) > 0 {
				add(Package{Name: p[0]["Name"], Version: p[0]["Version"], License: p[0]["License"], Type: "pypi", Source: f.Path})
			}
		case path.Base(lower) == "cargo.lock":
			for _, p := range tomlPackages(string(f.Data)) {
				add(Package{Name: p["name"], Version: p["version"], Type: "cargo", Source: f.Path})
			}
		case path.Base(lower) == "pom.properties":
			v := keyValues(f.Data, "=")
			name := v["artifactId"]
			p := Package{Name: name, Version: v["version"], Type: "maven", Source: f.Path}
			if g := v["groupId"]; g != "" {
				p.PURL = "pkg:maven/" + url.PathEscape(g) + "/" + url.PathEscape(name) + "@" + url.PathEscape(p.Version)
			}
			add(p)
		}
	}
	out := make([]Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out, osName, osVersion
}

func paragraphs(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	last := ""
	s := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(string(b), "\r\n", "\n")))
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
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

func apkParagraphs(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
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

func scanGoMod(s, source string, add func(Package)) {
	inBlock := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inBlock {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			add(Package{Name: f[0], Version: f[1], Type: "golang", Source: source})
		}
	}
}

func scanRequirements(s, source string, add func(Package)) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		for _, sep := range []string{"==", "~=", ">=", "<=", "!="} {
			if i := strings.Index(line, sep); i > 0 {
				add(Package{Name: strings.TrimSpace(line[:i]), Version: strings.TrimSpace(strings.SplitN(line[i+len(sep):], ";", 2)[0]), Type: "pypi", Source: source})
				break
			}
		}
	}
}

func tomlPackages(s string) []map[string]string {
	var out []map[string]string
	var cur map[string]string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			if cur != nil {
				out = append(out, cur)
			}
			cur = map[string]string{}
		} else if cur != nil {
			if i := strings.IndexByte(line, '='); i > 0 {
				cur[strings.TrimSpace(line[:i])] = trimQuotes(strings.TrimSpace(line[i+1:]))
			}
		}
	}
	if cur != nil {
		out = append(out, cur)
	}
	return out
}

func keyValues(b []byte, sep string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, sep); i > 0 {
			out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+len(sep):])
		}
	}
	return out
}
func trimQuotes(s string) string { return strings.Trim(s, `"'`) }
func makePURL(kind, name, version string) string {
	if kind == "" || name == "" {
		return ""
	}
	p := "pkg:" + kind + "/" + url.PathEscape(name)
	if version != "" {
		p += "@" + url.PathEscape(version)
	}
	return p
}
