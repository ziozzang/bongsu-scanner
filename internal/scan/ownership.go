package scan

import (
	"bufio"
	"bytes"
	"path"
	"sort"
	"strings"
)

const (
	maxOwnedPaths      = 64 << 10
	maxOwnedBytes      = 16 << 20
	maxOwnedPathLength = 4096
)

// Linux package database paths are case sensitive. Do not use normPath here.
func ownershipPath(p string) string { return clean(p) }
func languageMetadataPath(p string) bool {
	if len(p) > maxOwnedPathLength {
		return false
	}
	return strings.HasSuffix(p, ".dist-info/METADATA") || strings.HasSuffix(p, ".egg-info/PKG-INFO") || strings.HasSuffix(p, ".egg-info") || isInstalledNPMPackage(p) || isInstalledGemspec(p)
}
func isDpkgList(p string) bool {
	p = ownershipPath(p)
	return path.Dir(p) == "var/lib/dpkg/info" && strings.HasSuffix(p, ".list")
}
func (c *cataloger) ownPath(p, owner string) {
	p = ownershipPath(p)
	if !languageMetadataPath(p) || owner == "" {
		return
	}
	if prev, ok := c.ownedPaths[p]; ok {
		// Conflicting claims cannot safely suppress upstream advisories.
		if prev != owner {
			c.ownedPaths[p] = ""
		}
		return
	}
	if len(c.ownedPaths) >= maxOwnedPaths || c.ownedBytes+len(p)+len(owner) > maxOwnedBytes {
		return
	}
	if c.ownedPaths == nil {
		c.ownedPaths = make(map[string]string)
	}
	c.ownedPaths[strings.Clone(p)] = strings.Clone(owner)
	c.ownedBytes += len(p) + len(owner)
}
func (c *cataloger) collectOwnership(f File) {
	if isDpkgList(f.Path) {
		owner := "deb:" + strings.TrimSuffix(path.Base(f.Path), ".list")
		s := bufio.NewScanner(bytes.NewReader(f.Data))
		s.Buffer(make([]byte, 4096), int(maxFileMetadata))
		for s.Scan() {
			c.ownPath(s.Text(), owner)
		}
		return
	}
	p := normPath(f.Path)
	if p != "lib/apk/db/installed" && p != "usr/lib/apk/db/installed" {
		return
	}
	s := bufio.NewScanner(bytes.NewReader(f.Data))
	s.Buffer(make([]byte, 4096), int(maxFileMetadata))
	var name, version, dir string
	var files []string
	fileBytes := 0
	flush := func() {
		if name != "" && version != "" {
			for _, p := range files {
				c.ownPath(p, "apk:"+name+"@"+version)
			}
		}
		name, version, dir = "", "", ""
		files = nil
		fileBytes = 0
	}
	for s.Scan() {
		line := s.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch line[0] {
		case 'P':
			name = strings.Clone(line[2:])
		case 'V':
			version = strings.Clone(line[2:])
		case 'F':
			dir = strings.Clone(line[2:])
		case 'R':
			p := ownershipPath(path.Join(dir, line[2:]))
			if languageMetadataPath(p) && len(files) < maxOwnedPaths && fileBytes+len(p) <= maxOwnedBytes {
				files = append(files, p)
				fileBytes += len(p)
			}
		}
	}
	flush()
}
func (c *cataloger) resolveOwnership() {
	if len(c.ownedPaths) == 0 {
		c.ownedPaths = nil
		c.ownedBytes = 0
		return
	}
	// Index once: a package name may have thousands of installed versions.
	type locationKey struct{ name, version string }
	locations := make(map[locationKey][]string)
	for name, installed := range c.installed {
		for _, loc := range installed {
			key := locationKey{name, loc.version}
			locations[key] = append(locations[key], loc.source)
		}
	}
	deb := map[string]string{}
	put := func(key, owner string) {
		if prev, exists := deb[key]; exists && prev != owner {
			deb[key] = ""
		} else {
			deb[key] = owner
		}
	}
	for _, p := range c.seen {
		if p.Type == "deb" && p.Version != "" {
			owner := "deb:" + p.Name + "@" + p.Version
			put("deb:"+p.Name, owner)
			if p.Arch != "" {
				put("deb:"+p.Name+":"+p.Arch, owner)
			}
		}
	}
	for k, p := range c.seen {
		if p.Type != "pypi" && p.Type != "npm" && p.Type != "gem" {
			continue
		}
		owner := ""
		all := p.Source != ""
		sources := strings.Split(p.Source, ";")
		// Include locations beyond the inventory display cap. An unowned
		// installation must continue to receive upstream matching.
		for _, source := range locations[locationKey{packageNameKey(p), p.Version}] {
			sources = append(sources, strings.Split(source, ";")...)
		}
		for _, src := range sources {
			o := c.ownedPaths[ownershipPath(src)]
			if strings.HasPrefix(o, "deb:") {
				o = deb[o]
			}
			if o == "" || owner != "" && owner != o {
				all = false
				break
			}
			owner = o
		}
		if all {
			p.Owner = owner
			c.seen[k] = p
		}
	}
	c.ownedPaths = nil
	c.ownedBytes = 0
}

// Workers spool package values, not input bytes. Nameless ownership records
// carry dpkg/APK file lists through the same bounded gob transport; addPackage
// consumes them before package identity/evidence processing.
func scanFileOwnership(f File, add func(Package)) {
	var c cataloger
	c.collectOwnership(f)
	paths := make([]string, 0, len(c.ownedPaths))
	for p := range c.ownedPaths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	grouped := map[string][]string{}
	for _, p := range paths {
		owner := c.ownedPaths[p]
		if owner != "" {
			grouped[owner] = append(grouped[owner], p)
		}
	}
	owners := make([]string, 0, len(grouped))
	for owner := range grouped {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		add(Package{Owner: owner, Ownership: &packageOwnership{Paths: grouped[owner]}})
	}
}
