package scan

import (
	"archive/zip"
	"bufio"
	"bytes"
	"io"
	"os"
	"path"
	"strings"
	"unicode"
)

// Limits are injectable by serial tests, like the RPM and metadata limits.
var maxJavaArchive int64 = 512 << 20
var maxJavaExpanded int64 = 512 << 20

const maxJavaDepth = 3

func isJavaArchive(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".jar", ".war", ".ear", ".jpi", ".hpi":
		return true
	}
	return false
}

// diskMetadataLimit is shared by the walk and image spool/link machinery.
func diskMetadataLimit(name string) int64 {
	if isJavaArchive(name) {
		return maxJavaArchive
	}
	if isRPMDatabase(name) {
		return maxRPMDatabase
	}
	return 0
}
func metadataFileLimit(name string) int64 {
	if n := diskMetadataLimit(name); n != 0 {
		return n
	}
	return maxFileMetadata
}

func scanJavaFile(f File, diskPath string, add func(Package)) (skipped, failures int) {
	if f.Size > maxJavaArchive {
		return 1, 0
	}
	if diskPath == "" {
		return scanJavaArchive(bytes.NewReader(f.Data), int64(len(f.Data)), f, add)
	}
	rd, err := os.Open(diskPath)
	if err != nil {
		return 0, 1
	}
	defer rd.Close()
	st, err := rd.Stat()
	if err != nil {
		return 0, 1
	}
	return scanJavaArchive(rd, st.Size(), f, add)
}

// Only selected entries are inflated. Nested archives use bounded memory and
// ReaderAt; neither classes nor archive paths are ever extracted to disk.
func scanJavaArchive(rd io.ReaderAt, size int64, f File, add func(Package)) (skipped, failures int) {
	if size < 0 || size > maxJavaArchive {
		return 1, 0
	}
	remaining := maxJavaExpanded
	var visit func(io.ReaderAt, int64, string, int)
	visit = func(rd io.ReaderAt, size int64, source string, depth int) {
		z, err := zip.NewReader(rd, size)
		if err != nil {
			failures++
			return
		}
		read := func(e *zip.File, limit int64) []byte {
			limit = min(limit, remaining)
			if limit < 0 || e.UncompressedSize64 > uint64(limit) {
				skipped++
				return nil
			}
			r, err := e.Open()
			if err != nil {
				failures++
				return nil
			}
			b, err := io.ReadAll(io.LimitReader(r, limit+1))
			r.Close()
			remaining -= int64(len(b))
			if int64(len(b)) > limit {
				skipped++
				return nil
			}
			if err != nil {
				failures++
				return nil
			}
			return b
		}
		found := false
		var manifest *zip.File
		for _, e := range z.File {
			if e.FileInfo().IsDir() {
				continue
			}
			if e.Name == "META-INF/MANIFEST.MF" {
				manifest = e
			}
			if path.Base(e.Name) == "release" {
				if p, ok := javaReleasePackage(read(e, maxFileMetadata), source+"!"+e.Name, f.Layer); ok {
					add(p)
					found = true
				}
			}
			parts := strings.Split(e.Name, "/")
			if len(parts) != 5 || parts[0] != "META-INF" || parts[1] != "maven" || parts[4] != "pom.properties" {
				continue
			}
			b := read(e, maxFileMetadata)
			if b == nil {
				continue
			}
			v := keyValues(b, "=")
			name, group, version := strings.TrimSpace(v["artifactId"]), strings.TrimSpace(v["groupId"]), strings.TrimSpace(v["version"])
			if !javaCoordinatePart(name) || !javaCoordinatePart(version) || (group != "" && !javaCoordinatePart(group)) {
				continue
			}
			p := javaPackage(name, group, version, source, f.Layer, "pom.properties")
			add(p)
			found = true
		}
		if !found {
			name, version := archiveNameVersion(path.Base(source[strings.LastIndex(source, "!")+1:]))
			v := map[string]string{}
			if manifest != nil {
				v = javaManifest(read(manifest, maxFileMetadata))
			}
			evidence := "filename"
			for _, key := range []string{"implementation-version", "bundle-version", "specification-version"} {
				if ver := v[key]; javaCoordinatePart(ver) {
					version, evidence = ver, "manifest"
					break
				}
			}
			group := javaManifestGroup(v)
			if group != "" {
				evidence = "manifest"
			} else {
				group = javaClassGroup(z.File)
			}
			if artifact := javaTomcatArtifact(name, group, v); artifact != "" {
				name, group = artifact, "org.apache.tomcat"
				evidence = "manifest"
			}
			if javaCoordinatePart(name) && javaCoordinatePart(version) {
				p := javaPackage(name, group, version, source, f.Layer, evidence)
				if isJavaRuntimeTitle(v["implementation-title"]) {
					p = javaRuntimePackage(version, v["implementation-vendor"]+" "+v["implementation-vendor-id"]+" "+v["implementation-title"], source, f.Layer, "manifest")
				}
				add(p)
			}
		}
		for _, e := range z.File {
			if e.FileInfo().IsDir() || !isJavaArchive(e.Name) {
				continue
			}
			if depth >= maxJavaDepth {
				skipped++
				continue
			}
			b := read(e, maxJavaArchive)
			if b != nil {
				visit(bytes.NewReader(b), int64(len(b)), source+"!"+e.Name, depth+1)
			}
		}
	}
	visit(rd, size, f.Path, 0)
	return skipped, failures
}

func javaCoordinatePart(s string) bool {
	return s != "" && !strings.ContainsFunc(s, unicode.IsSpace)
}

// Tomcat distributions use short filenames and OSGi symbolic names such as
// org.apache.tomcat-catalina. Normalize only these known aliases with Tomcat
// metadata; a filename or display title alone is insufficient evidence.
func javaTomcatArtifact(name, group string, v map[string]string) string {
	artifact := name
	switch name {
	case "catalina", "catalina-ant", "catalina-ha", "jasper", "jasper-el", "annotations-api", "el-api", "jaspic-api", "jsp-api", "servlet-api", "websocket-api", "websocket-client-api":
		artifact = "tomcat-" + name
	case "catalina-tribes", "catalina-ssi", "catalina-storeconfig":
		artifact = "tomcat-" + strings.TrimPrefix(name, "catalina-")
	default:
		if !strings.HasPrefix(name, "tomcat-") {
			return ""
		}
	}
	if vendor := v["implementation-vendor-id"]; javaDomainID(vendor) && vendor != "org.apache.tomcat" {
		return ""
	}
	symbolic := strings.TrimSpace(strings.SplitN(v["bundle-symbolicname"], ";", 2)[0])
	if symbolic == "org.apache."+artifact {
		return artifact
	}
	if strings.EqualFold(v["implementation-title"], "Apache Tomcat") {
		switch group {
		case "org.apache.tomcat", "org.apache.catalina", "org.apache.jasper", "org.apache.coyote", "org.apache.juli":
			return artifact
		}
	}
	return ""
}

func javaPackage(name, group, version, source, layer, evidence string) Package {
	typ := "generic"
	if group != "" {
		typ = "maven"
	}
	return Package{Name: name, Namespace: group, Version: version, Type: typ, Source: source, Layer: layer, Evidence: evidence}
}

// Require a domain-shaped identifier, rather than a vendor's display name.
func javaDomainID(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts[0]) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part[0] < 'a' || part[0] > 'z' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

func javaManifestGroup(v map[string]string) string {
	if group := v["implementation-vendor-id"]; javaDomainID(group) {
		return group
	}
	for _, key := range []string{"bundle-symbolicname", "automatic-module-name"} {
		id := strings.TrimSpace(strings.SplitN(v[key], ";", 2)[0])
		if !javaDomainID(id) {
			continue
		}
		parts := strings.Split(id, ".")
		// The last segment names the bundle/module, unless only the domain
		// itself was supplied. Keep at most three namespace segments.
		return strings.Join(parts[:min(3, max(2, len(parts)-1))], ".")
	}
	return ""
}

// Inspect only central-directory names, never inflate class bodies. Ties
// resolve lexically so archive entry order cannot change the selected group.
func javaClassGroup(entries []*zip.File) string {
	counts := map[string]int{}
	best, bestCount := "", 0
	for _, e := range entries[:min(len(entries), 2000)] {
		name := e.Name
		for _, prefix := range []string{"BOOT-INF/classes/", "WEB-INF/classes/"} {
			name = strings.TrimPrefix(name, prefix)
		}
		if strings.HasPrefix(name, "META-INF/versions/") {
			_, name, _ = strings.Cut(strings.TrimPrefix(name, "META-INF/versions/"), "/")
		}
		if !strings.HasSuffix(name, ".class") {
			continue
		}
		parts := strings.Split(path.Dir(name), "/")
		group := strings.Join(parts[:min(3, len(parts))], ".")
		if !javaDomainID(group) {
			continue
		}
		counts[group]++
		if n := counts[group]; n > bestCount || n == bestCount && group < best {
			best, bestCount = group, n
		}
	}
	return best
}

func isJavaRuntimeTitle(title string) bool {
	switch strings.ToLower(strings.TrimSpace(title)) {
	case "java runtime environment", "java(tm) se runtime environment", "openjdk runtime environment":
		return true
	}
	return false
}

func javaRuntimePackage(version, vendor, source, layer, evidence string) Package {
	p := javaPackage("java-runtime", "", version, source, layer, evidence)
	vendor = strings.ToLower(vendor)
	if strings.Contains(vendor, "openjdk") || strings.Contains(vendor, "oracle") {
		p.Name = "openjdk"
		p.CPE = "cpe:2.3:a:oracle:openjdk:" + version + ":*:*:*:*:*:*:*"
	}
	return p
}

func javaReleasePackage(data []byte, source, layer string) (Package, bool) {
	v := keyValues(data, "=")
	version := trimQuotes(strings.TrimSpace(v["JAVA_VERSION"]))
	if !javaCoordinatePart(version) || version[0] < '0' || version[0] > '9' {
		return Package{}, false
	}
	vendor := trimQuotes(v["IMPLEMENTOR"]) + " " + trimQuotes(v["JAVA_VENDOR"])
	return javaRuntimePackage(version, vendor, source, layer, "release-file"), true
}

func isJavaRuntimePackage(p Package) bool {
	return p.Type == "generic" && (p.Name == "java-runtime" || p.Name == "openjdk") && (p.Evidence == "manifest" || p.Evidence == "release-file")
}

func mergeJavaEvidence(prev *Package, p Package) {
	if isJavaRuntimePackage(*prev) && isJavaRuntimePackage(p) && p.Name == "openjdk" {
		prev.Name = p.Name
		prev.PURL = buildPURL(*prev)
	}
	rank := func(evidence string) int {
		switch evidence {
		case "release-file":
			return 4
		case "pom.properties":
			return 3
		case "manifest":
			return 2
		case "filename":
			return 1
		}
		return 0
	}
	if rank(p.Evidence) > rank(prev.Evidence) {
		prev.Evidence = p.Evidence
	}
}

// Main manifest attributes are case-insensitive and continuation lines begin
// with a space. Named entry sections must not override the archive identity.
func javaManifest(b []byte) map[string]string {
	out := map[string]string{}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 4096), maxMetadata)
	key := ""
	for s.Scan() {
		line := strings.TrimSuffix(s.Text(), "\r")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") {
			if key != "" {
				out[key] += line[1:]
			}
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		key = ""
		if ok {
			key = strings.ToLower(strings.TrimSpace(k))
			out[key] = strings.TrimSpace(v)
		}
	}
	return out
}

// Find the first hyphen followed by a digit, preserving prerelease suffixes
// and hyphens in artifact names (foo-bar-1.2-RC1).
func archiveNameVersion(name string) (string, string) {
	name = strings.TrimSuffix(name, path.Ext(name))
	return installedNameVersion(name)
}
func installedNameVersion(name string) (string, string) {
	for i := 1; i+1 < len(name); i++ {
		if name[i] == '-' && name[i+1] >= '0' && name[i+1] <= '9' {
			return name[:i], name[i+1:]
		}
	}
	return name, ""
}
