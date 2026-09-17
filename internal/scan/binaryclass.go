package scan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"sync/atomic"
)

const (
	maxClassifiedBinaries = 20_000
	maxBinaryScanBytes    = 8 << 20
	maxJavaReleaseBytes   = 64 << 10
)

// A budget belongs to one walk (shared by its workers) or image, never to
// the process. It bounds Go probes as well as runtime string classification.
type binaryProbeBudget struct{ count atomic.Int64 }

func (b *binaryProbeBudget) take() bool {
	return b.count.Add(1) <= maxClassifiedBinaries
}

type binaryClassifier struct {
	name, vendor, product string
	file                  *regexp.Regexp
	markers               [][]byte
	versions              []*regexp.Regexp
}

func binaryRule(name, vendor, product, file, marker string, versions ...string) binaryClassifier {
	r := binaryClassifier{name: name, vendor: vendor, product: product, file: regexp.MustCompile(file)}
	for _, m := range strings.Split(marker, "|") {
		r.markers = append(r.markers, []byte(m))
	}
	for _, v := range versions {
		r.versions = append(r.versions, regexp.MustCompile(v))
	}
	return r
}

// File constraints are especially important for bare version strings (sqlite,
// zlib, Python): a linked dependency's version is not the executable's version.
// CPEs are attached here, before matching; both SBOM writers already preserve
// Package.CPE. Keeping the mapping here avoids a scan -> sbom import cycle.
var binaryClassifiers = []binaryClassifier{
	binaryRule("python", "python", "python", `^(?:python(?:[23](?:\.[0-9]+)?)?(?:\.exe)?|libpython[23]\.[0-9]+(?:m|d)?\.so(?:\.[0-9]+)*)$`, "Py_InitializeEx|PYTHONPATH",
		`Python ([23]\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`, `([23]\.[0-9]+\.[0-9]+) \((?:main|default|tags/)`,
		`\x00([23]\.[0-9]+\.[0-9]+)\x00`),
	binaryRule("node", "nodejs", "node.js", `^(?:node(?:js)?(?:\.exe)?|libnode\.so(?:\.[0-9]+)*)$`, "node_module_register|NODE_OPTIONS", `node/v([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("ruby", "ruby-lang", "ruby", `^(?:ruby(?:[0-9]+\.[0-9]+)?(?:\.exe)?|libruby(?:-[0-9]+\.[0-9]+)?\.so(?:\.[0-9]+)*)$`, "ruby_init|RUBYLIB", `ruby ([0-9]+\.[0-9]+\.[0-9]+)(?:p[0-9]*|[^0-9.]|$)`, `RUBY_VERSION[\x00 ="\t]+([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("openssl", "openssl", "openssl", `^(?:openssl(?:\.exe)?|lib(?:ssl|crypto)\.so(?:\.[0-9]+)*)$`, "OPENSSLDIR|OpenSSL_version|SSL_CTX_new", `OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)(?:[^0-9.a-z]|$)`),
	binaryRule("busybox", "busybox", "busybox", `^busybox(?:\.exe)?$`, "BusyBox multi-call|multi-call binary", `BusyBox v([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("php", "php", "php", `^(?:php(?:[0-9]+(?:\.[0-9]+)?)?(?:\.exe)?|libphp[0-9]*\.so(?:\.[0-9]+)*)$`, "php_version|PHP_INI_SCAN_DIR", `(?:X-Powered-By: PHP/|PHP Version )([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("perl", "perl", "perl", `^(?:perl(?:[0-9]+(?:\.[0-9]+)*)?(?:\.exe)?|libperl\.so(?:\.[0-9]+)*)$`, "Perl_runops|PERL5LIB", `/(?:lib/)?perl5/([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`, `This is perl 5, version ([0-9]+)(?:, subversion ([0-9]+))?`),
	binaryRule("nginx", "f5", "nginx", `^nginx(?:\.exe)?$`, "ngx_", `nginx/([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("httpd", "apache", "http_server", `^(?:httpd|apache2?)(?:\.exe)?$`, "ap_server_root|APACHE_RUN_DIR", `Apache/([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("redis", "redis", "redis", `^redis-server(?:\.exe)?$`, "redis-server", `(?:Redis version |redis_version:)([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("postgres", "postgresql", "postgresql", `^(?:(?:postgres|postmaster)(?:\.exe)?|libpq\.so(?:\.[0-9]+)*)$`, "PGDATA|PQconnectdb", `PostgreSQL ([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:[^0-9.]|$)`),
	binaryRule("mariadb", "mariadb", "mariadb", `^(?:mysql|mysqld|mariadb|mariadbd)(?:\.exe)?$`, "mysql_real_connect|MYSQL_HOME", `([0-9]+\.[0-9]+\.[0-9]+)-MariaDB`, `MariaDB ([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("mysql", "oracle", "mysql", `^(?:(?:mysql|mysqld)(?:\.exe)?|libmysqlclient\.so(?:\.[0-9]+)*)$`, "mysql_real_connect|MYSQL_HOME", `(?:MySQL |mysql  Ver |mysqld  Ver )([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("curl", "haxx", "curl", `^(?:curl(?:\.exe)?|libcurl\.so(?:\.[0-9]+)*)$`, "curl_easy_init", `(?:curl |libcurl/)([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("sqlite", "sqlite", "sqlite", `^(?:sqlite3(?:\.exe)?|libsqlite3\.so(?:\.[0-9]+)*)$`, "sqlite3_libversion", `\x00(3\.[0-9]+\.[0-9]+)\x00`),
	binaryRule("zlib", "zlib", "zlib", `^libz\.so(?:\.[0-9]+)*$`, "deflate", `\x00(1\.[0-9]+(?:\.[0-9]+)?)\x00`),
	binaryRule("glibc", "gnu", "glibc", `^(?:libc\.so(?:\.[0-9]+)*|libc-[0-9]+\.[0-9]+\.so|ld-linux(?:-[a-z0-9_-]+)?\.so(?:\.[0-9]+)*)$`, "GNU C Library", `GNU C Library [^\x00\n]{0,160}stable release version ([0-9]+\.[0-9]+)(?:\.[^0-9]|[^0-9.]|$)`),
	binaryRule("musl", "musl-libc", "musl", `^(?:libc\.so(?:\.[0-9]+)*|libc\.musl-[a-z0-9_-]+\.so(?:\.[0-9]+)*|ld-musl-[a-z0-9_-]+\.so(?:\.[0-9]+)*)$`, "musl libc", `musl libc[^\x00]{0,100}\nVersion ([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`),
	binaryRule("bash", "gnu", "bash", `^bash(?:\.exe)?$`, "BASH_VERSION|BASHOPTS", `GNU bash, version ([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9.]|$)`, `\x00([0-9]+\.[0-9]+\.[0-9]+)\([0-9]+\)-release\x00`),
}

func binaryRules(source string) []binaryClassifier {
	base := strings.ToLower(path.Base(source))
	var rules []binaryClassifier
	for _, rule := range binaryClassifiers {
		if rule.file.MatchString(base) {
			rules = append(rules, rule)
		}
	}
	return rules
}

// Recognize non-executable runtime libraries without opening every data file.
func runtimeLibraryCandidate(source string) bool {
	base := strings.ToLower(path.Base(source))
	return (strings.HasPrefix(base, "lib") || strings.HasPrefix(base, "ld-")) && len(binaryRules(source)) != 0
}

func isNativeBinary(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	if isELF(b) || b[0] == 'M' && b[1] == 'Z' {
		return true
	}
	switch binary.BigEndian.Uint32(b[:4]) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return true
	}
	return false
}

func binaryPackage(name, version, vendor, product, source, layer string) Package {
	p := Package{Name: name, Version: version, Type: "generic", Source: source, Layer: layer, Evidence: "binary"}
	p.PURL = buildPURL(p)
	p.CPE = "cpe:2.3:a:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
	return p
}

var binaryPythonFileVersion = regexp.MustCompile(`^(?:lib)?python([23](?:\.[0-9]+)?)`)

// Collect candidates across all signatures; conflicting versions are ambiguous.
// Bare Python versions are constrained by the filename's ABI.
func binaryPackages(r io.ReaderAt, size int64, source, layer string, options ...Options) []Package {
	if r == nil || size < 4 || size > maxGoBinary {
		return nil
	}
	rules := binaryRules(source)
	if len(rules) == 0 {
		return nil
	}
	r = boundedBinaryReader(r)
	var head [4]byte
	if _, err := r.ReadAt(head[:], 0); err != nil || !isNativeBinary(head[:]) {
		return nil
	}
	data := binaryScanData(r, size, isELF(head[:]))
	var pkgs []Package
	for _, rule := range rules {
		marked := false
		for _, marker := range rule.markers {
			marked = marked || bytes.Contains(data, marker)
		}
		if !marked || rule.name == "mysql" && bytes.Contains(data, []byte("MariaDB")) {
			continue
		}
		versions := map[string]bool{}
		ambiguous := false
		for i, re := range rule.versions {
			// Avoid scanning for formatted Python versions when their marker is absent.
			if rule.name == "python" && i == 1 && !bytes.Contains(data, []byte(" (main")) && !bytes.Contains(data, []byte(" (default")) && !bytes.Contains(data, []byte(" (tags/")) {
				continue
			}
			prefix := ""
			if rule.name == "python" && i == 2 {
				if !bytes.Contains(data, []byte("Py_GetVersion")) {
					continue
				}
				if m := binaryPythonFileVersion.FindStringSubmatch(path.Base(source)); len(m) == 2 {
					prefix = m[1] + "."
				}
			}
			remaining := data
			for attempts := 0; ; attempts++ {
				m := re.FindSubmatchIndex(remaining)
				if len(m) < 4 {
					break
				}
				if attempts == 32 {
					ambiguous = true
					break
				}
				version := string(remaining[m[2]:m[3]])
				if rule.name == "perl" && i == 1 {
					patch := "0"
					if len(m) >= 6 && m[4] >= 0 {
						patch = string(remaining[m[4]:m[5]])
					}
					version = "5." + version + "." + patch
				}
				if strings.HasPrefix(version, prefix) {
					versions[version] = true
				}
				// Keep a delimiter which may also start the next match.
				remaining = remaining[max(m[3], m[1]-1):]
			}
		}
		if ambiguous || len(versions) > 1 {
			for _, opts := range options {
				report(opts, "binary", fmt.Sprintf("%s: ambiguous %s version (%d distinct candidates)", source, rule.name, len(versions)), true)
			}
			continue
		}
		for version := range versions {
			pkgs = append(pkgs, binaryPackage(rule.name, version, rule.vendor, rule.product, source, layer))
		}
	}
	return pkgs
}

// Limit content scans to 8 MiB total. For large ELF files, reserve half of
// that budget for .rodata when it lies beyond the prefix. Section headers
// and the string table are bounded to 4096 entries / 64 KiB, and their
// reads also count against the shared classification/build-info budget.
func binaryScanData(r io.ReaderAt, size int64, elf bool) []byte {
	r = boundedBinaryReader(r)
	budget := r.(*binaryReadBudget)
	prefix := min(size, budget.remaining)
	var off, length int64
	if elf && size > maxBinaryScanBytes {
		off, length = binaryRodata(r, size)
		if off >= maxBinaryScanBytes/2 && length > 0 {
			length = min(length, maxBinaryScanBytes/2)
			prefix = maxBinaryScanBytes - length
			if off < prefix {
				prefix = off
			}
		} else {
			length = 0
		}
	}
	length = min(length, budget.remaining)
	prefix = min(prefix, budget.remaining-length)
	data := make([]byte, prefix)
	n, _ := r.ReadAt(data, 0)
	data = data[:n]
	if length > 0 {
		// A separator prevents a signature straddling unrelated regions.
		data = append(data, 0)
		start := len(data)
		data = append(data, make([]byte, length)...)
		n, _ := r.ReadAt(data[start:], off)
		data = data[:start+n]
	}
	return data
}

// Read only the ELF structures needed to locate .rodata. Do not invoke a
// general object parser that can allocate from attacker-controlled counts.
func binaryRodata(r io.ReaderAt, size int64) (int64, int64) {
	if size < 0 {
		return 0, 0
	}
	var h [64]byte
	if _, err := r.ReadAt(h[:], 0); err != nil || !isELF(h[:]) {
		return 0, 0
	}
	var order binary.ByteOrder
	switch h[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return 0, 0
	}
	var table uint64
	var stride, count, names uint16
	switch h[4] {
	case 1:
		table = uint64(order.Uint32(h[32:36]))
		stride, count, names = order.Uint16(h[46:48]), order.Uint16(h[48:50]), order.Uint16(h[50:52])
		if stride != 40 {
			return 0, 0
		}
	case 2:
		table = order.Uint64(h[40:48])
		stride, count, names = order.Uint16(h[58:60]), order.Uint16(h[60:62]), order.Uint16(h[62:64])
		if stride != 64 {
			return 0, 0
		}
	default:
		return 0, 0
	}
	valid := func(off, n uint64) bool { return off <= uint64(size) && n <= uint64(size)-off } // #nosec G115 -- size is nonnegative; valid bounds each offset and length by the int64 file size.
	if count == 0 || count > 4096 || names >= count || !valid(table, uint64(stride)*uint64(count)) {
		return 0, 0
	}
	sections := make([]byte, int(stride)*int(count))
	if _, err := r.ReadAt(sections, int64(table)); err != nil { // #nosec G115 -- size is nonnegative; valid bounds each offset and length by the int64 file size.
		return 0, 0
	}
	sectionRange := func(s []byte) (uint64, uint64) {
		if h[4] == 1 {
			return uint64(order.Uint32(s[16:20])), uint64(order.Uint32(s[20:24]))
		}
		return order.Uint64(s[24:32]), order.Uint64(s[32:40])
	}
	off, n := sectionRange(sections[int(names)*int(stride):])
	if n > 64<<10 || !valid(off, n) {
		return 0, 0
	}
	stringsTable := make([]byte, n)
	if _, err := r.ReadAt(stringsTable, int64(off)); err != nil { // #nosec G115 -- size is nonnegative; valid bounds each offset and length by the int64 file size.
		return 0, 0
	}
	for i := 0; i < int(count); i++ {
		s := sections[i*int(stride):]
		name := uint64(order.Uint32(s[:4]))
		if name >= uint64(len(stringsTable)) || !bytes.HasPrefix(stringsTable[name:], []byte(".rodata\x00")) {
			continue
		}
		// Ignore NOBITS and compressed sections: neither holds plain strings.
		if order.Uint32(s[4:8]) != 1 {
			continue
		}
		flags := uint64(order.Uint32(s[8:12]))
		if h[4] == 2 {
			flags = order.Uint64(s[8:16])
		}
		if flags&0x800 != 0 {
			continue
		}
		off, n = sectionRange(s)
		if valid(off, n) {
			return int64(off), int64(n) // #nosec G115 -- size is nonnegative; valid bounds each offset and length by the int64 file size.
		}
	}
	return 0, 0
}

var binaryJavaVersion = regexp.MustCompile(`^[0-9]+(?:[._][0-9]+)*(?:\+[0-9]+)?$`)

func binaryJavaRelease(r io.ReaderAt, size int64, source string) []Package {
	if size <= 0 || size > maxJavaReleaseBytes {
		return nil
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, 0); err != nil {
		return nil
	}
	values := keyValues(data, "=")
	version := trimQuotes(strings.TrimSpace(values["JAVA_VERSION"]))
	if !binaryJavaVersion.MatchString(version) {
		return nil
	}
	implementor := strings.ToLower(trimQuotes(strings.TrimSpace(values["IMPLEMENTOR"])))
	name, vendor, product := "openjdk", "oracle", "openjdk"
	if strings.Contains(implementor, "eclipse") || strings.Contains(implementor, "adoptium") || strings.Contains(implementor, "temurin") {
		name, vendor, product = "temurin", "eclipse", "temurin"
	}
	// '+' is legal in a Java version but must be quoted in a CPE attribute.
	p := binaryPackage(name, version, vendor, product, source, "")
	p.CPE = strings.ReplaceAll(p.CPE, "+", `\+`)
	return []Package{p}
}
