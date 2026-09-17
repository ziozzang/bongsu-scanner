package scan

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBinaryClassifierSignatures(t *testing.T) {
	for _, tc := range []struct{ file, text, name, version, cpe string }{
		{"python3", "Python 3.12.14", "python", "3.12.14", "python:python"},
		{"libpython3.12.so", "3.12.14 (main, today)", "python", "3.12.14", "python:python"},
		{"python3", "embedded banner: 3.12.14 (main, today)", "python", "3.12.14", "python:python"},
		{"python3.13", "Py_GetVersion\x003.13.5\x00", "python", "3.13.5", "python:python"},
		{"libpython3.10.so.1.0", "Py_GetVersion\x003.5.3\x003.10.18\x003.2.0\x00", "python", "3.10.18", "python:python"},
		{"node", "node/v22.12.0", "node", "22.12.0", "nodejs:node.js"},
		{"ruby", "ruby 3.3.5p100", "ruby", "3.3.5", "ruby-lang:ruby"},
		{"libruby.so.3", "RUBY_VERSION=\"3.3.5\"", "ruby", "3.3.5", "ruby-lang:ruby"},
		{"libssl.so.3", "OpenSSL 3.0.13 30 Jan 2024", "openssl", "3.0.13", "openssl:openssl"},
		{"openssl", "OpenSSL 1.1.1w 11 Sep 2023", "openssl", "1.1.1w", "openssl:openssl"},
		{"busybox", "BusyBox v1.36.1", "busybox", "1.36.1", "busybox:busybox"},
		{"php", "X-Powered-By: PHP/8.3.1", "php", "8.3.1", "php:php"},
		{"php8.3", "PHP Version 8.3.1", "php", "8.3.1", "php:php"},
		{"perl", "/usr/local/lib/perl5/5.40.0", "perl", "5.40.0", "perl:perl"},
		{"perl", "This is perl 5, version 40", "perl", "5.40.0", "perl:perl"},
		{"perl", "This is perl 5, version 40, subversion 2", "perl", "5.40.2", "perl:perl"},
		{"nginx", "nginx/1.27.0", "nginx", "1.27.0", "f5:nginx"},
		{"httpd", "Apache/2.4.62", "httpd", "2.4.62", "apache:http_server"},
		{"redis-server", "Redis version 7.2.4", "redis", "7.2.4", "redis:redis"},
		{"redis-server", "redis_version:7.2.4", "redis", "7.2.4", "redis:redis"},
		{"postgres", "PostgreSQL 16.4", "postgres", "16.4", "postgresql:postgresql"},
		{"mysqld", "MySQL 8.0.39", "mysql", "8.0.39", "oracle:mysql"},
		{"mariadbd", "11.4.2-MariaDB", "mariadb", "11.4.2", "mariadb:mariadb"},
		{"mysqld", "MySQL 8.0.39\x0011.4.2-MariaDB", "mariadb", "11.4.2", "mariadb:mariadb"},
		{"curl", "curl 8.9.1", "curl", "8.9.1", "haxx:curl"},
		{"libsqlite3.so.0", "sqlite3_libversion\x003.46.1", "sqlite", "3.46.1", "sqlite:sqlite"},
		{"libz.so.1", "deflate\x001.3.1", "zlib", "1.3.1", "zlib:zlib"},
		{"libc.so.6", "GNU C Library (GNU libc) stable release version 2.40.", "glibc", "2.40", "gnu:glibc"},
		{"libc.so.6", "GNU C Library (Debian GLIBC 2.41-12) stable release version 2.41.", "glibc", "2.41", "gnu:glibc"},
		{"ld-musl-x86_64.so.1", "musl libc (x86_64)\nVersion 1.2.5", "musl", "1.2.5", "musl-libc:musl"},
		{"bash", "GNU bash, version 5.2.32", "bash", "5.2.32", "gnu:bash"},
	} {
		t.Run(tc.file+"/"+tc.version, func(t *testing.T) {
			data := []byte("\x7fELF\x00" + tc.text + "\x00")
			pkgs := binaryPackages(bytes.NewReader(data), int64(len(data)), "usr/bin/"+tc.file, "layer")
			if len(pkgs) != 1 {
				t.Fatalf("packages = %+v", pkgs)
			}
			p := pkgs[0]
			if p.Name != tc.name || p.Version != tc.version || p.Type != "generic" || p.Evidence != "binary" || p.Source != "usr/bin/"+tc.file || p.Layer != "layer" || p.PURL != "pkg:generic/"+tc.name+"@"+tc.version || p.CPE != "cpe:2.3:a:"+tc.cpe+":"+tc.version+":*:*:*:*:*:*:*" {
				t.Fatalf("package = %+v", p)
			}
		})
	}
}

func TestBinaryClassifierRejectsWeakEvidence(t *testing.T) {
	for _, tc := range []struct{ file, data string }{
		{"libz.so.1", "\x7fELF\x001.3.1\x00"},
		{"libunrelated.so", "\x7fELF\x00deflate\x001.3.1\x00"},
		{"libsqlite3.so", "\x7fELF\x003.46.1\x00"},
		{"python3", "\x7fELF\x003.12.14\x00"},
		{"libssl.so.3", "\x7fELF\x00OPENSSL_3.5.0\x00OpenSSL/%s"},
		{"python3", "\x7fELF\x00Py_GetVersion\x003.5.3\x003.10.18\x00"},
		{"libpython3.10.so", "\x7fELF\x00Py_GetVersion\x003.5.3\x00"},
		{"sqlite3", "\x7fELF\x00sqlite3_libversion\x001.3.1\x00"},
		{"libsqlite3.so", "\x7fELF\x00sqlite3_libversion\x003.40.0\x003.46.1\x00"},
		{"libmariadb.so.3", "\x7fELF\x00MariaDB\x003.4.9\x00"},
		{"curl", "#!/bin/sh\ncurl 8.9.1\n"},
		{"curl", "\x7fELF\x00curl 8.9.123.4\x00"},
	} {
		if got := binaryPackages(strings.NewReader(tc.data), int64(len(tc.data)), tc.file, ""); len(got) != 0 {
			t.Errorf("%q: %+v", tc, got)
		}
	}
	if got := binaryPackages(nil, 1, "curl", ""); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestBinaryClassifierNativeFormats(t *testing.T) {
	for _, magic := range []string{"\x7fELF", "MZ\x90\x00", "\xcf\xfa\xed\xfe", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xfe\xed\xfa\xce"} {
		data := magic + "\x00curl 8.9.1\x00"
		if got := binaryPackages(strings.NewReader(data), int64(len(data)), "curl", ""); len(got) != 1 {
			t.Errorf("magic %x: %+v", magic, got)
		}
	}
}

type binaryCountingReader struct {
	io.ReaderAt
	read int
}

func (r *binaryCountingReader) ReadAt(b []byte, off int64) (int, error) {
	r.read += len(b)
	return r.ReaderAt.ReadAt(b, off)
}

func TestBinaryClassifierReadBounds(t *testing.T) {
	data := make([]byte, maxBinaryScanBytes+256)
	copy(data, "\x7fELF")
	copy(data[maxBinaryScanBytes:], "curl 8.9.1\x00")
	r := &binaryCountingReader{ReaderAt: bytes.NewReader(data)}
	if got := binaryPackages(r, int64(len(data)), "curl", ""); len(got) != 0 {
		t.Fatal("read outside prefix", got)
	}
	if r.read > maxBinaryScanBytes+68 {
		t.Fatalf("read %d bytes", r.read)
	}
	r.read = 0
	if got := binaryPackages(r, maxGoBinary+1, "curl", ""); len(got) != 0 || r.read != 0 {
		t.Fatal("oversize input read")
	}
}

func TestBinaryClassifierRodata(t *testing.T) {
	for _, class := range []byte{1, 2} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			data := make([]byte, maxBinaryScanBytes+512)
			copy(data, "\x7fELF")
			data[4], data[5] = class, 1
			if order == binary.BigEndian {
				data[5] = 2
			}
			stride := 64
			if class == 1 {
				stride = 40
				order.PutUint32(data[32:], 128)
				order.PutUint16(data[46:], 40)
				order.PutUint16(data[48:], 3)
				order.PutUint16(data[50:], 1)
			} else {
				order.PutUint64(data[40:], 128)
				order.PutUint16(data[58:], 64)
				order.PutUint16(data[60:], 3)
				order.PutUint16(data[62:], 1)
			}
			setSection := func(i int, off, size uint64) {
				s := data[128+i*stride:]
				order.PutUint32(s[4:], 1)
				if class == 1 {
					order.PutUint32(s[16:], uint32(off))
					order.PutUint32(s[20:], uint32(size))
				} else {
					order.PutUint64(s[24:], off)
					order.PutUint64(s[32:], size)
				}
			}
			copy(data[400:], "\x00.rodata\x00")
			setSection(1, 400, 9)
			setSection(2, maxBinaryScanBytes+128, 128)
			order.PutUint32(data[128+2*stride:], 1)
			copy(data[maxBinaryScanBytes+128:], "curl 8.9.1\x00")
			r := &binaryCountingReader{ReaderAt: bytes.NewReader(data)}
			got := binaryPackages(r, int64(len(data)), "curl", "")
			if len(got) != 1 || got[0].Version != "8.9.1" {
				t.Fatalf("class=%d, order=%v: %+v", class, order, got)
			}
			if r.read > maxBinaryScanBytes+4096 {
				t.Fatalf("read %d", r.read)
			}
			// A malicious section offset must not wrap into a valid range.
			setSection(2, ^uint64(0)-1, 128)
			if off, n := binaryRodata(bytes.NewReader(data), int64(len(data))); off != 0 || n != 0 {
				t.Fatalf("invalid section: %d %d", off, n)
			}
		}
	}
}

func TestBinaryProbeBudgetConcurrent(t *testing.T) {
	var b binaryProbeBudget
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range maxClassifiedBinaries {
				if b.take() {
					accepted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != maxClassifiedBinaries {
		t.Fatal(accepted.Load())
	}
	var next binaryProbeBudget
	if !next.take() {
		t.Fatal("budget leaked between scans")
	}
}

func TestBinaryJavaRelease(t *testing.T) {
	for _, tc := range []struct{ data, name, version, cpe string }{
		{"JAVA_VERSION=\"17.0.12\"\nIMPLEMENTOR=\"Oracle Corporation\"\n", "openjdk", "17.0.12", "oracle:openjdk:17.0.12"},
		{"JAVA_VERSION=\"21.0.4+7\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n", "temurin", "21.0.4+7", `eclipse:temurin:21.0.4\+7`},
		{"JAVA_VERSION=\"1.8.0_422\"\nIMPLEMENTOR=\"OpenJDK\"\n", "openjdk", "1.8.0_422", "oracle:openjdk:1.8.0_422"},
		{"JAVA_VERSION=\"bad:*:version\"\n", "", "", ""},
	} {
		got := binaryJavaRelease(strings.NewReader(tc.data), int64(len(tc.data)), "opt/jre/release")
		if tc.name == "" {
			if len(got) != 0 {
				t.Fatal(got)
			}
			continue
		}
		if len(got) != 1 || got[0].Name != tc.name || got[0].Version != tc.version || got[0].CPE != "cpe:2.3:a:"+tc.cpe+":*:*:*:*:*:*:*" {
			t.Fatal(got)
		}
	}
}

func TestBinaryClassifierHost(t *testing.T) {
	for _, tc := range []struct {
		file, name, command, expression string
		args                            []string
	}{
		{"/usr/bin/python3", "python", "/usr/bin/python3", `Python ([0-9]+\.[0-9]+\.[0-9]+)`, []string{"--version"}},
		{"/usr/bin/openssl", "openssl", "/usr/bin/openssl", `OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)`, []string{"version"}},
		{"/usr/bin/curl", "curl", "/usr/bin/curl", `curl ([0-9]+\.[0-9]+\.[0-9]+)`, []string{"--version"}},
		{"/usr/lib/x86_64-linux-gnu/libssl.so.3", "openssl", "/usr/bin/openssl", `OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)`, []string{"version"}},
		{"/usr/lib/x86_64-linux-gnu/libcrypto.so.3", "openssl", "/usr/bin/openssl", `OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)`, []string{"version"}},
		{"/lib/x86_64-linux-gnu/libc.so.6", "glibc", "/lib/x86_64-linux-gnu/libc.so.6", `stable release version ([0-9]+\.[0-9]+)`, nil},
	} {
		t.Run(tc.file, func(t *testing.T) {
			f, err := os.Open(tc.file)
			if err != nil {
				t.Skip(err)
			}
			defer f.Close()
			st, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(tc.command, tc.args...).CombinedOutput()
			if err != nil {
				t.Skipf("host version command unavailable: %v", err)
			}
			m := regexp.MustCompile(tc.expression).FindSubmatch(out)
			if len(m) < 2 {
				t.Fatalf("version output: %s", out)
			}
			// Walks catalog the regular target (python3.13), not its symlink
			// alias (python3); retain that ABI hint in this direct host check.
			source, err := filepath.EvalSymlinks(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			got := binaryPackages(f, st.Size(), source, "")
			if len(got) == 0 && strings.Contains(tc.file, "libssl") {
				b, _ := io.ReadAll(io.LimitReader(f, maxBinaryScanBytes))
				if !regexp.MustCompile(`OpenSSL [0-9]+\.[0-9]+\.[0-9]+`).Match(b) {
					t.Skip("libssl contains ABI versions only; cannot infer its installed patch version from its bytes")
				}
			}
			if len(got) != 1 || got[0].Name != tc.name || got[0].Version != string(m[1]) {
				t.Fatalf("packages=%+v; version command=%s", got, out)
			}
		})
	}
}

func TestGoBinaryEvidence(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	pkgs := goBinaryPackages(f, st.Size(), path, "")
	if len(pkgs) == 0 {
		t.Fatal("no Go build info")
	}
	for _, p := range pkgs {
		if p.Evidence != "binary" {
			t.Fatalf("missing evidence: %+v", p)
		}
	}
}
