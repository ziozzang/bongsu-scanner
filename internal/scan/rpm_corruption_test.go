package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRPMHeaderFieldsAndCorruption(t *testing.T) {
	b := rpmTestHeader(2)
	for _, blob := range [][]byte{b, append([]byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0}, b...)} {
		h, err := parseRPMHeader(blob)
		if err != nil || h.Epoch != 2 || h.Size != 12345 || h.Summary != "Example summary" || h.Vendor != "Example vendor" {
			t.Fatalf("header=%+v error=%v", h, err)
		}
	}
	for i := 0; i < len(b); i++ {
		if _, err := parseRPMHeader(b[:i]); err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"index count", func(b []byte) { binary.BigEndian.PutUint32(b, ^uint32(0)) }},
		{"store size", func(b []byte) { binary.BigEndian.PutUint32(b[4:], ^uint32(0)) }},
		{"tag offset", func(b []byte) { binary.BigEndian.PutUint32(b[16:], ^uint32(0)) }},
		{"string count", func(b []byte) { binary.BigEndian.PutUint32(b[20:], ^uint32(0)) }},
		{"wrong string type", func(b []byte) { binary.BigEndian.PutUint32(b[12:], 4) }},
		{"missing terminator", func(b []byte) { b[len(b)-1] = 'x' }},
		{"wrong epoch type", func(b []byte) { binary.BigEndian.PutUint32(b[8+3*16+4:], 6) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := bytes.Clone(b)
			tc.mutate(bad)
			if _, err := parseRPMHeader(bad); err == nil {
				t.Fatal("accepted corrupt header")
			}
		})
	}
	for _, src := range []string{"with-dashes-1.0-2.src.rpm", "with-dashes-1.0-2.nosrc.rpm"} {
		p := (rpmHeader{Name: "binary", Version: "2", Release: "3", SourceRPM: src}).pkg("db", "")
		if p.SourceName != "with-dashes" || p.SourceVersion != "1.0-2" {
			t.Fatal(p)
		}
	}
	if p := (rpmHeader{Name: "binary", Version: "1", Release: "2", SourceRPM: "(none)"}).pkg("", ""); p.SourceName != "" {
		t.Fatal(p)
	}
}

func TestRPMDatabasePartialResults(t *testing.T) {
	good, bad := rpmTestHeader(0), []byte("bad")
	sqlite, err := os.ReadFile(rpmTestSQLite(t, bad, good, nil))
	if err != nil {
		t.Fatal(err)
	}
	bdb := rpmTestBDB(good, binary.LittleEndian, true)
	// Append a malformed hash page after the valid record's overflow page.
	pg := make([]byte, 512)
	pg[25] = 13
	binary.LittleEndian.PutUint32(pg[8:], uint32(len(bdb)/512))
	binary.LittleEndian.PutUint16(pg[20:], 65535)
	bdb = append(bdb, pg...)
	binary.LittleEndian.PutUint32(bdb[32:], uint32(len(bdb)/512-1))
	ndb := rpmTestNDB(good)
	ndb[48] = 'X' // independent malformed slot
	for _, tc := range []struct {
		path   string
		data   []byte
		errors int
	}{
		{"var/lib/rpm/rpmdb.sqlite", sqlite, 2}, {"var/lib/rpm/Packages", bdb, 1}, {"var/lib/rpm/Packages.db", ndb, 1},
	} {
		t.Run(tc.path, func(t *testing.T) {
			var packages []Package
			count := scanRPMDatabase(File{Path: tc.path, Data: tc.data}, "", func(p Package) { packages = append(packages, p) })
			if len(packages) != 1 || count != tc.errors {
				t.Fatalf("packages=%+v errors=%d", packages, count)
			}
		})
	}
}

func TestRPMSQLiteReadOnlyPathAndCleanup(t *testing.T) {
	p := rpmTestSQLite(t, rpmTestHeader(0))
	// URI delimiters in a real pathname must not become SQLite options.
	weird := filepath.Join(filepath.Dir(p), "rpm ?#&mode=rw.sqlite")
	if err := os.Rename(p, weird); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(weird)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(weird, 0400); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	for _, disk := range []string{weird, ""} {
		n := 0
		if count := scanRPMDatabase(File{Path: "var/lib/rpm/rpmdb.sqlite", Data: b}, disk, func(Package) { n++ }); count != 0 || n != 1 {
			t.Fatalf("errors=%d packages=%d", count, n)
		}
	}
	after, err := os.ReadFile(weird)
	if err != nil || !bytes.Equal(b, after) {
		t.Fatal("source database modified", err)
	}
	if n := scanRPMDatabase(File{Path: "var/lib/rpm/rpmdb.sqlite", Data: []byte("broken")}, "", func(Package) { t.Fatal("corrupt DB emitted package") }); n == 0 {
		t.Fatal("missing error")
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary files remain %v %v", entries, err)
	}
	entries, err = os.ReadDir(filepath.Dir(weird))
	if err != nil || len(entries) != 1 {
		t.Fatalf("unexpected WAL/journal files %v %v", entries, err)
	}
}

func TestRPMBDBOverflowDefenses(t *testing.T) {
	// Exercise a multi-page chain, both endian orders, and legacy hash pages.
	blob := rpmTestHeader(0)
	// The header store can include unreferenced padding.
	padding := bytes.Repeat([]byte{0}, 1100)
	binary.BigEndian.PutUint32(blob[4:], binary.BigEndian.Uint32(blob[4:])+uint32(len(padding)))
	blob = append(blob, padding...)
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		valid := rpmTestBDB(blob, order, true)
		valid[512+25] = 2
		for _, tc := range []struct {
			name   string
			mutate func([]byte)
		}{
			{"valid", func([]byte) {}},
			{"cycle", func(b []byte) { order.PutUint32(b[1024+16:], 2) }},
			{"outside file", func(b []byte) { order.PutUint32(b[1024+16:], 9999) }},
			{"wrong page type", func(b []byte) { b[1024+25] = 13 }},
			{"bad value offset", func(b []byte) { order.PutUint16(b[512+28:], 65535) }},
			{"oversized value", func(b []byte) { off := int(order.Uint16(b[512+28:])); order.PutUint32(b[512+off+8:], ^uint32(0)) }},
			{"bad page size", func(b []byte) { order.PutUint32(b[20:], ^uint32(0)) }},
		} {
			t.Run(fmt.Sprint(order)+tc.name, func(t *testing.T) {
				b := bytes.Clone(valid)
				tc.mutate(b)
				n := 0
				errors := scanRPMDatabase(File{Path: "var/lib/rpm/Packages", Data: b}, "", func(Package) { n++ })
				if tc.name == "valid" {
					if errors != 0 || n != 1 {
						t.Fatalf("errors=%d packages=%d", errors, n)
					}
				} else if errors == 0 || n != 0 {
					t.Fatalf("errors=%d packages=%d", errors, n)
				}
			})
		}
	}
}

func TestRPMNDBDefenses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"slot pages", func(b []byte) { binary.LittleEndian.PutUint32(b[12:], ^uint32(0)) }},
		{"slot offset", func(b []byte) { binary.LittleEndian.PutUint32(b[40:], ^uint32(0)) }},
		{"slot size", func(b []byte) { binary.LittleEndian.PutUint32(b[44:], ^uint32(0)) }},
		{"blob size", func(b []byte) { binary.LittleEndian.PutUint32(b[4096+12:], ^uint32(0)) }},
		{"checksum", func(b []byte) { b[4096+30] ^= 1 }},
		{"trailer", func(b []byte) { b[len(b)-1] = 'X' }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := rpmTestNDB(rpmTestHeader(0))
			tc.mutate(b)
			n := 0
			count := scanRPMDatabase(File{Path: "var/lib/rpm/Packages.db", Data: b}, "", func(Package) { n++ })
			if count == 0 || n != 0 {
				t.Fatalf("errors=%d packages=%d", count, n)
			}
		})
	}
}

func TestRPMWalkCapsHashesAndCorruption(t *testing.T) {
	smallRPMTestLimits(t)
	testRPMWalkCapsHashesAndCorruption(t)
}

func testRPMWalkCapsHashesAndCorruption(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int64
		broken bool
	}{
		{"small", 0, false}, {"large", maxFileMetadata + 4096, false}, {"cap", maxRPMDatabase, false}, {"oversized", maxRPMDatabase + 1, false}, {"corrupt", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			rel := "var/lib/rpm/Packages.db"
			b := rpmTestNDB(rpmTestHeader(0))
			if tc.broken {
				b[48] = 'X'
			}
			writeTree(t, root, map[string]string{rel: string(b)})
			p := filepath.Join(root, rel)
			if tc.size > 0 {
				f, err := os.OpenFile(p, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				err = f.Truncate(tc.size)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			r, err := DirectoryContext(context.Background(), root, "test", Options{SkipBinaries: true, IncludeFileHashes: tc.size == 0, MaxTotalBytes: 1})
			if err != nil {
				t.Fatal(err)
			}
			if tc.size > maxRPMDatabase {
				if len(r.Packages) != 0 || r.Scan.MetadataSkipped != 1 {
					t.Fatalf("%+v", r.Scan)
				}
				return
			}
			if len(r.Packages) != 1 || r.Scan.MetadataSkipped != 0 || r.Scan.Partial != tc.broken {
				t.Fatalf("packages=%+v scan=%+v", r.Packages, r.Scan)
			}
			if tc.broken && r.Scan.SkippedErrors != 1 {
				t.Fatal(r.Scan)
			}
			if tc.size == 0 {
				if len(r.Files) != 1 || r.Files[0].SHA256 != fmt.Sprintf("%x", sha256.Sum256(b)) || len(r.Files[0].Data) != 0 {
					t.Fatalf("files=%+v", r.Files)
				}
			}
		})
	}
}

func TestRPMCatalogEpochAndLateDistro(t *testing.T) {
	var c cataloger
	for _, epoch := range []uint32{0, 2} {
		b := rpmTestNDB(rpmTestHeader(epoch))
		c.addFile(File{Path: "var/lib/rpm/Packages.db", Data: b})
		c.addFile(File{Path: "usr/lib/sysimage/rpm/Packages.db", Data: b})
	}
	c.addFile(File{Path: "usr/lib/os-release", Data: []byte("ID=fedora\nVERSION_ID=42")})
	c.addFile(File{Path: "etc/os-release", Data: []byte("ID=almalinux\nVERSION_ID=9.4")})
	pkgs, _ := c.finish()
	if len(pkgs) != 2 {
		t.Fatalf("different epochs collapsed: %+v", pkgs)
	}
	for _, p := range pkgs {
		if p.Namespace != "almalinux" || !strings.Contains(p.Source, ";") || !strings.Contains(p.PURL, "distro=almalinux-9.4") {
			t.Fatal(p)
		}
	}
	p := Package{Type: "rpm", Namespace: "fedora", Name: "LibX", Version: "0:1:2-3", SourceName: "Source", SourceVersion: "4-5"}
	if got, want := buildPURL(p), "pkg:rpm/fedora/LibX@1:2-3?upstream=Source%404-5"; got != want {
		t.Fatalf("%s != %s", got, want)
	}
}

func FuzzRPMHeader(f *testing.F) {
	f.Add(rpmTestHeader(0))
	f.Add([]byte("broken"))
	f.Fuzz(func(t *testing.T, b []byte) { parseRPMHeader(b) })
}

func TestRPMWalkPathScopeAndExclusion(t *testing.T) {
	for _, excluded := range []bool{false, true} {
		t.Run(fmt.Sprint(excluded), func(t *testing.T) {
			root := t.TempDir()
			b := rpmTestNDB(rpmTestHeader(0))
			writeTree(t, root, map[string]string{"var/lib/rpm/Packages.db": string(b), "nested/var/lib/rpm/Packages.db": string(b), "tmp/Packages.db": string(b)})
			opts := Options{SkipBinaries: true}
			if excluded {
				opts.Exclude = []string{"var/lib/rpm"}
			}
			r, err := DirectoryContext(context.Background(), root, "test", opts)
			want := 1
			if excluded {
				want = 0
			}
			if err != nil || len(r.Packages) != want {
				t.Fatalf("packages=%+v error=%v", r.Packages, err)
			}
		})
	}
}
