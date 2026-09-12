package scan

import (
	"context"
	"database/sql"
	"encoding/binary"
	"hash/adler32"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// RPM database blobs omit the eight-byte header magic used by .rpm files.
func rpmTestHeader(epoch uint32) []byte {
	tags := []struct {
		tag, typ uint32
		value    []byte
	}{
		{1000, 6, []byte("Lib-example\x00")}, {1001, 6, []byte("1.2\x00")},
		{1002, 6, []byte("3.el9\x00")}, {1003, 4, binary.BigEndian.AppendUint32(nil, epoch)},
		{1022, 6, []byte("x86_64\x00")}, {1044, 6, []byte("example-src-1.2-3.el9.src.rpm\x00")},
		{1014, 6, []byte("MIT\x00")}, {1004, 9, []byte("Example summary\x00")},
		{1009, 4, binary.BigEndian.AppendUint32(nil, 12345)}, {1011, 6, []byte("Example vendor\x00")},
	}
	var index, data []byte
	for _, tag := range tags {
		if tag.typ == 4 {
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
		}
		for _, n := range []uint32{tag.tag, tag.typ, uint32(len(data)), 1} {
			index = binary.BigEndian.AppendUint32(index, n)
		}
		data = append(data, tag.value...)
	}
	b := binary.BigEndian.AppendUint32(nil, uint32(len(tags)))
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	return append(append(b, index...), data...)
}

func rpmTestSQLite(t *testing.T, blobs ...[]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rpmdb.sqlite")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)"); err != nil {
		t.Fatal(err)
	}
	for i, b := range blobs {
		if _, err = db.Exec("INSERT INTO Packages VALUES (?, ?)", i+1, b); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func rpmTestBDB(blob []byte, order binary.ByteOrder, overflow bool) []byte {
	const size = 512
	npages := 2
	if overflow {
		npages += (len(blob) + size - 27) / (size - 26)
	}
	b := make([]byte, size*npages)
	order.PutUint32(b[12:], 0x00061561)
	order.PutUint32(b[16:], 9)
	order.PutUint32(b[20:], size)
	b[25] = 8
	order.PutUint32(b[32:], uint32(npages-1))
	p := b[size : 2*size]
	order.PutUint32(p[8:], 1)
	order.PutUint16(p[20:], 2)
	p[25] = 13
	key := size - 5
	order.PutUint16(p[26:], uint16(key))
	p[key] = 1
	order.PutUint32(p[key+1:], 1)
	value := key - 1 - len(blob)
	if overflow {
		value = key - 12
	}
	order.PutUint16(p[28:], uint16(value))
	order.PutUint16(p[22:], uint16(value))
	if !overflow {
		p[value] = 1
		copy(p[value+1:key], blob)
		return b
	}
	p[value] = 3
	order.PutUint32(p[value+4:], 2)
	order.PutUint32(p[value+8:], uint32(len(blob)))
	for i := 2; i < npages; i++ {
		p = b[i*size : (i+1)*size]
		order.PutUint32(p[8:], uint32(i))
		if i+1 < npages {
			order.PutUint32(p[16:], uint32(i+1))
		}
		p[25] = 7
		n := min(len(blob), size-26)
		order.PutUint16(p[22:], uint16(n))
		copy(p[26:], blob[:n])
		blob = blob[n:]
	}
	return b
}

func rpmTestNDB(blob []byte) []byte {
	n := (len(blob) + 28 + 15) / 16 * 16
	b := make([]byte, 4096+n)
	copy(b, "RpmP")
	binary.LittleEndian.PutUint32(b[12:], 1)
	for off := 32; off < 4096; off += 16 {
		copy(b[off:], "Slot")
	}
	binary.LittleEndian.PutUint32(b[36:], 1)
	binary.LittleEndian.PutUint32(b[40:], 256)
	binary.LittleEndian.PutUint32(b[44:], uint32(n/16))
	p := b[4096:]
	copy(p, "BlbS")
	binary.LittleEndian.PutUint32(p[4:], 1)
	binary.LittleEndian.PutUint32(p[12:], uint32(len(blob)))
	copy(p[16:], blob)
	binary.LittleEndian.PutUint32(p[n-12:], adler32.Checksum(p[:n-12]))
	binary.LittleEndian.PutUint32(p[n-8:], uint32(len(blob)))
	copy(p[n-4:], "BlbE")
	return b
}

func TestRPMCatalogBackends(t *testing.T) {
	blob := rpmTestHeader(2)
	sqlite, err := os.ReadFile(rpmTestSQLite(t, blob))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		data []byte
	}{
		{"var/lib/rpm/rpmdb.sqlite", sqlite}, {"usr/lib/sysimage/rpm/rpmdb.sqlite", sqlite},
		{"var/lib/rpm/Packages", rpmTestBDB(blob, binary.LittleEndian, false)},
		{"var/lib/rpm/Packages", rpmTestBDB(blob, binary.BigEndian, true)},
		{"var/lib/rpm/Packages.db", rpmTestNDB(blob)},
	} {
		t.Run(tc.path, func(t *testing.T) {
			pkgs, _ := catalog([]File{{Path: tc.path, Data: tc.data, Layer: "layer"}, {Path: "etc/os-release", Data: []byte("ID=rocky\nVERSION_ID=9.4\n")}}, nil)
			if len(pkgs) != 1 {
				t.Fatalf("packages = %+v", pkgs)
			}
			p := pkgs[0]
			if p.Type != "rpm" || p.Name != "Lib-example" || p.Version != "2:1.2-3.el9" || p.License != "MIT" || p.Arch != "x86_64" || p.SourceName != "example-src" || p.SourceVersion != "1.2-3.el9" || p.Namespace != "rocky" || p.Distro != "rocky-9.4" || p.Source != tc.path || p.Layer != "layer" {
				t.Fatalf("package = %+v", p)
			}
			want := "pkg:rpm/rocky/Lib-example@1.2-3.el9?arch=x86_64&distro=rocky-9.4&epoch=2&upstream=example-src"
			if p.PURL != want {
				t.Fatalf("purl = %s, want %s", p.PURL, want)
			}
		})
	}
}

func TestRPMWalkPrepassLargeDatabase(t *testing.T) {
	for _, rel := range []string{"var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "var/lib/rpm/Packages.db"} {
		t.Run(rel, func(t *testing.T) {
			root := t.TempDir()
			var b []byte
			switch filepath.Base(rel) {
			case "rpmdb.sqlite":
				var err error
				b, err = os.ReadFile(rpmTestSQLite(t, rpmTestHeader(0)))
				if err != nil {
					t.Fatal(err)
				}
			case "Packages":
				b = rpmTestBDB(rpmTestHeader(0), binary.LittleEndian, true)
			case "Packages.db":
				b = rpmTestNDB(rpmTestHeader(0))
			}
			writeTree(t, root, map[string]string{rel: string(b), "etc/os-release": "ID=rocky\nVERSION_ID=9.4\n", "aaa/package-lock.json": `{"dependencies":{"noise":{"version":"1"}}}`})
			f, err := os.OpenFile(filepath.Join(root, rel), os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Truncate(17 << 20); err != nil {
				t.Fatal(err)
			}
			f.Close()
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			r, err := DirectoryContext(context.Background(), root, "test", Options{SkipBinaries: true, MaxTotalBytes: 1})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Packages) != 1 || r.Packages[0].Name != "Lib-example" || r.Packages[0].Version != "1.2-3.el9" || r.Scan.MetadataSkipped != 1 {
				t.Fatalf("packages=%+v scan=%+v", r.Packages, r.Scan)
			}
			entries, err := os.ReadDir(tmp)
			if err != nil || len(entries) != 0 {
				t.Fatalf("temporary files remain: %v %v", entries, err)
			}
		})
	}
}

func TestRPMPURLRules(t *testing.T) {
	p := Package{Type: "rpm", Namespace: "Rocky", Name: "LibX", Version: "3:1.0-2", Arch: "noarch", Distro: "rocky-9.4", SourceName: "LibX", SourceVersion: "1.0-2"}
	if got, want := buildPURL(p), "pkg:rpm/rocky/LibX@1.0-2?arch=noarch&distro=rocky-9.4&epoch=3&upstream=LibX"; got != want {
		t.Fatalf("%s != %s", got, want)
	}
}
