package scan

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func ownershipHeader() []byte {
	return rpmHeaderWithTags([]struct {
		tag, typ, count uint32
		value           []byte
	}{
		{1000, 6, 1, []byte("python3-idna\x00")}, {1001, 6, 1, []byte("2.5\x00")}, {1002, 6, 1, []byte("8.el8_10\x00")},
		{5096, 6, 1, []byte("python38:3.8:123:abcd\x00")},
		{1117, 8, 2, []byte("idna-2.5.egg-info\x00unrelated.py\x00")},
		{1118, 8, 1, []byte("/usr/lib/python/site-packages/\x00")},
		{1116, 4, 2, binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), 0)},
	})
}
func TestDistroRPMHeader(t *testing.T) {
	h, err := parseRPMHeader(ownershipHeader())
	if err != nil {
		t.Fatal(err)
	}
	v := reflect.ValueOf(h)
	if got := v.FieldByName("Modularity"); !got.IsValid() || got.String() != "python38:3.8:123:abcd" {
		t.Fatalf("modularity missing: %+v", h)
	}
	if got := v.FieldByName("Files"); !got.IsValid() || !reflect.DeepEqual(got.Interface(), []string{"usr/lib/python/site-packages/idna-2.5.egg-info"}) {
		t.Fatalf("metadata paths missing: %+v", h)
	}
}
func TestDistroOwnerWalkOrders(t *testing.T) {
	metadata := File{Path: "usr/lib/python/site-packages/idna-2.5.egg-info", Data: []byte("Name: idna\nVersion: 2.5\n")}
	for _, typ := range []string{"rpm", "deb", "apk"} {
		for _, reverse := range []bool{false, true} {
			t.Run(typ+map[bool]string{false: "/db-first", true: "/metadata-first"}[reverse], func(t *testing.T) {
				c := cataloger{}
				db := func() {
					switch typ {
					case "rpm":
						if n := c.addRPMFile(File{Path: "var/lib/rpm/rpmdb.sqlite"}, rpmTestSQLite(t, ownershipHeader())); n != 0 {
							t.Fatal(n)
						}
					case "deb":
						c.addFile(File{Path: "var/lib/dpkg/info/python3-idna:amd64.list", Data: []byte("/" + metadata.Path + "\n/usr/bin/ignored\n")})
						c.addFile(File{Path: "var/lib/dpkg/status", Data: []byte("Package: python3-idna\nVersion: 2.5-8.el8_10\nArchitecture: amd64\nStatus: install ok installed\n\n")})
					case "apk":
						c.addFile(File{Path: "lib/apk/db/installed", Data: []byte("P:python3-idna\nV:2.5-8.el8_10\nF:usr/lib/python/site-packages\nR:idna-2.5.egg-info\nR:ignored.py\n\n")})
					}
				}
				if reverse {
					c.addFile(metadata)
					db()
				} else {
					db()
					c.addFile(metadata)
				}
				pkgs, _ := c.finish()
				found := false
				for _, p := range pkgs {
					if p.Type == "pypi" {
						found = true
						got := reflect.ValueOf(p).FieldByName("Owner")
						if !got.IsValid() || got.String() != typ+":python3-idna@2.5-8.el8_10" {
							t.Fatalf("owner missing: %+v", p)
						}
					}
				}
				if !found {
					t.Fatal("inventory lost")
				}
			})
		}
	}
}

func TestDistroHeaderValidation(t *testing.T) {
	for _, tag := range []uint32{5096, 1116, 1117, 1118} {
		for _, kind := range []string{"offset", "count", "type", "duplicate"} {
			b := ownershipHeader()
			n := int(binary.BigEndian.Uint32(b))
			for i := 0; i < n; i++ {
				e := b[8+i*16 : 8+(i+1)*16]
				if binary.BigEndian.Uint32(e) != tag {
					continue
				}
				switch kind {
				case "offset":
					binary.BigEndian.PutUint32(e[8:], ^uint32(0))
				case "count":
					binary.BigEndian.PutUint32(e[12:], ^uint32(0))
				case "type":
					binary.BigEndian.PutUint32(e[4:], 7)
				case "duplicate":
					copy(b[8:24], e)
				}
				break
			}
			if _, err := parseRPMHeader(b); err == nil {
				t.Fatalf("tag=%d kind=%s accepted", tag, kind)
			}
		}
	}
	b := ownershipHeader()
	n := int(binary.BigEndian.Uint32(b))
	for i := 0; i < n; i++ {
		e := b[8+i*16 : 8+(i+1)*16]
		if binary.BigEndian.Uint32(e) == 1116 {
			off := int(binary.BigEndian.Uint32(e[8:]))
			binary.BigEndian.PutUint32(b[8+n*16+off:], 2)
		}
	}
	if _, err := parseRPMHeader(b); err == nil {
		t.Fatal("invalid directory index accepted")
	}
}

func TestDistroOwnershipPatternsAndLimits(t *testing.T) {
	for _, p := range []string{"usr/lib/x.dist-info/METADATA", "usr/lib/x.egg-info/PKG-INFO", "usr/lib/x.egg-info", "usr/lib/node_modules/@scope/x/package.json", "usr/lib/ruby/gems/3.0/specifications/x.gemspec"} {
		if !languageMetadataPath(p) {
			t.Errorf("metadata rejected: %s", p)
		}
	}
	for _, p := range []string{"usr/lib/x.py", "usr/lib/x.dist-info/RECORD", "app/package.json", "usr/lib/x.gemspec"} {
		if languageMetadataPath(p) {
			t.Errorf("nonmetadata accepted: %s", p)
		}
	}
	c := cataloger{}
	for i := 0; i < maxOwnedPaths+5; i++ {
		c.ownPath(fmt.Sprintf("usr/lib/%d.egg-info", i), "rpm:p@1")
	}
	if len(c.ownedPaths) != maxOwnedPaths {
		t.Fatal(len(c.ownedPaths))
	}
	c = cataloger{}
	c.ownedBytes = maxOwnedBytes
	c.ownPath("x.egg-info", "rpm:p@1")
	if len(c.ownedPaths) != 0 {
		t.Fatal("byte cap ignored")
	}
}

func TestDistroOwnerKeepsUnownedDuplicate(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		c := cataloger{}
		for i := 0; i < maxPackageSources+1; i++ {
			j := i
			if reverse {
				j = maxPackageSources - i
			}
			p := fmt.Sprintf("usr/lib/%d/x.egg-info", j)
			c.addFile(File{Path: p, Data: []byte("Name: x\nVersion: 1\n")})
			if j < maxPackageSources {
				c.ownPath(p, "rpm:x@1")
			}
		}
		pkgs, _ := c.finish()
		if len(pkgs) != 1 || pkgs[0].Owner != "" {
			t.Fatalf("unowned install suppressed: %+v", pkgs)
		}
	}
}

func BenchmarkDistroRPMHeader(b *testing.B) {
	data := ownershipHeader()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseRPMHeader(data); err != nil {
			b.Fatal(err)
		}
	}
}

func bulkOwnershipHeader(count int, metadata bool) []byte {
	base := []byte("ordinary.py\x00")
	if metadata {
		base = []byte("x.egg-info\x00")
	}
	return rpmHeaderWithTags([]struct {
		tag, typ, count uint32
		value           []byte
	}{
		{1000, 6, 1, []byte("example\x00")}, {1001, 6, 1, []byte("1\x00")}, {1002, 6, 1, []byte("1.el8\x00")},
		{1116, 4, uint32(count), make([]byte, 4*count)}, {1117, 8, uint32(count), bytes.Repeat(base, count)}, {1118, 8, 1, []byte("/usr/lib/python/\x00")},
	})
}
func TestDistroRPMRetention(t *testing.T) {
	for _, metadata := range []bool{false, true} {
		h, err := parseRPMHeader(bulkOwnershipHeader(200000, metadata))
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if metadata {
			want = maxOwnedPaths
		}
		if len(h.Files) != want {
			t.Fatalf("metadata=%t paths=%d want=%d", metadata, len(h.Files), want)
		}
	}
}
func BenchmarkDistroRPMHeader200K(b *testing.B) {
	data := bulkOwnershipHeader(200000, false)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, err := parseRPMHeader(data); err != nil {
			b.Fatal(err)
		}
	}
}
func TestDistroRPMDatabaseOwners(t *testing.T) {
	for _, kind := range []string{"bdb", "ndb"} {
		c := cataloger{}
		f := File{Path: "var/lib/rpm/Packages", Data: rpmTestBDB(ownershipHeader(), binary.LittleEndian, true)}
		if kind == "ndb" {
			f.Path = "var/lib/rpm/Packages.db"
			f.Data = rpmTestNDB(ownershipHeader())
		}
		c.addFile(f)
		c.addFile(File{Path: "usr/lib/python/site-packages/idna-2.5.egg-info", Data: []byte("Name: idna\nVersion: 2.5\n")})
		pkgs, _ := c.finish()
		found := false
		for _, p := range pkgs {
			if p.Type == "pypi" {
				found = true
				if p.Owner != "rpm:python3-idna@2.5-8.el8_10" {
					t.Fatalf("%s: %+v", kind, p)
				}
			}
		}
		if !found {
			t.Fatal(kind)
		}
	}
}

func TestDistroOwnerDirectoryWorkers(t *testing.T) {
	for _, typ := range []string{"rpm", "deb", "apk"} {
		for _, workers := range []int{1, 4} {
			t.Run(fmt.Sprintf("%s/%d", typ, workers), func(t *testing.T) {
				root := t.TempDir()
				files := map[string]string{"usr/lib/python/site-packages/idna-2.5.egg-info": "Name: idna\nVersion: 2.5\n"}
				if typ == "rpm" {
					files["var/lib/rpm/Packages.db"] = string(rpmTestNDB(ownershipHeader()))
				} else if typ == "deb" {
					files["var/lib/dpkg/status"] = "Package: python3-idna\nVersion: 2.5-8.el8_10\nArchitecture: amd64\nStatus: install ok installed\n\n"
					files["var/lib/dpkg/info/python3-idna:amd64.list"] = "/usr/lib/python/site-packages/idna-2.5.egg-info\n"
				} else {
					files["lib/apk/db/installed"] = "P:python3-idna\nV:2.5-8.el8_10\nF:usr/lib/python/site-packages\nR:idna-2.5.egg-info\n\n"
				}
				writeTree(t, root, files)
				r, err := Directory(root, "test", Options{Workers: workers})
				if err != nil {
					t.Fatal(err)
				}
				p := packageNames(r)["idna"]
				if p.Owner != typ+":python3-idna@2.5-8.el8_10" {
					t.Fatalf("%+v", r.Packages)
				}
			})
		}
	}
}

func TestDistroOwnerSpoolReplay(t *testing.T) {
	for _, typ := range []string{"rpm", "deb", "apk"} {
		var spool bytes.Buffer
		encoder := gob.NewEncoder(&spool)
		emit := func(p Package) {
			if err := encoder.Encode(p); err != nil {
				t.Fatal(err)
			}
		}
		switch typ {
		case "rpm":
			scanRPMDatabase(File{Path: "var/lib/rpm/Packages.db", Data: rpmTestNDB(ownershipHeader())}, "", emit)
		case "deb":
			scanFile(File{Path: "var/lib/dpkg/info/python3-idna.list", Data: []byte("/usr/lib/python/site-packages/idna-2.5.egg-info\n")}, emit)
			scanFile(File{Path: "var/lib/dpkg/status", Data: []byte("Package: python3-idna\nVersion: 2.5-8.el8_10\n\n")}, emit)
		case "apk":
			scanFile(File{Path: "lib/apk/db/installed", Data: []byte("P:python3-idna\nV:2.5-8.el8_10\nF:usr/lib/python/site-packages\nR:idna-2.5.egg-info\n\n")}, emit)
		}
		c := cataloger{}
		c.addFile(File{Path: "usr/lib/python/site-packages/idna-2.5.egg-info", Data: []byte("Name: idna\nVersion: 2.5\n")})
		decoder := gob.NewDecoder(&spool)
		for {
			var p Package
			err := decoder.Decode(&p)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			c.addPackage(p)
		}
		pkgs, _ := c.finish()
		if len(pkgs) != 2 {
			t.Fatalf("transport records leaked: %+v", pkgs)
		}
		for _, p := range pkgs {
			if p.Ownership != nil {
				t.Fatal("retained transport paths")
			}
			if p.Type == "pypi" && p.Owner != typ+":python3-idna@2.5-8.el8_10" {
				t.Fatalf("%s: %+v", typ, p)
			}
		}
	}
}
