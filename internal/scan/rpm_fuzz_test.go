package scan

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/purl"
)

// rpmFuzzCheck validates the package derived from a header that parsed.
func rpmFuzzCheck(t *testing.T, b []byte) {
	t.Helper()
	h, err := parseRPMHeader(b)
	if err != nil {
		return
	}
	if strings.TrimSpace(h.Name) == "" || h.Version == "" || h.Release == "" {
		t.Fatalf("parsed header without identity: %+v", h)
	}
	p := h.pkg("var/lib/rpm/Packages", "")
	if p.Type != "rpm" || p.Name != h.Name || !strings.Contains(p.Version, h.Version) {
		t.Fatalf("package %+v does not reflect header %+v", p, h)
	}
	pkgs, _ := catalog(nil, []Package{p})
	for _, q := range pkgs {
		if q.PURL == "" {
			t.Fatalf("rpm package without purl: %+v", q)
		}
		if _, err := purl.Parse(q.PURL); err != nil {
			t.Fatalf("rpm purl %q: %v", q.PURL, err)
		}
	}
}

// rpmHeaderWithTags builds a header from arbitrary (tag, type, count, value)
// entries so seeds can cover every tag the parser interprets.
func rpmHeaderWithTags(entries []struct {
	tag, typ, count uint32
	value           []byte
}) []byte {
	var index, data []byte
	for _, e := range entries {
		if e.typ == 4 {
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
		}
		for _, n := range []uint32{e.tag, e.typ, uint32(len(data)), e.count} {
			index = binary.BigEndian.AppendUint32(index, n)
		}
		data = append(data, e.value...)
	}
	b := binary.BigEndian.AppendUint32(nil, uint32(len(entries)))
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	return append(append(b, index...), data...)
}

// Array tags exercise ownership paths together with module identity. Each
// malformed variant changes one property of an otherwise valid header.
func rpmArrayFuzzSeeds() [][]byte {
	entries := []struct {
		tag, typ, count uint32
		value           []byte
	}{
		{1000, 6, 1, []byte("python3\x00")}, {1001, 6, 1, []byte("3.9\x00")}, {1002, 6, 1, []byte("1.el9\x00")},
		{5096, 6, 1, []byte("python39:3.9:1234:abcd\x00")},
		{1116, 4, 2, []byte{0, 0, 0, 0, 0, 0, 0, 1}},
		{1117, 8, 2, []byte("METADATA\x00package.json\x00")},
		{1118, 8, 2, []byte("/usr/lib/python3/site-packages/example.dist-info/\x00/usr/lib/node_modules/example/\x00")},
	}
	valid := rpmHeaderWithTags(entries)
	seeds := [][]byte{valid, append([]byte(nil), valid[:len(valid)-1]...)}
	entries[4].count = 1
	seeds = append(seeds, rpmHeaderWithTags(entries))
	entries[4].count = 2
	entries[4].value = []byte{0, 0, 0, 0, 0, 0, 0, 2} // directory index outside array
	seeds = append(seeds, rpmHeaderWithTags(entries))
	entries[4].value = []byte{0, 0, 0, 0, 0, 0, 0, 1}
	entries[6].count = 3 // directory count exceeds its string store
	seeds = append(seeds, rpmHeaderWithTags(entries))
	return seeds
}

func FuzzRPMHeaderPackage(f *testing.F) {
	for _, seed := range rpmArrayFuzzSeeds() {
		f.Add(seed)
	}
	f.Add(rpmTestHeader(0))
	f.Add(rpmTestHeader(3))
	f.Add(append([]byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0}, rpmTestHeader(1)...))
	// I18N summary with several locales and a source rpm without release.
	f.Add(rpmHeaderWithTags([]struct {
		tag, typ, count uint32
		value           []byte
	}{
		{1000, 6, 1, []byte("bash\x00")}, {1001, 6, 1, []byte("5.2.15\x00")}, {1002, 6, 1, []byte("3.fc39\x00")},
		{1004, 9, 3, []byte("Bash shell\x00Shell Bash\x00Bash\x00")}, {1044, 6, 1, []byte("bash.src.rpm\x00")},
		{1022, 6, 1, []byte("noarch\x00")}, {5000, 8, 2, []byte("a\x00b\x00")},
	}))
	f.Add([]byte("broken"))
	f.Add(make([]byte, 8))
	f.Fuzz(func(t *testing.T, b []byte) {
		rpmFuzzCheck(t, b)
	})
}

func FuzzRPMBDB(f *testing.F) {
	for _, seed := range rpmArrayFuzzSeeds() {
		f.Add(rpmTestBDB(seed, binary.LittleEndian, false))
	}
	blob := rpmTestHeader(2)
	f.Add(rpmTestBDB(blob, binary.LittleEndian, false))
	f.Add(rpmTestBDB(blob, binary.BigEndian, false))
	f.Add(rpmTestBDB(blob, binary.LittleEndian, true))
	f.Add(rpmTestBDB(bytes.Repeat(blob, 12), binary.BigEndian, true))
	f.Add(make([]byte, 1024))
	f.Fuzz(func(t *testing.T, b []byte) {
		var emitted int
		errs := scanRPMBDB(bytes.NewReader(b), int64(len(b)), func(h []byte) {
			emitted++
			if len(h) > maxRPMHeader {
				t.Fatalf("emitted %d byte header", len(h))
			}
			rpmFuzzCheck(t, h)
		})
		if errs < 0 {
			t.Fatalf("negative error count %d", errs)
		}
		var viaDB int
		got := scanRPMDatabase(File{Path: "var/lib/rpm/Packages", Data: b}, "", func(Package) { viaDB++ })
		if got < 0 {
			t.Fatalf("negative error count %d", got)
		}
		if viaDB > emitted {
			t.Fatalf("database scan produced %d packages from %d headers", viaDB, emitted)
		}
	})
}

func FuzzRPMNDB(f *testing.F) {
	for _, seed := range rpmArrayFuzzSeeds() {
		f.Add(rpmTestNDB(seed))
	}
	blob := rpmTestHeader(0)
	f.Add(rpmTestNDB(blob))
	two := rpmTestNDB(blob)
	// A second slot pointing at the same blob must be rejected as a duplicate id.
	copy(two[48:], two[32:48])
	f.Add(two)
	f.Add(append([]byte("RpmP"), make([]byte, 4092)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		var emitted int
		errs := scanRPMNDB(bytes.NewReader(b), int64(len(b)), func(h []byte) {
			emitted++
			if len(h) > maxRPMHeader {
				t.Fatalf("emitted %d byte header", len(h))
			}
			rpmFuzzCheck(t, h)
		})
		if errs < 0 {
			t.Fatalf("negative error count %d", errs)
		}
		var viaDB int
		got := scanRPMDatabase(File{Path: "usr/lib/sysimage/rpm/Packages.db", Data: b}, "", func(Package) { viaDB++ })
		if got < 0 || viaDB > emitted {
			t.Fatalf("database scan produced %d packages (%d errors) from %d headers", viaDB, got, emitted)
		}
	})
}

// TestRPMHeaderBoundedWork pins the fixes for headers whose index repeats a
// string tag many times over a large store, and whose string counts exceed
// the bytes left in the store.
func TestRPMHeaderBoundedWork(t *testing.T) {
	store := make([]byte, 256<<10) // all NUL: every byte is an empty string
	var index []byte
	for i := 0; i < 65536; i++ {
		for _, n := range []uint32{1004, 9, 0, 0xffffffff} {
			index = binary.BigEndian.AppendUint32(index, n)
		}
	}
	b := binary.BigEndian.AppendUint32(nil, 65536)
	b = binary.BigEndian.AppendUint32(b, uint32(len(store)))
	b = append(append(b, index...), store...)
	start := time.Now()
	if _, err := parseRPMHeader(b); err == nil {
		t.Fatal("header with 65536 duplicate summary tags accepted")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("duplicate tags took %s", d)
	}
	// A single tag whose count exceeds the store must fail without scanning.
	one := rpmHeaderWithTags([]struct {
		tag, typ, count uint32
		value           []byte
	}{{1000, 6, 1, []byte("a\x00")}, {1001, 6, 1, []byte("1\x00")}, {1002, 6, 1, []byte("2\x00")}, {1004, 9, 0xffffffff, []byte("s\x00")}})
	if _, err := parseRPMHeader(one); err == nil {
		t.Fatal("string count larger than the store accepted")
	}
	dup := rpmHeaderWithTags([]struct {
		tag, typ, count uint32
		value           []byte
	}{{1000, 6, 1, []byte("a\x00")}, {1001, 6, 1, []byte("1\x00")}, {1002, 6, 1, []byte("2\x00")}, {1000, 6, 1, []byte("b\x00")}})
	if _, err := parseRPMHeader(dup); err == nil {
		t.Fatal("duplicate name tag accepted")
	}
	if _, err := parseRPMHeader(rpmTestHeader(1)); err != nil {
		t.Fatalf("valid header rejected: %v", err)
	}
}

func TestRPMArrayFuzzSeeds(t *testing.T) {
	for i, seed := range rpmArrayFuzzSeeds() {
		h, err := parseRPMHeader(seed)
		if i == 0 {
			if err != nil || h.Modularity != "python39:3.9:1234:abcd" || len(h.Files) != 2 {
				t.Fatalf("valid seed does not reach array/module parsing: %+v %v", h, err)
			}
		} else if err == nil {
			t.Fatalf("malformed seed %d accepted", i)
		}
	}
}
