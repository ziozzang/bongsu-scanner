package scan

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

// maxRPMDatabase is overridable by serial tests; production keeps 256 MiB.
var maxRPMDatabase int64 = 256 << 20

const (
	maxRPMHeader = 16 << 20
	maxRPMPages  = 1 << 20
)

func isRPMDatabase(p string) bool {
	switch normPath(p) {
	case "var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite",
		"var/lib/rpm/packages", "usr/lib/sysimage/rpm/packages",
		"var/lib/rpm/packages.db", "usr/lib/sysimage/rpm/packages.db":
		return true
	}
	return false
}

type rpmHeader struct {
	Name, Version, Release, Arch, SourceRPM, License, Summary, Vendor string
	Modularity                                                        string
	Files                                                             []string
	Epoch                                                             uint32
	Size                                                              uint64
}

// parseRPMHeader reads the big-endian index and store of an exported header.
// Database headers normally start with nindex/hsize; accept the optional
// eight-byte magic prefix as well. Unknown tags do not allocate memory.
func parseRPMHeader(b []byte) (rpmHeader, error) {
	var h rpmHeader
	bad := func() (rpmHeader, error) { return rpmHeader{}, fmt.Errorf("invalid RPM header") }
	if len(b) > maxRPMHeader {
		return bad()
	}
	if len(b) >= 8 && bytes.Equal(b[:4], []byte{0x8e, 0xad, 0xe8, 1}) {
		b = b[8:]
	}
	if len(b) < 8 {
		return bad()
	}
	be := binary.BigEndian
	n, size := uint64(be.Uint32(b)), uint64(be.Uint32(b[4:]))
	start := uint64(8) + n*16
	if n == 0 || n > 65536 || start > uint64(len(b)) || size > uint64(len(b))-start {
		return bad()
	}
	data := b[start : start+size]
	// A header never repeats a tag. Rejecting duplicates also bounds the
	// string scans below to one pass over the store per interpreted tag, so
	// 65536 index entries cannot each rescan a 16 MiB store.
	seen := map[uint32]bool{}
	type array struct {
		data  []byte
		count uint64
	}
	arrays := map[uint32]array{}
	for i := uint64(0); i < n; i++ {
		e := b[8+i*16 : 8+(i+1)*16]
		tag, typ, off, count := be.Uint32(e), be.Uint32(e[4:]), uint64(be.Uint32(e[8:])), uint64(be.Uint32(e[12:]))
		var dst *string
		switch tag {
		case 1000, 1001, 1002, 1022, 1044, 1014, 1004, 1011, 1003, 1009, 5096, 1116, 1117, 1118:
			if seen[tag] {
				return bad()
			}
			seen[tag] = true
		}
		switch tag {
		case 1116, 1117, 1118:
			if off > size || count > size-off {
				return bad()
			}
			remaining := data[off:]
			if tag == 1116 {
				if typ != 4 || off%4 != 0 || count > uint64(len(remaining))/4 {
					return bad()
				}
				arrays[tag] = array{remaining[:count*4], count}
			} else {
				if typ != 8 {
					return bad()
				}
				rest := remaining
				for j := uint64(0); j < count; j++ {
					end := bytes.IndexByte(rest, 0)
					if end < 0 {
						return bad()
					}
					rest = rest[end+1:]
				}
				arrays[tag] = array{remaining[:len(remaining)-len(rest)], count}
			}
			continue
		case 5096:
			dst = &h.Modularity
		case 1000:
			dst = &h.Name
		case 1001:
			dst = &h.Version
		case 1002:
			dst = &h.Release
		case 1022:
			dst = &h.Arch
		case 1044:
			dst = &h.SourceRPM
		case 1014:
			dst = &h.License
		case 1004:
			dst = &h.Summary
		case 1011:
			dst = &h.Vendor
		case 1003, 1009:
			if typ != 4 || count != 1 || off > size || size-off < 4 || off%4 != 0 {
				return bad()
			}
			v := be.Uint32(data[off:])
			if tag == 1003 {
				h.Epoch = v
			} else {
				h.Size = uint64(v)
			}
			continue
		default:
			continue
		}
		if off >= size || count == 0 || (typ != 6 && !(tag == 1004 && typ == 9)) || (typ == 6 && count != 1) {
			return bad()
		}
		remaining := data[off:]
		if count > uint64(len(remaining)) { // every string needs at least its NUL
			return bad()
		}
		for j := uint64(0); j < count; j++ {
			end := bytes.IndexByte(remaining, 0)
			if end < 0 {
				return bad()
			}
			if j == 0 {
				*dst = string(remaining[:end])
			}
			remaining = remaining[end+1:]
		}
	}
	if strings.TrimSpace(h.Name) == "" || h.Version == "" || h.Release == "" {
		return bad()
	}
	// Validate every entry, but allocate only candidate metadata names and
	// their referenced directories. Both string stores are scanned linearly.
	if len(arrays) != 0 {
		if len(arrays) != 3 || arrays[1116].count != arrays[1117].count {
			return bad()
		}
		bases, dirs, indexes := arrays[1117], arrays[1118], arrays[1116]
		type candidate struct {
			base string
			dir  uint32
		}
		var candidates []candidate
		wanted := map[uint32]string{}
		rest := bases.data
		for i := uint64(0); i < bases.count; i++ {
			end := bytes.IndexByte(rest, 0)
			base := rest[:end]
			rest = rest[end+1:]
			dir := be.Uint32(indexes.data[i*4:])
			if uint64(dir) >= dirs.count {
				return bad()
			}
			if len(candidates) < maxOwnedPaths && len(base) <= maxOwnedPathLength && !bytes.ContainsAny(base, "/\\") && (bytes.Equal(base, []byte("METADATA")) || bytes.Equal(base, []byte("PKG-INFO")) || bytes.Equal(base, []byte("package.json")) || bytes.HasSuffix(base, []byte(".egg-info")) || bytes.HasSuffix(base, []byte(".gemspec"))) {
				candidates = append(candidates, candidate{string(base), dir})
				wanted[dir] = ""
			}
		}
		rest = dirs.data
		for i := uint64(0); i < dirs.count; i++ {
			end := bytes.IndexByte(rest, 0)
			if _, ok := wanted[uint32(i)]; ok && end <= maxOwnedPathLength {
				wanted[uint32(i)] = string(rest[:end])
			}
			rest = rest[end+1:]
		}
		retainedBytes := 0
		for _, c := range candidates {
			dir := wanted[c.dir]
			if dir == "" {
				continue
			}
			p := ownershipPath(path.Join(dir, c.base))
			if languageMetadataPath(p) && retainedBytes+len(p) <= maxOwnedBytes {
				h.Files = append(h.Files, p)
				retainedBytes += len(p)
			}
		}
	}
	return h, nil
}

func (h rpmHeader) pkg(src, layer string) Package {
	v := h.Version + "-" + h.Release
	if h.Epoch != 0 {
		v = strconv.FormatUint(uint64(h.Epoch), 10) + ":" + v
	}
	p := Package{Type: "rpm", Name: h.Name, Version: v, Arch: h.Arch, License: h.License, Source: src, Layer: layer, Modularity: h.Modularity}
	if len(h.Files) != 0 {
		p.Ownership = &packageOwnership{Paths: h.Files}
	}
	for _, suffix := range []string{".src.rpm", ".nosrc.rpm"} {
		if !strings.HasSuffix(h.SourceRPM, suffix) {
			continue
		}
		nv, rel := splitLast(strings.TrimSuffix(h.SourceRPM, suffix), "-")
		name, ver := splitLast(nv, "-")
		if name != "" && ver != "" && rel != "" {
			p.SourceName, p.SourceVersion = name, ver+"-"+rel
		}
		break
	}
	return p
}

// scanRPMDatabase emits each valid package and returns a corruption/error
// count, preserving partial inventories. diskPath is a trusted local path,
// separate from the inventory's root-relative path and layer attribution.
func scanRPMDatabase(f File, diskPath string, add func(Package)) int {
	errors := 0
	emit := func(b []byte) {
		h, err := parseRPMHeader(b)
		if err != nil {
			errors++
			return
		}
		// RPM's signing keys are database records, not installed OS packages.
		if h.Name != "gpg-pubkey" {
			p := h.pkg(f.Path, f.Layer)
			add(p)
		}
	}
	if int64(len(f.Data)) > maxRPMDatabase {
		return 1
	}
	if path.Base(normPath(f.Path)) == "rpmdb.sqlite" {
		if diskPath == "" {
			tmp, err := os.CreateTemp("", "bscan-rpm-*.sqlite")
			if err != nil {
				return 1
			}
			diskPath = tmp.Name()
			defer func() {
				// Best-effort removal of temporary state; preserve the operation result.
				_ = os.Remove(diskPath)
			}()
			_, err = tmp.Write(f.Data)
			closeErr := tmp.Close()
			if err != nil || closeErr != nil {
				return 1
			}
		}
		return scanRPMSQLite(diskPath, emit) + errors
	}
	var r io.ReaderAt = bytes.NewReader(f.Data)
	size := int64(len(f.Data))
	if diskPath != "" {
		file, err := os.Open(diskPath) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
		if err != nil {
			return 1
		}
		defer func() {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = file.Close()
		}()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return 1
		}
		r, size = file, info.Size()
	}
	if size <= 0 || size > maxRPMDatabase {
		return 1
	}
	if path.Base(normPath(f.Path)) == "packages.db" {
		return scanRPMNDB(r, size, emit) + errors
	}
	return scanRPMBDB(r, size, emit) + errors
}

func scanRPMSQLite(diskPath string, emit func([]byte)) int {
	info, err := os.Stat(diskPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxRPMDatabase {
		return 1
	}
	abs, err := filepath.Abs(diskPath)
	if err != nil {
		return 1
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return 1
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = db.Close()
	}()
	db.SetMaxOpenConns(1)
	// Do not materialize an untrusted oversized blob in the SQL driver.
	rows, err := db.Query("SELECT CASE WHEN length(blob) <= ? THEN blob ELSE NULL END FROM Packages ORDER BY hnum", maxRPMHeader)
	if err != nil {
		return 1
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = rows.Close()
	}()
	errors := 0
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			errors++
			continue
		}
		emit(b)
	}
	if rows.Err() != nil {
		errors++
	}
	return errors
}
