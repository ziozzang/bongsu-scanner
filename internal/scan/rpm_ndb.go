package scan

import (
	"encoding/binary"
	"hash/adler32"
	"io"
)

// NDB uses 4096-byte slot pages and 16-byte allocation blocks. The blob
// envelope (including padding) has an Adler-32 checksum and length trailer.
// Layout: rpm/lib/backend/ndb/rpmpkg.c, PKGDB_*, SLOT_*, BLOBHEAD_*.
func scanRPMNDB(r io.ReaderAt, size int64, emit func([]byte)) int {
	const pageSize = 4096
	page := make([]byte, pageSize)
	if size < pageSize || size > maxRPMDatabase || size%16 != 0 {
		return 1
	}
	if _, err := r.ReadAt(page, 0); err != nil {
		return 1
	}
	le := binary.LittleEndian
	pages := int64(le.Uint32(page[12:]))
	if string(page[:4]) != "RpmP" || le.Uint32(page[4:]) != 0 || pages < 1 || pages > maxRPMPages || pages > size/pageSize {
		return 1
	}
	errors := 0
	seen := make(map[uint32]bool)
	readBytes := int64(0)
	for pg := int64(0); pg < pages; pg++ {
		if pg != 0 {
			if _, err := r.ReadAt(page, pg*pageSize); err != nil {
				errors++
				continue
			}
		}
		start := 0
		if pg == 0 {
			start = 32
		}
		for off := start; off < pageSize; off += 16 {
			slot := page[off : off+16]
			if string(slot[:4]) != "Slot" {
				errors++
				continue
			}
			pos := int64(le.Uint32(slot[8:])) * 16
			if pos == 0 {
				continue
			}
			id, n := le.Uint32(slot[4:]), int64(le.Uint32(slot[12:]))*16
			if id == 0 || seen[id] || pos < pages*pageSize || n < 32 || n > maxRPMHeader+48 || pos > size || n > size-pos {
				errors++
				continue
			}
			seen[id] = true
			readBytes += n
			if readBytes > maxRPMDatabase {
				return errors + 1
			}
			b := make([]byte, n)
			if _, err := r.ReadAt(b, pos); err != nil {
				errors++
				continue
			}
			length := int64(le.Uint32(b[12:]))
			if string(b[:4]) != "BlbS" || le.Uint32(b[4:]) != id || length > maxRPMHeader || (length+28+15)/16*16 != n || string(b[n-4:]) != "BlbE" || int64(le.Uint32(b[n-8:])) != length || le.Uint32(b[n-12:]) != adler32.Checksum(b[:n-12]) {
				errors++
				continue
			}
			emit(b[16 : 16+length])
		}
	}
	return errors
}
