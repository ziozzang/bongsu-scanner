package scan

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// BDB hash metadata and page layouts are documented in Berkeley DB's
// dbinc/db_page.h. Only inline H_KEYDATA and H_OFFPAGE values are needed;
// key zero is RPM's instance counter. ReadAt keeps overflow traversal from
// disturbing the sequential hash-page scan.
func scanRPMBDB(r io.ReaderAt, size int64, emit func([]byte)) int {
	meta := make([]byte, 72)
	if size < 512 || size > maxRPMDatabase {
		return 1
	}
	if _, err := r.ReadAt(meta, 0); err != nil {
		return 1
	}
	var order binary.ByteOrder = binary.LittleEndian
	if order.Uint32(meta[12:]) != 0x00061561 {
		order = binary.BigEndian
	}
	pageSize := int64(order.Uint32(meta[20:]))
	if order.Uint32(meta[12:]) != 0x00061561 || meta[24] != 0 || meta[25] != 8 || meta[26]&1 != 0 || pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return 1
	}
	pages := int64(order.Uint32(meta[32:])) + 1
	errors := 0
	if pages > size/pageSize {
		errors++
		pages = size / pageSize
	}
	if pages > maxRPMPages {
		errors++
		pages = maxRPMPages
	}
	if pages < 2 {
		return errors
	}
	page := make([]byte, pageSize)
	// Bound total overflow I/O as well as individual chains: corrupt entries
	// must not cause repeated reads of the same large chain without limit.
	readsLeft := int64(maxRPMDatabase / pageSize)
	for pg := int64(1); pg < pages; pg++ {
		if _, err := r.ReadAt(page, pg*pageSize); err != nil {
			errors++
			continue
		}
		if page[25] != 2 && page[25] != 13 {
			continue
		}
		entries := int(order.Uint16(page[20:]))
		if order.Uint32(page[8:]) != uint32(pg) || entries%2 != 0 || 26+entries*2 > len(page) {
			errors++
			continue
		}
		offsets := make([]int, entries)
		valid := true
		for i := range offsets {
			offsets[i] = int(order.Uint16(page[26+2*i:]))
			if offsets[i] < 26+entries*2 || offsets[i] >= len(page) {
				valid = false
			}
		}
		if !valid {
			errors++
			continue
		}
		// Sorted hash pages reorder the index pairs; physical offsets are
		// not necessarily monotonic in index order.
		physical := append([]int(nil), offsets...)
		sort.Ints(physical)
		ends := make(map[int]int, entries)
		for i, off := range physical {
			end := len(page)
			if i+1 < len(physical) {
				end = physical[i+1]
			}
			if off == end {
				valid = false
			}
			ends[off] = end
		}
		if !valid {
			errors++
			continue
		}
		for i := 0; i < entries; i += 2 {
			key := page[offsets[i]:ends[offsets[i]]]
			if len(key) != 5 || key[0] != 1 {
				errors++
				continue
			}
			if order.Uint32(key[1:]) == 0 {
				continue
			}
			value := page[offsets[i+1]:ends[offsets[i+1]]]
			switch value[0] {
			case 1:
				emit(value[1:])
			case 3:
				if len(value) != 12 {
					errors++
					continue
				}
				b, err := rpmBDBOverflow(r, order, pageSize, pages, order.Uint32(value[4:]), int64(order.Uint32(value[8:])), &readsLeft)
				if err != nil {
					errors++
					continue
				}
				emit(b)
			default:
				errors++
			}
		}
	}
	return errors
}

func rpmBDBOverflow(r io.ReaderAt, order binary.ByteOrder, pageSize, pages int64, pg uint32, length int64, readsLeft *int64) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, fmt.Errorf("invalid RPM BDB overflow chain") }
	if length <= 0 || length > maxRPMHeader {
		return bad()
	}
	b := make([]byte, 0, int(length))
	page := make([]byte, pageSize)
	seen := make(map[uint32]bool)
	for pg != 0 {
		if int64(pg) >= pages || seen[pg] || *readsLeft <= 0 {
			return bad()
		}
		seen[pg] = true
		*readsLeft--
		if _, err := r.ReadAt(page, int64(pg)*pageSize); err != nil {
			return nil, err
		}
		if page[25] != 7 || order.Uint32(page[8:]) != pg {
			return bad()
		}
		next := order.Uint32(page[16:])
		n := pageSize - 26
		if next == 0 {
			n = int64(order.Uint16(page[22:]))
		}
		if n <= 0 || n > pageSize-26 || int64(len(b))+n > length {
			return bad()
		}
		b = append(b, page[26:26+n]...)
		pg = next
	}
	if int64(len(b)) != length {
		return bad()
	}
	return b, nil
}
