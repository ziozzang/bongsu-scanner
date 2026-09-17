package scan

import (
	"debug/buildinfo"
	"encoding/binary"
	"io"
	"strings"
)

// goBinaryPackages extracts Go module dependencies and the Go toolchain
// version from a compiled Go binary using debug/buildinfo. It returns nil
// when the data is not a Go binary. Callers pass the discovered file path as
// source so the packages can be attributed to it.
//
// The result contains a "stdlib" package carrying the Go version, the main
// module when it has a real version (not "(devel)"), and every dependency
// with its replacement applied. Dependencies replaced by a local directory
// carry no usable version and are omitted.
func goBinaryPackages(r io.ReaderAt, size int64, source, layer string) (pkgs []Package) {
	if r == nil || size <= 0 {
		return nil
	}
	defer func() {
		// debug/buildinfo is not hardened against every malformed input;
		// a corrupt binary must never take the scanner down.
		if rec := recover(); rec != nil {
			pkgs = nil
		}
	}()
	r = boundedBinaryReader(r)
	if !binaryHeaderWithinLimits(r) {
		return nil
	}
	info, err := buildinfo.Read(r)
	if err != nil || info == nil {
		return nil
	}
	add := func(name, version string, indirect bool) {
		name, version = strings.TrimSpace(name), strings.TrimSpace(version)
		if name == "" || version == "" || version == "(devel)" || isLocalModulePath(name) {
			return
		}
		pkgs = append(pkgs, Package{Name: name, Version: version, Type: "golang", Source: source, Layer: layer, Indirect: indirect, Evidence: "binary"})
	}
	if v := goVersionNumber(info.GoVersion); v != "" {
		add("stdlib", v, false)
	}
	add(info.Main.Path, info.Main.Version, false)
	for _, d := range info.Deps {
		m := d
		if m == nil {
			continue
		}
		if m.Replace != nil {
			m = m.Replace
		}
		add(m.Path, m.Version, false)
	}
	return pkgs
}

// goVersionNumber turns runtime version strings such as "go1.22.4",
// "go1.23rc1" or "devel go1.24-abcdef" into "1.22.4", "1.23rc1", "1.24".
func goVersionNumber(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "devel ") {
		v = strings.TrimSpace(strings.TrimPrefix(v, "devel "))
		if i := strings.IndexByte(v, '-'); i > 0 {
			v = v[:i]
		}
	}
	v = strings.TrimPrefix(v, "go")
	if v == "" || (v[0] < '0' || v[0] > '9') {
		return ""
	}
	return v
}

// binaryReadBudget caps total classification and build-info I/O, including
// repeated reads and ELF headers. Callers share one instance for both probes.
// Files whose required reads exceed 8 MiB are only hashed beyond that budget.
type binaryReadBudget struct {
	io.ReaderAt
	remaining int64
}

func boundedBinaryReader(r io.ReaderAt) io.ReaderAt {
	if _, ok := r.(*binaryReadBudget); ok {
		return r
	}
	return &binaryReadBudget{ReaderAt: r, remaining: maxBinaryScanBytes}
}

func (r *binaryReadBudget) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, io.EOF
	}
	requested := len(p)
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	if len(p) == 0 && requested != 0 {
		return 0, io.EOF
	}
	n, err := r.ReaderAt.ReadAt(p, off)
	r.remaining -= int64(n)
	if n < requested && err == nil {
		err = io.EOF
	}
	return n, err
}

// debug/elf also supports extended counts in section zero. Reject those
// before the general parser allocates tables from untrusted header counts.
func binaryHeaderWithinLimits(r io.ReaderAt) bool {
	var h [64]byte
	n, err := r.ReadAt(h[:], 0)
	if n < 4 || !isELF(h[:n]) {
		return true
	}
	if err != nil {
		return false
	}
	var order binary.ByteOrder
	switch h[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return false
	}
	var count, programs uint16
	var table uint64
	switch h[4] {
	case 1:
		table = uint64(order.Uint32(h[32:36]))
		count = order.Uint16(h[48:50])
		programs = order.Uint16(h[44:46])
	case 2:
		table = order.Uint64(h[40:48])
		count = order.Uint16(h[60:62])
		programs = order.Uint16(h[56:58])
	default:
		return false
	}
	return count <= 4096 && programs <= 4096 && (count != 0 || table == 0)
}
