package scan

import (
	"debug/buildinfo"
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
	info, err := buildinfo.Read(r)
	if err != nil || info == nil {
		return nil
	}
	add := func(name, version string, indirect bool) {
		name, version = strings.TrimSpace(name), strings.TrimSpace(version)
		if name == "" || version == "" || version == "(devel)" || isLocalModulePath(name) {
			return
		}
		pkgs = append(pkgs, Package{Name: name, Version: version, Type: "golang", Source: source, Layer: layer, Indirect: indirect})
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
	if strings.HasPrefix(v, "go") {
		v = v[2:]
	}
	if v == "" || (v[0] < '0' || v[0] > '9') {
		return ""
	}
	return v
}
