package scan

import (
	"io"
)

// Legacy adapters retained for existing regression fixtures only.
func (u *unpacker) applyTar(rd io.Reader, layer string) error {
	return u.applyTarSource(rd, layer, nil)
}

// findOSRelease picks the root's os-release out of files using osReleaseRank.
func findOSRelease(files []File) *OSRelease {
	best, bestRank := (*OSRelease)(nil), 0
	for _, f := range files {
		r := osReleaseRank(f.Path)
		if r == 0 || r <= bestRank || len(f.Data) == 0 {
			continue
		}
		o := parseOSRelease(f.Data)
		if o.ID == "" {
			continue
		}
		best, bestRank = &o, r
	}
	return best
}

// catalog preserves the in-memory entry point used by image/archive scans.
func catalog(files []File, extra []Package) ([]Package, *OSRelease) {
	var c cataloger
	for _, f := range files {
		c.addFile(f)
	}
	c.addPackages(extra)
	return c.finish()
}

func scanInstalledNPM(f File, add func(Package)) {
	scanInstalledNPMWithPrefixes(f, nil, add)
}

// makePURL is kept for callers that only know type, name and version.
func makePURL(kind, name, version string) string {
	return buildPURL(Package{Type: kind, Name: name, Version: version})
}
