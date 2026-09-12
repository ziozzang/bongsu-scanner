// Package version compares package versions using the rules of the
// ecosystem the package belongs to. It is intended for evaluating OSV
// "affected" ranges against versions found in SBOMs, so every comparator
// is total (never panics, always returns an answer) and deterministic.
//
// Supported families and the specification each one follows:
//
//   - deb:     dpkg version comparison (Debian Policy §5.6.12, lib/dpkg/vercmp.c)
//   - apk:     Alpine apk-tools version comparison (src/version.c)
//   - rpm:     rpmvercmp with epoch:version-release labels
//   - semver:  Semantic Versioning 2.0.0 with lenient parsing
//   - pypi:    PEP 440
//   - golang:  Go module versions (semver + pseudo-versions + "+incompatible")
//   - maven:   Maven ComparableVersion
//   - generic: natural ordering of numeric/non-numeric tokens (fallback)
//
// The ecosystem name given to Compare, Valid and Normalize may be a purl
// type ("deb", "npm"), an OSV ecosystem ("Debian", "crates.io"), an OSV
// ecosystem with a release suffix ("Debian:13", "Alpine:v3.20") or one of
// the universal names "semver" and "generic". Matching is case-insensitive.
package version
