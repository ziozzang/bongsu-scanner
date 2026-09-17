package scan

import "time"

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Data   []byte `json:"-"`
	Layer  string `json:"layer,omitempty"`
}

// Package is one inventoried package. Identity fields feed purl generation:
//
//	Type       purl type (deb, apk, npm, golang, pypi, cargo, maven)
//	Namespace  purl namespace (deb: debian/ubuntu; apk: alpine/wolfi; npm: @scope;
//	           golang: module path before the final segment; maven: groupId)
//	Name       purl name (npm: name without scope; golang: final path segment)
//	Version    package version as recorded by the package manager
//	Arch       ?arch= qualifier for OS packages
//	Distro     ?distro= qualifier, e.g. "debian-13", "alpine-3.20.10"
//	SourceName ?upstream= qualifier: dpkg "Source:" or apk "o:" package name
//
// Source is the path of the metadata file the package was discovered in.
type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version,omitempty"`
	Type          string `json:"type,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	PURL          string `json:"purl,omitempty"`
	CPE           string `json:"cpe,omitempty"`
	License       string `json:"license,omitempty"`
	Source        string `json:"source,omitempty"`
	Arch          string `json:"architecture,omitempty"`
	Distro        string `json:"distro,omitempty"`
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
	Indirect      bool   `json:"indirect,omitempty"`
	Dev           bool   `json:"dev,omitempty"`
	Layer         string `json:"layer,omitempty"`
	Evidence      string `json:"evidence,omitempty"`

	// VersionOriginal preserves a manifest version before Maven normalization.
	VersionOriginal string `json:"version_original,omitempty"`
}

// OSRelease is the parsed /etc/os-release of the scanned root.
type OSRelease struct {
	ID         string `json:"id,omitempty"`
	IDLike     string `json:"id_like,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	Codename   string `json:"codename,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`
}

// Distro returns the purl distro qualifier value, e.g. "debian-13", or "".
func (o OSRelease) Distro() string {
	if o.ID == "" {
		return ""
	}
	if o.VersionID == "" {
		return o.ID
	}
	return o.ID + "-" + o.VersionID
}

// LayerInfo describes one image layer in manifest order.
type LayerInfo struct {
	Digest    string `json:"digest"`            // manifest/blob digest, "sha256:..."
	DiffID    string `json:"diff_id,omitempty"` // uncompressed tar digest, "sha256:..."
	Size      int64  `json:"size,omitempty"`
	MediaType string `json:"media_type,omitempty"`
	Verified  bool   `json:"verified"` // actual content hash matched declared digest
}

// ImageMetadata is populated for docker://, container://, and image archives.
type ImageMetadata struct {
	ID           string      `json:"id,omitempty"`     // image config digest, "sha256:..."
	Digest       string      `json:"digest,omitempty"` // manifest digest when known
	Tags         []string    `json:"tags,omitempty"`
	RepoDigests  []string    `json:"repo_digests,omitempty"`
	OS           string      `json:"os,omitempty"`
	Architecture string      `json:"architecture,omitempty"`
	Variant      string      `json:"variant,omitempty"`
	Created      string      `json:"created,omitempty"`
	Layers       []LayerInfo `json:"layers,omitempty"`
	ContainerID  string      `json:"container_id,omitempty"` // container:// only
}

// ScanMetadata records how complete the scan was.
type ScanMetadata struct {
	Partial          bool     `json:"partial"`
	EUID             int      `json:"euid"`
	PermissionDenied int      `json:"permission_denied,omitempty"`
	SkippedErrors    int      `json:"skipped_errors,omitempty"`
	SkippedPaths     []string `json:"skipped_paths,omitempty"`
	Excluded         []string `json:"excluded,omitempty"`
	FilesVisited     int64    `json:"files_visited,omitempty"`
	InContainer      bool     `json:"in_container,omitempty"`
	// ExcludedCount is the total number of excluded paths; Excluded keeps
	// only the first maxRecordedPaths entries.
	ExcludedCount int `json:"excluded_count,omitempty"`
	// LimitReached names the cap that truncated the scan ("max-files",
	// "max-total-bytes", or both comma-separated); empty when none did.
	LimitReached string `json:"limit_reached,omitempty"`
	// MetadataSkipped counts metadata omitted by byte/size limits or growth.
	MetadataSkipped int `json:"metadata_skipped,omitempty"`
	// DeclaredSkipped counts dependencies omitted from bundled declaration files.
	DeclaredSkipped int `json:"declared_skipped,omitempty"`
}

type HostMetadata struct {
	Hostname        string   `json:"hostname,omitempty"`
	OperatingSystem string   `json:"operating_system,omitempty"`
	OSVersion       string   `json:"os_version,omitempty"`
	Kernel          string   `json:"kernel,omitempty"`
	Architecture    string   `json:"architecture,omitempty"`
	CPUModel        string   `json:"cpu_model,omitempty"`
	CPUCount        int      `json:"cpu_count,omitempty"`
	MemoryBytes     uint64   `json:"memory_bytes,omitempty"`
	IPAddresses     []string `json:"ip_addresses,omitempty"`
}

type Result struct {
	Name       string
	Source     string
	SourceType string
	SourceHash string
	ScannedAt  time.Time
	Files      []File
	Packages   []Package
	Layers     []File
	OSName     string
	OSVersion  string
	OS         *OSRelease
	Image      *ImageMetadata
	Scan       *ScanMetadata
	Host       *HostMetadata
}
