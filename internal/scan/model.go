package scan

import "time"

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Data   []byte `json:"-"`
	Layer  string `json:"layer,omitempty"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
	PURL    string `json:"purl,omitempty"`
	License string `json:"license,omitempty"`
	Source  string `json:"source,omitempty"`
	Arch    string `json:"architecture,omitempty"`
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
	Host       *HostMetadata
}
