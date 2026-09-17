package sbom

// Legacy adapters retained for existing regression fixtures only.
// validLicenseExpression reports whether s parses as an SPDX expression.
func validLicenseExpression(s string) bool {
	_, ok := licenseExpression(s)
	return ok
}

type spdxDoc struct {
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	SPDXID            string           `json:"SPDXID"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo `json:"creationInfo"`
	Packages          []spdxPackage    `json:"packages"`
	Files             []spdxFile       `json:"files,omitempty"`
	Relationships     []relationship   `json:"relationships"`
}
