package sbom

type GenConfig struct {
	SchemaVersion string       `json:"schema_version"`
	RootTarget    string       `json:"root_target"`
	Nodes         []NodeConfig `json:"nodes"`
	Edges         []EdgeConfig `json:"edges"`
}

type NodeConfig struct {
	Label        string `json:"label"`
	MetadataFile string `json:"metadata_file"`

	// ConcludedLicenseFile is the license attribute file overriding the declared
	// license of the package. Set in the classifications by `ConcludedLicenses.Apply`.
	ConcludedLicenseFile string `json:"concluded_license_file,omitempty"`
}

type EdgeConfig struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}
