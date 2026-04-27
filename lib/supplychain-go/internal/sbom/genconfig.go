package sbom

type GenConfig struct {
	Subject       SubjectConfig        `json:"subject"`
	Nodes         []NodeConfig         `json:"nodes"`
	Relationships []RelationshipConfig `json:"relationships"`
}

type SubjectConfig struct {
	Label string `json:"label"`
}

type NodeConfig struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Metadata string `json:"metadata"`
}

type RelationshipConfig struct {
	From           string `json:"from"`
	To             string `json:"to"`
	Relationship   string `json:"relationship"`
	Origin         string `json:"origin"`
	AppliesTo      string `json:"applies_to,omitempty"`
	ToolchainType  string `json:"toolchain_type,omitempty"`
	ToolchainLabel string `json:"toolchain_label,omitempty"`
	Notes          string `json:"notes,omitempty"`
}
