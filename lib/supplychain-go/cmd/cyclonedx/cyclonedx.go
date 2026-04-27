package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	supplychain "github.com/bazel-contrib/supply-chain/lib/supplychain-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

const subjectBOMRef = "bazel-subject"

func main() {
	var outPath, configPath, format string
	flag.StringVar(&outPath, "out", "", "The path to write the generated CycloneDX SBOM.")
	flag.StringVar(&configPath, "config", "", "The path to the SBOM generation configuration file.")
	flag.StringVar(&format, "format", "json", "The output format of the CycloneDX SBOM (json or xml).")
	flag.Parse()

	if configPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --config flag is required")
		os.Exit(1)
	}

	if outPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --out flag is required")
		os.Exit(1)
	}

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
		os.Exit(1)
	}

	var config sbom.GenConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing config file: %v\n", err)
		os.Exit(1)
	}

	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	bom, err := GenerateBOM(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating BOM: %v\n", err)
		os.Exit(1)
	}

	encoder := cdx.NewBOMEncoder(out, cdx.BOMFileFormatJSON)
	switch format {
	case "json":
		encoder = cdx.NewBOMEncoder(out, cdx.BOMFileFormatJSON)
	case "xml":
		encoder = cdx.NewBOMEncoder(out, cdx.BOMFileFormatXML)
	default:
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a supported format. Use 'json' or 'xml'\n", format)
		os.Exit(1)
	}

	if err := encoder.Encode(bom); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding BOM: %v\n", err)
		os.Exit(1)
	}
}

func GenerateBOM(config sbom.GenConfig) (*cdx.BOM, error) {
	components := make([]cdx.Component, 0, len(config.Nodes))
	dependencyMap := map[string][]string{
		subjectBOMRef: {},
	}
	labelToBOMRef := map[string]string{}

	rootComponent := cdx.Component{
		BOMRef: subjectBOMRef,
		Type:   cdx.ComponentTypeApplication,
		Name:   config.Subject.Label,
	}

	for _, node := range config.Nodes {
		pkgMetadata, err := supplychain.ReadPackageMetadataFromFile(node.Metadata)
		if err != nil {
			return nil, fmt.Errorf("error reading metadata file %s: %w", node.Metadata, err)
		}

		purl := pkgMetadata.GetPURL()

		fullName := purl.Name
		if purl.Namespace != "" {
			fullName = purl.Namespace + "/" + fullName
		}

		component := cdx.Component{
			BOMRef:     node.ID,
			Type:       cdx.ComponentTypeLibrary,
			Name:       fullName,
			PackageURL: purl.String(),
			Scope:      componentScopeForNode(node.ID, config.Relationships),
			Properties: &[]cdx.Property{},
		}

		if purl.Version != "" {
			component.Version = purl.Version
		}

		components = append(components, component)
		dependencyMap[node.ID] = []string{}
		labelToBOMRef[node.Label] = node.ID
	}

	for i := range components {
		component := &components[i]
		for _, rel := range config.Relationships {
			if rel.To != component.BOMRef {
				continue
			}
			component.Properties = appendProperty(component.Properties, "bazel:relationship", rel.Relationship)
			component.Properties = appendProperty(component.Properties, "bazel:origin", rel.Origin)
			if rel.AppliesTo != "" {
				component.Properties = appendProperty(component.Properties, "bazel:applies_to", rel.AppliesTo)
			}
			if rel.ToolchainType != "" {
				component.Properties = appendProperty(component.Properties, "bazel:toolchain_type", rel.ToolchainType)
			}
			if rel.ToolchainLabel != "" {
				component.Properties = appendProperty(component.Properties, "bazel:toolchain_label", rel.ToolchainLabel)
			}
			if rel.Notes != "" {
				component.Properties = appendProperty(component.Properties, "bazel:notes", rel.Notes)
			}
			fromRef := ""
			switch rel.From {
			case config.Subject.Label:
				fromRef = subjectBOMRef
			default:
				fromRef = labelToBOMRef[rel.From]
			}
			if fromRef == "" && rel.Origin == "dependency" {
				fromRef = subjectBOMRef
			}
			if fromRef == "" {
				continue
			}
			dependencyMap[fromRef] = appendUnique(dependencyMap[fromRef], rel.To)
		}
	}

	dependencies := make([]cdx.Dependency, 0, len(dependencyMap))
	for ref, deps := range dependencyMap {
		depCopy := deps
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          ref,
			Dependencies: &depCopy,
		})
	}

	bom := cdx.NewBOM()
	bom.Version = 1
	bom.Metadata = &cdx.Metadata{
		Component: &rootComponent,
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type: cdx.ComponentTypeApplication,
					Name: "Bazel Supply Chain Tools CycloneDX generator",
				},
			},
		},
	}
	if len(components) > 0 {
		bom.Components = &components
	}
	if len(dependencies) > 0 {
		bom.Dependencies = &dependencies
	}

	return bom, nil
}

func componentScopeForNode(nodeID string, relationships []sbom.RelationshipConfig) cdx.Scope {
	scope := cdx.ScopeRequired
	for _, rel := range relationships {
		if rel.To != nodeID {
			continue
		}
		switch rel.Relationship {
		case "build_tool", "build_dependency":
			return cdx.ScopeExcluded
		}
		if rel.Relationship == "provided_runtime" {
			scope = cdx.ScopeRequired
		}
	}
	return scope
}

func appendProperty(properties *[]cdx.Property, name, value string) *[]cdx.Property {
	if properties == nil {
		properties = &[]cdx.Property{}
	}
	*properties = append(*properties, cdx.Property{
		Name:  name,
		Value: value,
	})
	return properties
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
