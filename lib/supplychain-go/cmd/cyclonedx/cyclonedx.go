package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	cdx "github.com/CycloneDX/cyclonedx-go"
	supplychain "github.com/bazel-contrib/supply-chain/lib/supplychain-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

func main() {
	var outPath, graphPath, classificationsPath, format string
	flag.StringVar(&outPath, "out", "", "The path to write the generated CycloneDX SBOM.")
	flag.StringVar(&graphPath, "graph", "", "The path to the graph JSON file.")
	flag.StringVar(&classificationsPath, "classifications", "", "The path to the classifications JSON file.")
	flag.StringVar(&format, "format", "json", "The output format of the CycloneDX SBOM (json or xml).")
	flag.Parse()

	if outPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --out flag is required")
		os.Exit(1)
	}

	if graphPath == "" || classificationsPath == "" {
		fmt.Fprintln(os.Stderr, "Error: both --graph and --classifications flags are required")
		os.Exit(1)
	}

	graphBytes, err := os.ReadFile(graphPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading graph: %v\n", err)
		os.Exit(1)
	}

	var graph sbom.GraphConfig
	if err := json.Unmarshal(graphBytes, &graph); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing graph: %v\n", err)
		os.Exit(1)
	}

	classBytes, err := os.ReadFile(classificationsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading classifications: %v\n", err)
		os.Exit(1)
	}

	var classifications sbom.Classifications
	if err := json.Unmarshal(classBytes, &classifications); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing classifications: %v\n", err)
		os.Exit(1)
	}

	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	bom, err := GenerateBOM(graph, classifications)
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

func GenerateBOM(graph sbom.GraphConfig, classifications sbom.Classifications) (*cdx.BOM, error) {
	components := make([]cdx.Component, 0)
	componentRefs := make(map[string]bool)
	labelToBOMRef := make(map[string]string)
	var rootComponent *cdx.Component

	// Helper function to create component from node
	createComponent := func(node *sbom.NodeConfig, scope string) (cdx.Component, error) {
		if node.MetadataFile == "" {
			return cdx.Component{}, fmt.Errorf("node %s has no metadata file", node.Label)
		}

		pkgMetadata, err := supplychain.ReadPackageMetadataFromFile(node.MetadataFile)
		if err != nil {
			return cdx.Component{}, fmt.Errorf("error reading metadata file %s: %w", node.MetadataFile, err)
		}

		purl := pkgMetadata.GetPURL()

		fullName := purl.Name
		if purl.Namespace != "" {
			fullName = purl.Namespace + "/" + fullName
		}

		packageURL := purl.String()
		component := cdx.Component{
			Type:       cdx.ComponentTypeLibrary,
			Name:       fullName,
			PackageURL: packageURL,
		}

		// Add version if available
		if purl.Version != "" {
			component.Version = purl.Version
		}

		// Add scope if provided
		if scope != "" {
			component.Scope = cdx.Scope(scope)
		}

		bomRef, err := componentBOMRef(packageURL, component)
		if err != nil {
			return cdx.Component{}, err
		}
		component.BOMRef = bomRef

		labelToBOMRef[node.Label] = bomRef
		return component, nil
	}

	// Handle root component
	if classifications.RootComponent != nil {
		comp, err := createComponent(classifications.RootComponent, "")
		if err != nil {
			return nil, err
		}
		rootComponent = &comp
	}

	// Add direct dependencies with scope="direct"
	for i := range classifications.Dependencies.Direct {
		comp, err := createComponent(&classifications.Dependencies.Direct[i], "direct")
		if err != nil {
			return nil, err
		}
		if !componentRefs[comp.BOMRef] {
			components = append(components, comp)
			componentRefs[comp.BOMRef] = true
		}
	}

	// Add transitive dependencies with scope="transitive"
	for i := range classifications.Dependencies.Transitive {
		comp, err := createComponent(&classifications.Dependencies.Transitive[i], "transitive")
		if err != nil {
			return nil, err
		}
		if !componentRefs[comp.BOMRef] {
			components = append(components, comp)
			componentRefs[comp.BOMRef] = true
		}
	}

	// Build Dependencies from graph edges
	depMap := make(map[string]map[string]bool) // parent BOMRef -> child BOMRefs
	for _, edge := range graph.Edges {
		fromRef, fromOk := labelToBOMRef[edge.From]
		toRef, toOk := labelToBOMRef[edge.To]

		if fromOk && toOk {
			if depMap[fromRef] == nil {
				depMap[fromRef] = make(map[string]bool)
			}
			depMap[fromRef][toRef] = true
		}
	}

	// Convert to CycloneDX Dependencies format
	var dependencies *[]cdx.Dependency
	if len(depMap) > 0 {
		deps := make([]cdx.Dependency, 0, len(depMap))
		parentRefs := make([]string, 0, len(depMap))
		for parentRef := range depMap {
			parentRefs = append(parentRefs, parentRef)
		}
		sort.Strings(parentRefs)

		for _, parentRef := range parentRefs {
			childRefs := make([]string, 0, len(depMap[parentRef]))
			for childRef := range depMap[parentRef] {
				childRefs = append(childRefs, childRef)
			}
			sort.Strings(childRefs)

			deps = append(deps, cdx.Dependency{
				Ref:          parentRef,
				Dependencies: &childRefs,
			})
		}
		dependencies = &deps
	}

	bom := cdx.NewBOM()
	bom.Version = 1

	if len(components) > 0 {
		bom.Components = &components
	}

	bom.Dependencies = dependencies

	// Add metadata with tool information and root component
	metadata := &cdx.Metadata{
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type: cdx.ComponentTypeApplication,
					Name: "Bazel Supply Chain Tools CycloneDX generator",
				},
			},
		},
	}

	// Set the root component in metadata if we have one
	if rootComponent != nil {
		metadata.Component = rootComponent
	}

	bom.Metadata = metadata

	return bom, nil
}

func componentBOMRef(baseRef string, component cdx.Component) (string, error) {
	component.BOMRef = ""
	encoded, err := json.Marshal(component)
	if err != nil {
		return "", fmt.Errorf("error hashing CycloneDX component: %w", err)
	}

	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%s#sha256:%s", baseRef, hex.EncodeToString(sum[:])), nil
}
