package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	supplychain "github.com/bazel-contrib/supply-chain/lib/supplychain-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

func main() {
	var outPath, graphPath, classificationsPath, format, validatorPath, buildStatusPath, stableStatusPath, serialNumberPath string
	flag.StringVar(&outPath, "out", "", "The path to write the generated CycloneDX SBOM.")
	flag.StringVar(&graphPath, "graph", "", "The path to the graph JSON file.")
	flag.StringVar(&classificationsPath, "classifications", "", "The path to the classifications JSON file.")
	flag.StringVar(&format, "format", "json", "The output format of the CycloneDX SBOM (json or xml).")
	flag.StringVar(&buildStatusPath, "created_from_status_file", "", "Path to a Bazel volatile-status.txt file to read BUILD_TIMESTAMP and stable build identity values from.")
	flag.StringVar(&stableStatusPath, "stable_status_file", "", "Path to a Bazel stable-status.txt file to read stable build identity values from.")
	flag.StringVar(&serialNumberPath, "serial_number_file", "", "Path to a file containing the CycloneDX BOM serialNumber.")
	flag.StringVar(&validatorPath, "validator", "", "Optional runfiles path or executable path to the CycloneDX CLI validator.")
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

	buildStatus, err := sbom.ReadBuildStatus(buildStatusPath, stableStatusPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading build status file: %v\n", err)
		os.Exit(1)
	}

	serialNumber, err := readSerialNumber(serialNumberPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading serial number file: %v\n", err)
		os.Exit(1)
	}

	bom, err := GenerateBOM(graph, classifications, buildStatus, serialNumber)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating BOM: %v\n", err)
		os.Exit(1)
	}

	var buf bytes.Buffer
	encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	switch format {
	case "json":
		encoder = cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	case "xml":
		encoder = cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatXML)
	default:
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a supported format. Use 'json' or 'xml'\n", format)
		os.Exit(1)
	}

	if err := encoder.Encode(bom); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding BOM: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
		os.Exit(1)
	}

	if validatorPath != "" {
		if err := sbom.RunValidator(validatorPath, "validate", "--input-file", outPath, "--input-format", format, "--input-version", "v1_6", "--fail-on-errors"); err != nil {
			fmt.Fprintf(os.Stderr, "Error validating BOM: %v\n", err)
			os.Exit(1)
		}
	}
}

func GenerateBOM(graph sbom.GraphConfig, classifications sbom.Classifications, buildStatus sbom.BuildStatus, serialNumber string) (*cdx.BOM, error) {
	components := make([]cdx.Component, 0)
	labelToBOMRef := make(map[string]string)
	var rootComponent *cdx.Component

	// Helper function to create component from node
	createComponent := func(node *sbom.NodeConfig) (cdx.Component, error) {
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

		bomRef := purl.String()
		component := cdx.Component{
			BOMRef:     bomRef,
			Type:       cdx.ComponentTypeLibrary,
			Name:       fullName,
			PackageURL: bomRef,
		}

		downloadLocation := ""
		qualifiers := purl.Qualifiers.Map()
		if qualifier := strings.TrimSpace(qualifiers["download_url"]); qualifier != "" {
			downloadLocation = qualifier
		} else if qualifier := strings.TrimSpace(qualifiers["url_download"]); qualifier != "" {
			downloadLocation = qualifier
		}
		if downloadLocation != "" {
			component.ExternalReferences = &[]cdx.ExternalReference{
				{
					Type: cdx.ERTypeDistribution,
					URL:  downloadLocation,
				},
			}
		}

		// Add version if available
		if purl.Version != "" {
			component.Version = purl.Version
		}

		labelToBOMRef[node.Label] = bomRef
		return component, nil
	}

	// Handle root component
	if classifications.RootComponent != nil {
		comp, err := createComponent(classifications.RootComponent)
		if err != nil {
			return nil, err
		}
		rootComponent = &comp
	}

	// Add direct and transitive dependencies, skipping any component whose
	// BOMRef was already added (classification should already be unique per
	// component, but a duplicate BOMRef is invalid CycloneDX, so guard here
	// too).
	seenBOMRef := make(map[string]bool)
	addComponent := func(node *sbom.NodeConfig) error {
		comp, err := createComponent(node)
		if err != nil {
			return err
		}
		if seenBOMRef[comp.BOMRef] {
			return nil
		}
		seenBOMRef[comp.BOMRef] = true
		components = append(components, comp)
		return nil
	}

	for i := range classifications.Dependencies.Direct {
		if err := addComponent(&classifications.Dependencies.Direct[i]); err != nil {
			return nil, err
		}
	}

	for i := range classifications.Dependencies.Transitive {
		if err := addComponent(&classifications.Dependencies.Transitive[i]); err != nil {
			return nil, err
		}
	}

	// Build Dependencies from graph edges
	depMap := make(map[string][]string) // parent BOMRef -> []child BOMRefs
	seenDep := make(map[string]map[string]bool)
	for _, edge := range graph.Edges {
		fromRef, fromOk := labelToBOMRef[edge.From]
		toRef, toOk := labelToBOMRef[edge.To]

		if !fromOk || !toOk || fromRef == toRef {
			// A self-reference can appear if two distinct graph nodes
			// resolved to the same component (e.g. duplicate metadata).
			continue
		}
		if seenDep[fromRef] == nil {
			seenDep[fromRef] = make(map[string]bool)
		}
		if seenDep[fromRef][toRef] {
			continue
		}
		seenDep[fromRef][toRef] = true
		depMap[fromRef] = append(depMap[fromRef], toRef)
	}

	// Convert to CycloneDX Dependencies format
	var dependencies *[]cdx.Dependency
	if len(depMap) > 0 {
		deps := make([]cdx.Dependency, 0, len(depMap))
		for parentRef, childRefs := range depMap {
			deps = append(deps, cdx.Dependency{
				Ref:          parentRef,
				Dependencies: &childRefs,
			})
		}
		dependencies = &deps
	}

	bom := cdx.NewBOM()
	bom.Version = 1
	if serialNumber == "" {
		serialNumber = buildStatus.SerialNumber
	}
	if serialNumber != "" {
		bom.SerialNumber = serialNumber
	}

	if len(components) > 0 {
		bom.Components = &components
	}

	bom.Dependencies = dependencies

	// Add metadata with tool information and root component
	metadata := &cdx.Metadata{
		Timestamp: buildStatus.Created.Format(time.RFC3339),
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
		if version := buildStatus.Version(); version != "" {
			rootComponent.Version = version
		}
		if revisionURL := buildStatus.RevisionURL(); revisionURL != "" {
			references := appendExternalReference(rootComponent.ExternalReferences, cdx.ExternalReference{
				Type: cdx.ERTypeVCS,
				URL:  revisionURL,
			})
			rootComponent.ExternalReferences = &references
		}
		metadata.Component = rootComponent
	}

	bom.Metadata = metadata

	return bom, nil
}

var cyclonedxSerialNumberPattern = regexp.MustCompile(`^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func readSerialNumber(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	serialNumber := strings.TrimSpace(string(data))
	if serialNumber == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	if !cyclonedxSerialNumberPattern.MatchString(serialNumber) {
		return "", fmt.Errorf("%s must contain a CycloneDX serialNumber in urn:uuid form", path)
	}
	return serialNumber, nil
}

func appendExternalReference(existing *[]cdx.ExternalReference, reference cdx.ExternalReference) []cdx.ExternalReference {
	if existing == nil {
		return []cdx.ExternalReference{reference}
	}
	references := append([]cdx.ExternalReference{}, *existing...)
	references = append(references, reference)
	return references
}
