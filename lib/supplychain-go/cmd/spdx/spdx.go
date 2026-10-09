package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	supplychain "github.com/bazel-contrib/supply-chain/lib/supplychain-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/spdxnamespace"
	spdxJson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdxTV "github.com/spdx/tools-golang/tagvalue"
	spdxYaml "github.com/spdx/tools-golang/yaml"
)

func main() {
	var outPath, graphPath, classificationsPath, format, buildStatusPath, stableStatusPath, documentNamespacePath, documentNamespace, buildVersion, vcsRevision, validatorPath string
	flag.StringVar(&outPath, "out", "", "The path to write the generated SPDX SBOM.")
	flag.StringVar(&graphPath, "graph", "", "The path to the graph JSON file.")
	flag.StringVar(&classificationsPath, "classifications", "", "The path to the classifications JSON file.")
	flag.StringVar(&format, "format", "json", "The output format of the SPDX SBOM.")
	flag.StringVar(&buildStatusPath, "created_from_status_file", "", "Path to a Bazel volatile-status.txt file to read BUILD_TIMESTAMP and stable build identity values from.")
	flag.StringVar(&stableStatusPath, "stable_status_file", "", "Path to a Bazel stable-status.txt file to read stable build identity values from.")
	flag.StringVar(&buildVersion, "build_version", "", "Build version to place in the subject package versionInfo.")
	flag.StringVar(&vcsRevision, "vcs_revision", "", "VCS revision to place in the subject package versionInfo when --build_version is unset.")
	flag.StringVar(&documentNamespace, "document_namespace", "", "The SPDX document namespace. If unset, --document_namespace_file is used; if both are unset, a deterministic namespace is derived from the document subject.")
	flag.StringVar(&documentNamespacePath, "document_namespace_file", "", "Path to a file whose content is used as the SPDX document namespace. If unset, a deterministic namespace is derived from the document subject.")
	flag.StringVar(&validatorPath, "validator", "", "Optional runfiles path or executable path to the SPDX tools-java validator wrapper.")
	flag.Parse()

	if graphPath == "" || classificationsPath == "" {
		panic("both --graph and --classifications flags are required")
	}

	graphBytes, err := os.ReadFile(graphPath)
	if err != nil {
		panic(fmt.Errorf("reading graph: %w", err))
	}

	var graph sbom.GraphConfig
	if err := json.Unmarshal(graphBytes, &graph); err != nil {
		panic(fmt.Errorf("parsing graph: %w", err))
	}

	classBytes, err := os.ReadFile(classificationsPath)
	if err != nil {
		panic(fmt.Errorf("reading classifications: %w", err))
	}

	var classifications sbom.Classifications
	if err := json.Unmarshal(classBytes, &classifications); err != nil {
		panic(fmt.Errorf("parsing classifications: %w", err))
	}

	buildStatus, err := sbom.ReadBuildStatus(buildStatusPath, stableStatusPath)
	if err != nil {
		panic(fmt.Errorf("reading build status file: %w", err))
	}
	mergeBuildStatus(&buildStatus, buildVersion, vcsRevision)

	if documentNamespace == "" {
		var err error
		documentNamespace, err = spdxnamespace.ReadFile(documentNamespacePath)
		if err != nil {
			panic(fmt.Errorf("reading document namespace file: %w", err))
		}
	}

	doc, err := GenerateDocument(graph, classifications, buildStatus, documentNamespace)
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	switch format {
	case "json":
		must(spdxJson.Write(doc, &buf))
	case "yaml":
		must(spdxYaml.Write(doc, &buf))
	case "tag-value":
		must(spdxTV.Write(doc, &buf))
	default:
		panic(fmt.Sprintf("'%s' is not a supported format", format))
	}

	must(os.WriteFile(outPath, buf.Bytes(), 0664))

	if validatorPath != "" {
		must(sbom.RunValidator(validatorPath, outPath))
	}
}

func mergeBuildStatus(buildStatus *sbom.BuildStatus, buildVersion, vcsRevision string) {
	if buildVersion != "" {
		buildStatus.BuildVersion = buildVersion
	}
	if vcsRevision != "" {
		buildStatus.VCSRevision = vcsRevision
	}
}

func GenerateDocument(graph sbom.GraphConfig, classifications sbom.Classifications, buildStatus sbom.BuildStatus, documentNamespace string) (*spdx.Document, error) {
	graph = sbom.NormalizeGraph(graph)
	spdxPackages := make([]*spdx.Package, 0)
	labelToID := make(map[string]string)
	idx := 0

	// Identify the document as a whole (name/namespace, below) by its
	// subject: preferably the root component; failing that (e.g.
	// require_root_metadata = False and the root has no metadata), the
	// first package created.
	var subjectName, subjectPURL string
	var subjectPackage *spdx.Package

	// Helper function to create package from node
	createPackage := func(node *sbom.NodeConfig) (*spdx.Package, error) {
		if node.MetadataFile == "" {
			return nil, nil
		}

		pkgMetadata, err := supplychain.ReadPackageMetadataFromFile(node.MetadataFile)
		if err != nil {
			return nil, err
		}

		elementID := fmt.Sprintf("dep-%d", idx)
		idx++

		purl := pkgMetadata.GetPURL()
		if subjectPURL == "" {
			subjectName = purl.Name
			subjectPURL = purl.String()
		}

		downloadLocation := "NOASSERTION"
		qualifiers := purl.Qualifiers.Map()
		if qualifier := strings.TrimSpace(qualifiers["download_url"]); qualifier != "" {
			downloadLocation = qualifier
		} else if qualifier := strings.TrimSpace(qualifiers["url_download"]); qualifier != "" {
			downloadLocation = qualifier
		}

		pkg := &spdx.Package{
			PackageSPDXIdentifier:   common.ElementID(elementID),
			PackageDownloadLocation: downloadLocation,
			PackageLicenseConcluded: "NOASSERTION",
			PackageLicenseDeclared:  "NOASSERTION",
			PackageExternalReferences: []*spdx.PackageExternalReference{
				{
					Category: "PACKAGE-MANAGER",
					RefType:  "purl",
					Locator:  purl.String(),
				},
			},
			PackageName:    purl.Name,
			PackageVersion: purl.Version,
		}
		if subjectPackage == nil {
			subjectPackage = pkg
		}

		labelToID[node.Label] = elementID
		return pkg, nil
	}

	// Add root component
	if classifications.RootComponent != nil {
		pkg, err := createPackage(classifications.RootComponent)
		if err != nil {
			return nil, err
		}
		if pkg != nil {
			spdxPackages = append(spdxPackages, pkg)
		}
	}

	// Add all dependencies (direct + transitive)
	for i := range classifications.Dependencies.Direct {
		pkg, err := createPackage(&classifications.Dependencies.Direct[i])
		if err != nil {
			return nil, err
		}
		if pkg != nil {
			spdxPackages = append(spdxPackages, pkg)
		}
	}
	for i := range classifications.Dependencies.Transitive {
		pkg, err := createPackage(&classifications.Dependencies.Transitive[i])
		if err != nil {
			return nil, err
		}
		if pkg != nil {
			spdxPackages = append(spdxPackages, pkg)
		}
	}

	// Build Relationships from graph edges
	relationships := make([]*spdx.Relationship, 0, len(graph.Edges))
	seenRelationship := make(map[string]map[string]bool)
	for _, edge := range graph.Edges {
		fromID, fromOk := labelToID[edge.From]
		toID, toOk := labelToID[edge.To]

		if !fromOk || !toOk || fromID == toID {
			// A self-reference can appear if two distinct graph nodes
			// resolved to the same package (e.g. duplicate metadata).
			continue
		}
		if seenRelationship[fromID] == nil {
			seenRelationship[fromID] = make(map[string]bool)
		}
		if seenRelationship[fromID][toID] {
			continue
		}
		seenRelationship[fromID][toID] = true
		relationships = append(relationships, &spdx.Relationship{
			RefA:         common.MakeDocElementID("", fromID),
			RefB:         common.MakeDocElementID("", toID),
			Relationship: "DEPENDS_ON",
		})
	}

	// Add DESCRIBES relationship from DOCUMENT to root component
	if classifications.RootComponent != nil {
		if rootID, ok := labelToID[classifications.RootComponent.Label]; ok {
			relationships = append(relationships, &spdx.Relationship{
				RefA:         common.MakeDocElementID("", "DOCUMENT"),
				RefB:         common.MakeDocElementID("", rootID),
				Relationship: "DESCRIBES",
			})
		}
	}

	if subjectName == "" {
		subjectName = "sbom"
		subjectPURL = "sbom"
	}
	if documentNamespace == "" {
		// 6.5: mandatory, must be unique to this document. Derived
		// deterministically from the subject's purl (rather than e.g. a
		// random UUID) so that re-generating the SBOM for an unchanged
		// dependency graph produces byte-identical output and stays
		// Bazel-cacheable.
		documentNamespace = "https://spdx.org/spdxdocs/" + url.PathEscape(subjectPURL)
	} else if err := spdxnamespace.Validate(documentNamespace); err != nil {
		return nil, fmt.Errorf("invalid document namespace: %w", err)
	}
	if subjectPackage != nil {
		if version := buildStatus.Version(); version != "" {
			subjectPackage.PackageVersion = version
		}
	}

	doc := spdx.Document{
		SPDXIdentifier: "DOCUMENT",
		SPDXVersion:    "SPDX-2.3",
		// 6.2: mandatory, and specifically "CC0-1.0" per the spec. This is
		// the license of the SPDX *metadata* document itself, independent of
		// the licenses of the packages it describes.
		DataLicense:       "CC0-1.0",
		DocumentName:      subjectName,
		DocumentNamespace: documentNamespace,
		Packages:          spdxPackages,
		Relationships:     relationships,
		CreationInfo: &spdx.CreationInfo{
			Creators: []common.Creator{
				{Creator: "Bazel Supply Chain Tools SPDX generator", CreatorType: "Tool"},
			},
			Created: buildStatus.Created.Format(time.RFC3339),
		},
	}

	return &doc, nil
}
