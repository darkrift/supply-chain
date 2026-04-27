package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	supplychain "github.com/bazel-contrib/supply-chain/lib/supplychain-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
	spdxJson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdxTV "github.com/spdx/tools-golang/tagvalue"
	spdxYaml "github.com/spdx/tools-golang/yaml"
)

const subjectSPDXID = "SPDXRef-Subject"

func main() {
	var outPath, configPath, format string
	flag.StringVar(&outPath, "out", "", "The path to write the generated SPDX SBOM.")
	flag.StringVar(&configPath, "config", "", "The path to the SBOM generation configuration file.")
	flag.StringVar(&format, "format", "json", "The output format of the SPDX SBOM.")
	flag.Parse()
	var config sbom.GenConfig

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		panic(err)
	}

	json.Unmarshal(configBytes, &config)

	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	doc, err := GenerateDocument(config)
	if err != nil {
		panic(err)
	}

	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	switch format {
	case "json":
		must(spdxJson.Write(doc, out))
	case "yaml":
		must(spdxYaml.Write(doc, out))
	case "tag-value":
		must(spdxTV.Write(doc, out))
	default:
		panic(fmt.Sprintf("'%s' is not a supported format", format))
	}
}

func GenerateDocument(config sbom.GenConfig) (*spdx.Document, error) {
	packages := make([]*spdx.Package, 0, len(config.Nodes)+1)
	packageIDs := make(map[string]common.ElementID, len(config.Nodes)+1)
	labelToPackageIDs := make(map[string]common.ElementID, len(config.Nodes)+1)

	subjectPackage := &spdx.Package{
		PackageSPDXIdentifier: common.ElementID(subjectSPDXID),
		PackageName:           config.Subject.Label,
	}
	packages = append(packages, subjectPackage)
	packageIDs[config.Subject.Label] = common.ElementID(subjectSPDXID)
	labelToPackageIDs[config.Subject.Label] = common.ElementID(subjectSPDXID)

	for i, node := range config.Nodes {
		pkgMetadata, err := supplychain.ReadPackageMetadataFromFile(node.Metadata)
		if err != nil {
			return nil, err
		}

		purl := pkgMetadata.GetPURL()
		elementID := common.ElementID(fmt.Sprintf("SPDXRef-Node-%d", i))
		packageIDs[node.ID] = elementID
		labelToPackageIDs[node.Label] = elementID

		pkg := &spdx.Package{
			PackageSPDXIdentifier: elementID,
			PackageExternalReferences: []*spdx.PackageExternalReference{
				{
					Category: "PACKAGE-MANAGER",
					RefType:  "purl",
					Locator:  purl.String(),
				},
			},
			PackageName: purl.Name,
		}
		if purl.Version != "" {
			pkg.PackageVersion = purl.Version
		}
		packages = append(packages, pkg)
	}

	relationships := []*spdx.Relationship{
		{
			RefA:         common.MakeDocElementID("", "DOCUMENT"),
			RefB:         common.MakeDocElementID("", string(common.ElementID(subjectSPDXID))),
			Relationship: "DESCRIBES",
		},
	}

	for _, rel := range config.Relationships {
		toID, ok := packageIDs[rel.To]
		if !ok {
			continue
		}
		fromID, ok := labelToPackageIDs[rel.From]
		if !ok && rel.Origin == "dependency" {
			fromID = common.ElementID(subjectSPDXID)
			ok = true
		}
		if !ok {
			continue
		}
		relationship := &spdx.Relationship{
			RefA:         common.MakeDocElementID("", string(fromID)),
			RefB:         common.MakeDocElementID("", string(toID)),
			Relationship: relationshipType(rel.Relationship),
		}
		if comment := relationshipComment(rel); comment != "" {
			relationship.RelationshipComment = comment
		}
		relationships = append(relationships, relationship)
	}

	doc := spdx.Document{
		SPDXIdentifier: "SPDXRef-DOCUMENT",
		SPDXVersion:    "SPDX-2.3",
		Packages:       packages,
		Relationships:  relationships,
		CreationInfo:   &spdx.CreationInfo{},
	}

	return &doc, nil
}

func relationshipType(kind string) string {
	switch kind {
	case "build_tool":
		return "BUILD_TOOL_OF"
	case "build_dependency":
		return "BUILD_DEPENDENCY_OF"
	case "runtime_dependency":
		return "RUNTIME_DEPENDENCY_OF"
	case "provided_runtime":
		return "PROVIDED_DEPENDENCY_OF"
	case "static_link":
		return "STATIC_LINK"
	case "dynamic_link":
		return "DYNAMIC_LINK"
	default:
		return "DEPENDS_ON"
	}
}

func relationshipComment(rel sbom.RelationshipConfig) string {
	parts := make([]string, 0, 4)
	if rel.Origin != "" {
		parts = append(parts, "origin="+rel.Origin)
	}
	if rel.AppliesTo != "" {
		parts = append(parts, "applies_to="+rel.AppliesTo)
	}
	if rel.ToolchainType != "" {
		parts = append(parts, "toolchain_type="+rel.ToolchainType)
	}
	if rel.ToolchainLabel != "" {
		parts = append(parts, "toolchain_label="+rel.ToolchainLabel)
	}
	if rel.Notes != "" {
		parts = append(parts, "notes="+rel.Notes)
	}
	return strings.Join(parts, ", ")
}
