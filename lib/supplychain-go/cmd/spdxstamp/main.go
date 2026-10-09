package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/spdxnamespace"
	spdxJson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	spdxTV "github.com/spdx/tools-golang/tagvalue"
	spdxYaml "github.com/spdx/tools-golang/yaml"
)

func main() {
	var inPath, outPath, format, buildStatusPath, stableStatusPath, documentNamespacePath, validatorPath string
	flag.StringVar(&inPath, "in", "", "The path to the generated SPDX SBOM.")
	flag.StringVar(&outPath, "out", "", "The path to write the stamped SPDX SBOM.")
	flag.StringVar(&format, "format", "json", "The output format of the SPDX SBOM.")
	flag.StringVar(&buildStatusPath, "created_from_status_file", "", "Path to a Bazel volatile-status.txt file to read BUILD_TIMESTAMP and stable build identity values from.")
	flag.StringVar(&stableStatusPath, "stable_status_file", "", "Path to a Bazel stable-status.txt file to read stable build identity values from.")
	flag.StringVar(&documentNamespacePath, "document_namespace_file", "", "Path to a file whose content is used as the SPDX document namespace.")
	flag.StringVar(&validatorPath, "validator", "", "Optional runfiles path or executable path to the SPDX tools-java validator wrapper.")
	flag.Parse()

	if inPath == "" || outPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --in and --out flags are required")
		os.Exit(1)
	}

	if err := run(inPath, outPath, format, buildStatusPath, stableStatusPath, documentNamespacePath, validatorPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error stamping document: %v\n", err)
		os.Exit(1)
	}
}

func run(inPath, outPath, format, buildStatusPath, stableStatusPath, documentNamespacePath, validatorPath string) error {
	input, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer input.Close()

	doc, err := readDocument(input, format)
	if err != nil {
		return fmt.Errorf("decoding input: %w", err)
	}

	buildStatus, err := sbom.ReadBuildStatus(buildStatusPath, stableStatusPath)
	if err != nil {
		return fmt.Errorf("reading build status file: %w", err)
	}
	documentNamespace, err := spdxnamespace.ReadFile(documentNamespacePath)
	if err != nil {
		return fmt.Errorf("reading document namespace file: %w", err)
	}
	if err := stampDocument(doc, buildStatus, documentNamespace); err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := writeDocument(doc, format, &buf); err != nil {
		return fmt.Errorf("encoding stamped document: %w", err)
	}

	if err := os.WriteFile(outPath, buf.Bytes(), 0o664); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}
	if validatorPath != "" {
		if err := sbom.RunValidator(validatorPath, outPath); err != nil {
			return fmt.Errorf("validating document: %w", err)
		}
	}
	return nil
}

func stampDocument(doc *spdx.Document, buildStatus sbom.BuildStatus, documentNamespace string) error {
	if doc.CreationInfo == nil {
		return fmt.Errorf("document has nil creationInfo")
	}
	doc.CreationInfo.Created = buildStatus.Created.Format(time.RFC3339)
	if documentNamespace != "" {
		doc.DocumentNamespace = documentNamespace
	}
	if err := spdxnamespace.Validate(doc.DocumentNamespace); err != nil {
		return fmt.Errorf("invalid document namespace: %w", err)
	}
	if len(doc.Packages) > 0 {
		if version := buildStatus.Version(); version != "" {
			doc.Packages[0].PackageVersion = version
		}
	}
	return nil
}

func readDocument(input *os.File, format string) (*spdx.Document, error) {
	switch format {
	case "json":
		return spdxJson.Read(input)
	case "yaml":
		return spdxYaml.Read(input)
	case "tag-value":
		return spdxTV.Read(input)
	default:
		return nil, fmt.Errorf("'%s' is not a supported format", format)
	}
}

func writeDocument(doc *spdx.Document, format string, output *bytes.Buffer) error {
	switch format {
	case "json":
		return spdxJson.Write(doc, output)
	case "yaml":
		return spdxYaml.Write(doc, output)
	case "tag-value":
		return spdxTV.Write(doc, output)
	default:
		return fmt.Errorf("'%s' is not a supported format", format)
	}
}
