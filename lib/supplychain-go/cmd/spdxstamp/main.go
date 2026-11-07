package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/spdxnamespace"
)

func main() {
	var inPath, outPath, buildStatusPath, stableStatusPath, documentNamespacePath, validatorPath string
	flag.StringVar(&inPath, "in", "", "The path to the generated SPDX 3.0.1 SBOM (JSON-LD).")
	flag.StringVar(&outPath, "out", "", "The path to write the stamped SPDX SBOM.")
	flag.StringVar(&buildStatusPath, "created_from_status_file", "", "Path to a Bazel volatile-status.txt file to read BUILD_TIMESTAMP and stable build identity values from.")
	flag.StringVar(&stableStatusPath, "stable_status_file", "", "Path to a Bazel stable-status.txt file to read stable build identity values from.")
	flag.StringVar(&documentNamespacePath, "document_namespace_file", "", "Path to a file whose content is used as the SPDX document namespace.")
	flag.StringVar(&validatorPath, "validator", "", "Optional runfiles path or executable path to the SPDX tools-java validator wrapper.")
	flag.Parse()

	if inPath == "" || outPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --in and --out flags are required")
		os.Exit(1)
	}

	if err := run(inPath, outPath, buildStatusPath, stableStatusPath, documentNamespacePath, validatorPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error stamping document: %v\n", err)
		os.Exit(1)
	}
}

func run(inPath, outPath, buildStatusPath, stableStatusPath, documentNamespacePath, validatorPath string) error {
	input, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var doc struct {
		Context string           `json:"@context"`
		Graph   []map[string]any `json:"@graph"`
	}
	if err := json.Unmarshal(input, &doc); err != nil {
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
	if err := stampGraph(doc.Graph, buildStatus, documentNamespace); err != nil {
		return err
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
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

// stampGraph sets the creation time, the document namespace and the version of
// the subject package (the first one, which is the root component when there
// is one) in the JSON-LD graph written by cmd/spdx.
func stampGraph(graph []map[string]any, buildStatus sbom.BuildStatus, documentNamespace string) error {
	created := false
	for _, node := range graph {
		switch node["type"] {
		case "CreationInfo":
			node["created"] = buildStatus.Created.UTC().Format(time.RFC3339)
			created = true
		case "SpdxDocument":
			if documentNamespace == "" {
				continue
			}
			if err := spdxnamespace.Validate(documentNamespace); err != nil {
				return fmt.Errorf("invalid document namespace: %w", err)
			}
			node["spdxId"] = documentNamespace
			namespaces, _ := node["namespaceMap"].([]any)
			for _, entry := range namespaces {
				if namespace, ok := entry.(map[string]any); ok && namespace["prefix"] == "SPDXRef" {
					namespace["namespace"] = documentNamespace + "#"
				}
			}
		case "software_Package":
			if version := buildStatus.Version(); version != "" && node["spdxId"] == "SPDXRef:dep-0" {
				node["software_packageVersion"] = version
			}
		}
	}
	if !created {
		return fmt.Errorf("document has no CreationInfo")
	}
	return nil
}
