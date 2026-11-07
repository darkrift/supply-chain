package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

func main() {
	var inPath, outPath, format, buildStatusPath, stableStatusPath, serialNumberPath, validatorPath string
	flag.StringVar(&inPath, "in", "", "The path to the generated CycloneDX SBOM.")
	flag.StringVar(&outPath, "out", "", "The path to write the stamped CycloneDX SBOM.")
	flag.StringVar(&format, "format", "json", "The output format of the CycloneDX SBOM (json or xml).")
	flag.StringVar(&buildStatusPath, "created_from_status_file", "", "Path to a Bazel volatile-status.txt file to read BUILD_TIMESTAMP and stable build identity values from.")
	flag.StringVar(&stableStatusPath, "stable_status_file", "", "Path to a Bazel stable-status.txt file to read stable build identity values from.")
	flag.StringVar(&serialNumberPath, "serial_number_file", "", "Path to a file containing the CycloneDX BOM serialNumber.")
	flag.StringVar(&validatorPath, "validator", "", "Optional runfiles path or executable path to the CycloneDX CLI validator.")
	flag.Parse()

	if inPath == "" || outPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --in and --out flags are required")
		os.Exit(1)
	}

	if err := run(inPath, outPath, format, buildStatusPath, stableStatusPath, serialNumberPath, validatorPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error stamping BOM: %v\n", err)
		os.Exit(1)
	}
}

func run(inPath, outPath, format, buildStatusPath, stableStatusPath, serialNumberPath, validatorPath string) error {
	input, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer input.Close()

	fileFormat, err := parseFormat(format)
	if err != nil {
		return err
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(input, fileFormat).Decode(&bom); err != nil {
		return fmt.Errorf("decoding input: %w", err)
	}

	buildStatus, err := sbom.ReadBuildStatus(buildStatusPath, stableStatusPath)
	if err != nil {
		return fmt.Errorf("reading build status file: %w", err)
	}
	serialNumber, err := readSerialNumber(serialNumberPath)
	if err != nil {
		return fmt.Errorf("reading serial number file: %w", err)
	}
	stampBOM(&bom, buildStatus, serialNumber)

	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, fileFormat).Encode(&bom); err != nil {
		return fmt.Errorf("encoding stamped BOM: %w", err)
	}

	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}
	if validatorPath != "" {
		if err := sbom.RunValidator(validatorPath, "validate", "--input-file", outPath, "--input-format", format, "--input-version", "v1_6", "--fail-on-errors"); err != nil {
			return fmt.Errorf("validating BOM: %w", err)
		}
	}
	return nil
}

func stampBOM(bom *cdx.BOM, buildStatus sbom.BuildStatus, serialNumber string) {
	if serialNumber == "" {
		serialNumber = buildStatus.SerialNumber
	}
	if serialNumber != "" {
		bom.SerialNumber = serialNumber
	}
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	bom.Metadata.Timestamp = buildStatus.Created.Format(time.RFC3339)
	if bom.Metadata.Component != nil {
		if version := buildStatus.Version(); version != "" {
			bom.Metadata.Component.Version = version
		}
		if revisionURL := buildStatus.RevisionURL(); revisionURL != "" {
			references := replaceOrAppendExternalReference(bom.Metadata.Component.ExternalReferences, cdx.ExternalReference{
				Type: cdx.ERTypeVCS,
				URL:  revisionURL,
			})
			bom.Metadata.Component.ExternalReferences = &references
		}
	}
}

func parseFormat(format string) (cdx.BOMFileFormat, error) {
	switch format {
	case "json":
		return cdx.BOMFileFormatJSON, nil
	case "xml":
		return cdx.BOMFileFormatXML, nil
	default:
		return 0, fmt.Errorf("'%s' is not a supported format. Use 'json' or 'xml'", format)
	}
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

func replaceOrAppendExternalReference(existing *[]cdx.ExternalReference, reference cdx.ExternalReference) []cdx.ExternalReference {
	if existing == nil {
		return []cdx.ExternalReference{reference}
	}
	references := append([]cdx.ExternalReference{}, *existing...)
	for i := range references {
		if references[i].Type == reference.Type && references[i].URL == "urn:vcs:revision:unknown" {
			references[i] = reference
			return references
		}
	}
	references = append(references, reference)
	return references
}
