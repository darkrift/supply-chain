// Command schemavalidate validates a JSON document against a JSON Schema,
// entirely offline.
//
// It is meant to back a Bazel validation action (see
// https://bazel.build/extending/rules#validation-actions): the schema and
// any auxiliary schemas it references via "$ref" must be supplied as inputs
// (--schema / --aux_schema), and on success the tool writes --output, which
// the calling rule declares as its validation action's output.
//
// This package deliberately does not import
// github.com/santhosh-tekuri/jsonschema/v5/httploader (or any other loader
// extension), so the only registered URL scheme is "file". A schema that
// references a URL not supplied via --schema/--aux_schema fails the build
// with a clear "no Loader found" error instead of silently reaching out to
// the network.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

func main() {
	var schemaPath, instancePath, outputPath string
	var auxPaths stringList

	flag.StringVar(&schemaPath, "schema", "", "Path to the root JSON Schema document.")
	flag.StringVar(&instancePath, "instance", "", "Path to the JSON document to validate.")
	flag.StringVar(&outputPath, "output", "", "Path to write on successful validation.")
	flag.Var(&auxPaths, "aux_schema", "Path to an additional schema referenced by --schema via \"$ref\" (repeatable). Registered under its own \"$id\".")
	flag.Parse()

	if schemaPath == "" || instancePath == "" || outputPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --schema, --instance and --output are required")
		os.Exit(1)
	}

	if err := run(schemaPath, auxPaths, instancePath, outputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(schemaPath string, auxPaths []string, instancePath, outputPath string) error {
	if err := sbom.ValidateJSONSchema(schemaPath, auxPaths, instancePath); err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, []byte("OK\n"), 0o644); err != nil {
		return fmt.Errorf("writing output %s: %w", outputPath, err)
	}
	return nil
}

type stringList []string

func (s *stringList) String() string {
	return fmt.Sprint([]string(*s))
}

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
