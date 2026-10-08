package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// ValidateJSONSchema validates instancePath against the root schema and any
// auxiliary schemas referenced by the root schema.
func ValidateJSONSchema(schemaPath string, auxPaths []string, instancePath string) error {
	data, err := os.ReadFile(instancePath)
	if err != nil {
		return fmt.Errorf("reading instance %s: %w", instancePath, err)
	}
	if err := ValidateJSONSchemaBytes(schemaPath, auxPaths, data); err != nil {
		return fmt.Errorf("%s does not conform to %s:\n\n%w", instancePath, schemaPath, err)
	}
	return nil
}

// ValidateJSONSchemaBytes validates instanceData against the root schema and
// any auxiliary schemas referenced by the root schema.
func ValidateJSONSchemaBytes(schemaPath string, auxPaths []string, instanceData []byte) error {
	compiler := jsonschema.NewCompiler()

	rootID, err := addSchemaResource(compiler, schemaPath)
	if err != nil {
		return fmt.Errorf("loading schema %s: %w", schemaPath, err)
	}

	for _, auxPath := range auxPaths {
		if _, err := addSchemaResource(compiler, auxPath); err != nil {
			return fmt.Errorf("loading auxiliary schema %s: %w", auxPath, err)
		}
	}

	schema, err := compiler.Compile(rootID)
	if err != nil {
		return fmt.Errorf("compiling schema %s: %w", schemaPath, err)
	}

	instance, err := decodeJSON(instanceData)
	if err != nil {
		return fmt.Errorf("reading instance: %w", err)
	}

	if err := schema.Validate(instance); err != nil {
		return err
	}
	return nil
}

// addSchemaResource reads a vendored schema file and registers it with the
// compiler under its own "$id", so that a "$ref" in another document which
// resolves to this same "$id" is served from this already-loaded resource
// instead of being fetched.
func addSchemaResource(compiler *jsonschema.Compiler, path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var meta struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", err
	}
	if meta.ID == "" {
		return "", fmt.Errorf("schema has no \"$id\"")
	}

	if err := compiler.AddResource(meta.ID, bytes.NewReader(data)); err != nil {
		return "", err
	}
	return meta.ID, nil
}

// decodeJSON decodes like encoding/json, but with UseNumber() so that
// schema.Validate sees the same number representation the jsonschema
// package itself uses when it loads a document, avoiding float64-precision
// mismatches on "type": "integer" checks.
func decodeJSON(data []byte) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var v interface{}
	if err := decoder.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
