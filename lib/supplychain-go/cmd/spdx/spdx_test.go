package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// writePackage writes a package_metadata file, optionally with a license
// attribute, and returns the node for it.
func writePackage(t *testing.T, dir, name, licenseJSON string) sbom.NodeConfig {
	t.Helper()
	attributes := "{}"
	if licenseJSON != "" {
		licensePath := filepath.Join(dir, name+".license.json")
		writeFile(t, licensePath, licenseJSON)
		attributes = fmt.Sprintf(`{"build.bazel.attribute.license": %q}`, licensePath)
	}
	metadataPath := filepath.Join(dir, name+".metadata.json")
	writeFile(t, metadataPath, fmt.Sprintf(
		`{"label": "@@//%s:package_metadata", "purl": "pkg:generic/%s@1.0.0", "attributes": %s}`,
		name, name, attributes,
	))
	return sbom.NodeConfig{Label: "//" + name, MetadataFile: metadataPath}
}

func TestGenerateDocumentLicenses(t *testing.T) {
	dir := t.TempDir()
	textPath := filepath.Join(dir, "LICENSE")
	writeFile(t, textPath, "ACME license text")

	root := writePackage(t, dir, "root", "")
	single := writePackage(t, dir, "single", `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//single:license"}`)
	custom := writePackage(t, dir, "custom", fmt.Sprintf(
		`{"kind":{"identifier":"LicenseRef-acme","name":"ACME License"},"label":"//custom:license","text":%q}`, textPath))
	dual := writePackage(t, dir, "dual", `{"expression":{"operator":"OR","operands":[
		{"kind":{"identifier":"MIT","name":"MIT License"}},
		{"kind":{"identifier":"LicenseRef-acme","name":"ACME License"}}]},"label":"//dual:license"}`)
	exception := writePackage(t, dir, "exception", `{"expression":{"operator":"WITH","operands":[
		{"kind":{"identifier":"GPL-2.0-only","name":"GPL"}}],
		"exception":{"identifier":"AdditionRef-link","name":"Linking"}},"label":"//exception:license"}`)

	doc, err := GenerateDocument(
		sbom.GraphConfig{},
		sbom.Classifications{
			RootComponent: &root,
			Dependencies: sbom.DependencyNodes{
				Direct: []sbom.NodeConfig{single, custom, dual, exception},
			},
		},
	)
	require.NoError(t, err)

	declared := map[string]string{}
	for _, p := range doc.Packages {
		declared[p.PackageName] = p.PackageLicenseDeclared

		// Without an override, the concluded license is the declared one.
		assert.Equal(t, p.PackageLicenseDeclared, p.PackageLicenseConcluded, p.PackageName)
	}
	assert.Equal(t, map[string]string{
		"root":      "NOASSERTION",
		"single":    "MIT",
		"custom":    "LicenseRef-acme",
		"dual":      "MIT OR LicenseRef-acme",
		"exception": "GPL-2.0-only WITH AdditionRef-link",
	}, declared)

	// The custom license is defined once, with its text, and the custom
	// exception is not defined as a license.
	require.Len(t, doc.OtherLicenses, 1)
	assert.Equal(t, "LicenseRef-acme", doc.OtherLicenses[0].LicenseIdentifier)
	assert.Equal(t, "ACME License", doc.OtherLicenses[0].LicenseName)
	assert.Equal(t, "ACME license text", doc.OtherLicenses[0].ExtractedText)
}

// writeConcluded writes a concluded licenses manifest and loads it.
func writeConcluded(t *testing.T, dir string, requireResolved bool, licenses map[string]string) *sbom.ConcludedLicenses {
	t.Helper()
	entries := map[string]string{}
	for purl, licenseJSON := range licenses {
		path := filepath.Join(dir, fmt.Sprintf("concluded-%d.json", len(entries)))
		writeFile(t, path, licenseJSON)
		entries[purl] = path
	}
	manifest, err := json.Marshal(map[string]any{
		"licenses":                 entries,
		"require_resolved_choices": requireResolved,
	})
	require.NoError(t, err)
	manifestPath := filepath.Join(dir, "concluded.json")
	writeFile(t, manifestPath, string(manifest))

	concluded, err := sbom.LoadConcludedLicenses(manifestPath)
	require.NoError(t, err)
	return concluded
}

func applied(t *testing.T, concluded *sbom.ConcludedLicenses, classifications sbom.Classifications) sbom.Classifications {
	t.Helper()
	require.NoError(t, concluded.Apply(&classifications))
	return classifications
}

func classify(nodes ...sbom.NodeConfig) sbom.Classifications {
	return sbom.Classifications{Dependencies: sbom.DependencyNodes{Direct: nodes}}
}

func TestGenerateDocumentConcludedLicenses(t *testing.T) {
	dir := t.TempDir()
	dual := writePackage(t, dir, "dual", `{"expression":{"operator":"OR","operands":[
		{"kind":{"identifier":"MIT","name":"MIT License"}},
		{"kind":{"identifier":"Apache-2.0","name":"Apache"}}]},"label":"//dual:license"}`)
	other := writePackage(t, dir, "other", `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//other:license"}`)

	concluded := writeConcluded(t, dir, false, map[string]string{
		"pkg:generic/dual@1.0.0": `{"kind":{"identifier":"LicenseRef-legal","name":"Legal"},"label":"//legal"}`,
	})

	doc, err := GenerateDocument(sbom.GraphConfig{}, applied(t, concluded, classify(dual, other)))
	require.NoError(t, err)

	type licenses struct{ Declared, Concluded string }
	got := map[string]licenses{}
	for _, p := range doc.Packages {
		got[p.PackageName] = licenses{p.PackageLicenseDeclared, p.PackageLicenseConcluded}
	}
	assert.Equal(t, map[string]licenses{
		// The declared license is kept, the conclusion overrides it.
		"dual":  {"MIT OR Apache-2.0", "LicenseRef-legal"},
		"other": {"MIT", "MIT"},
	}, got)

	// Custom licenses used by a conclusion are defined in the document.
	require.Len(t, doc.OtherLicenses, 1)
	assert.Equal(t, "LicenseRef-legal", doc.OtherLicenses[0].LicenseIdentifier)
}

func TestGenerateDocumentConcludedLicenseOfRoot(t *testing.T) {
	dir := t.TempDir()
	root := writePackage(t, dir, "root", `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//root:license"}`)
	concluded := writeConcluded(t, dir, false, map[string]string{
		"pkg:generic/root@1.0.0": `{"kind":{"identifier":"Apache-2.0","name":"Apache"},"label":"//legal"}`,
	})

	doc, err := GenerateDocument(sbom.GraphConfig{}, applied(t, concluded, sbom.Classifications{RootComponent: &root}))
	require.NoError(t, err)
	require.Len(t, doc.Packages, 1)
	assert.Equal(t, "MIT", doc.Packages[0].PackageLicenseDeclared)
	assert.Equal(t, "Apache-2.0", doc.Packages[0].PackageLicenseConcluded)
}

// A concluded license never replaces the declared one, including the custom
// licenses it references.
func TestGenerateDocumentConcludedLicenseKeepsDeclared(t *testing.T) {
	dir := t.TempDir()
	custom := writePackage(t, dir, "custom", `{"expression":{"operator":"OR","operands":[
		{"kind":{"identifier":"LicenseRef-acme","name":"ACME License"}},
		{"kind":{"identifier":"MIT","name":"MIT License"}}]},"label":"//custom:license"}`)
	concluded := writeConcluded(t, dir, false, map[string]string{
		"pkg:generic/custom@1.0.0": `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//legal"}`,
	})

	doc, err := GenerateDocument(sbom.GraphConfig{}, applied(t, concluded, classify(custom)))
	require.NoError(t, err)
	require.Len(t, doc.Packages, 1)
	assert.Equal(t, "LicenseRef-acme OR MIT", doc.Packages[0].PackageLicenseDeclared)
	assert.Equal(t, "MIT", doc.Packages[0].PackageLicenseConcluded)

	require.Len(t, doc.OtherLicenses, 1)
	assert.Equal(t, "LicenseRef-acme", doc.OtherLicenses[0].LicenseIdentifier)
}
