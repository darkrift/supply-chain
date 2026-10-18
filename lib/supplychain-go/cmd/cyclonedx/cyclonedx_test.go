package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePackage(t *testing.T, dir, name, licenseJSON string) sbom.NodeConfig {
	t.Helper()
	attributes := "{}"
	if licenseJSON != "" {
		licensePath := filepath.Join(dir, name+".license.json")
		require.NoError(t, os.WriteFile(licensePath, []byte(licenseJSON), 0o644))
		attributes = fmt.Sprintf(`{"build.bazel.attribute.license": %q}`, licensePath)
	}
	metadataPath := filepath.Join(dir, name+".metadata.json")
	require.NoError(t, os.WriteFile(metadataPath, []byte(fmt.Sprintf(
		`{"label": "@@//%s:package_metadata", "purl": "pkg:generic/%s@1.0.0", "attributes": %s}`,
		name, name, attributes,
	)), 0o644))
	return sbom.NodeConfig{Label: "//" + name, MetadataFile: metadataPath}
}

func TestGenerateBOMLicenses(t *testing.T) {
	dir := t.TempDir()

	none := writePackage(t, dir, "none", "")
	single := writePackage(t, dir, "single", `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//single:license"}`)
	deprecated := writePackage(t, dir, "deprecated", `{"kind":{"identifier":"GPL-2.0+","name":"GPL 2.0 or later"},"label":"//deprecated:license"}`)
	custom := writePackage(t, dir, "custom", `{"kind":{"identifier":"LicenseRef-acme","name":"ACME License"},"label":"//custom:license"}`)
	dual := writePackage(t, dir, "dual", `{"expression":{"operator":"OR","operands":[
		{"kind":{"identifier":"Apache-2.0","name":"Apache"}},
		{"kind":{"identifier":"MIT","name":"MIT License"}}]},"label":"//dual:license"}`)
	exception := writePackage(t, dir, "exception", `{"expression":{"operator":"OR","operands":[
		{"kind":{"identifier":"LicenseRef-acme","name":"ACME License"}},
		{"operator":"WITH","operands":[{"kind":{"identifier":"GPL-2.0-only","name":"GPL"}}],
		 "exception":{"identifier":"Classpath-exception-2.0","name":"Classpath"}}]},"label":"//exception:license"}`)

	bom, err := GenerateBOM(
		sbom.GraphConfig{},
		sbom.Classifications{
			Dependencies: sbom.DependencyNodes{
				Direct: []sbom.NodeConfig{none, single, deprecated, custom, dual, exception},
			},
		},
	)
	require.NoError(t, err)

	licenses := map[string]*cdx.Licenses{}
	for _, c := range *bom.Components {
		licenses[c.Name] = c.Licenses
	}

	assert.Nil(t, licenses["none"])
	assert.Equal(t, &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}}, licenses["single"])
	assert.Equal(t, &cdx.Licenses{{License: &cdx.License{ID: "GPL-2.0+"}}}, licenses["deprecated"])
	assert.Equal(t, &cdx.Licenses{{License: &cdx.License{Name: "ACME License"}}}, licenses["custom"])
	assert.Equal(t, &cdx.Licenses{{Expression: "Apache-2.0 OR MIT"}}, licenses["dual"])
	assert.Equal(t,
		&cdx.Licenses{{Expression: "LicenseRef-acme OR GPL-2.0-only WITH Classpath-exception-2.0"}},
		licenses["exception"],
	)
}

func writeConcluded(t *testing.T, dir string, requireResolved bool, licenses map[string]string) *sbom.ConcludedLicenses {
	t.Helper()
	entries := map[string]string{}
	for purl, licenseJSON := range licenses {
		path := filepath.Join(dir, fmt.Sprintf("concluded-%d.json", len(entries)))
		require.NoError(t, os.WriteFile(path, []byte(licenseJSON), 0o644))
		entries[purl] = path
	}
	manifest, err := json.Marshal(map[string]any{
		"licenses":                 entries,
		"require_resolved_choices": requireResolved,
	})
	require.NoError(t, err)
	manifestPath := filepath.Join(dir, "concluded.json")
	require.NoError(t, os.WriteFile(manifestPath, manifest, 0o644))

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

// The declared license of an overridden component is always kept as evidence.
func TestGenerateBOMConcludedLicenseKeepsDeclared(t *testing.T) {
	dir := t.TempDir()
	root := writePackage(t, dir, "root", `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//root:license"}`)
	custom := writePackage(t, dir, "custom", `{"expression":{"operator":"OR","operands":[
		{"kind":{"identifier":"LicenseRef-acme","name":"ACME License"}},
		{"kind":{"identifier":"MIT","name":"MIT License"}}]},"label":"//custom:license"}`)
	concluded := writeConcluded(t, dir, false, map[string]string{
		"pkg:generic/root@1.0.0":   `{"kind":{"identifier":"Apache-2.0","name":"Apache"},"label":"//legal"}`,
		"pkg:generic/custom@1.0.0": `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//legal"}`,
	})

	classifications := classify(custom)
	classifications.RootComponent = &root
	bom, err := GenerateBOM(sbom.GraphConfig{}, applied(t, concluded, classifications))
	require.NoError(t, err)

	require.NotNil(t, bom.Metadata.Component)
	assert.Equal(t, &cdx.Evidence{Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT", Acknowledgement: cdx.LicenseAcknowledgementDeclared}}}}, bom.Metadata.Component.Evidence)
	assert.Equal(t, &cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0", Acknowledgement: cdx.LicenseAcknowledgementConcluded}}}, bom.Metadata.Component.Licenses)

	require.Len(t, *bom.Components, 1)
	component := (*bom.Components)[0]
	assert.Equal(t, &cdx.Evidence{Licenses: &cdx.Licenses{{Expression: "LicenseRef-acme OR MIT"}}}, component.Evidence)
	assert.Equal(t, &cdx.Licenses{{License: &cdx.License{ID: "MIT", Acknowledgement: cdx.LicenseAcknowledgementConcluded}}}, component.Licenses)
}

func TestGenerateBOMConcludedLicenses(t *testing.T) {
	dir := t.TempDir()
	single := writePackage(t, dir, "single", `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//single:license"}`)
	dual := writePackage(t, dir, "dual", `{"expression":{"operator":"OR","operands":[
		{"kind":{"identifier":"Apache-2.0","name":"Apache"}},
		{"kind":{"identifier":"MIT","name":"MIT License"}}]},"label":"//dual:license"}`)
	compound := writePackage(t, dir, "compound", `{"expression":{"operator":"OR","operands":[
		{"kind":{"identifier":"Apache-2.0","name":"Apache"}},
		{"kind":{"identifier":"MIT","name":"MIT License"}}]},"label":"//compound:license"}`)
	none := writePackage(t, dir, "none", "")
	untouched := writePackage(t, dir, "untouched", `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//untouched:license"}`)

	concluded := writeConcluded(t, dir, false, map[string]string{
		"pkg:generic/single@1.0.0":   `{"kind":{"identifier":"LicenseRef-legal","name":"Legal"},"label":"//legal"}`,
		"pkg:generic/dual@1.0.0":     `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//legal"}`,
		"pkg:generic/compound@1.0.0": `{"expression":{"operator":"AND","operands":[{"kind":{"identifier":"MIT","name":"m"}},{"kind":{"identifier":"BSD-3-Clause","name":"b"}}]},"label":"//legal"}`,
		"pkg:generic/none@1.0.0":     `{"kind":{"identifier":"Apache-2.0","name":"Apache"},"label":"//legal"}`,
	})

	bom, err := GenerateBOM(sbom.GraphConfig{}, applied(t, concluded, classify(single, dual, compound, none, untouched)))
	require.NoError(t, err)

	components := map[string]cdx.Component{}
	for _, c := range *bom.Components {
		components[c.Name] = c
	}

	// The concluded license is the component license, the declared one is
	// evidence.
	assert.Equal(t,
		&cdx.Licenses{{License: &cdx.License{Name: "Legal", Acknowledgement: cdx.LicenseAcknowledgementConcluded}}},
		components["single"].Licenses)
	assert.Equal(t,
		&cdx.Evidence{Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT", Acknowledgement: cdx.LicenseAcknowledgementDeclared}}}},
		components["single"].Evidence)

	// Choosing one license of a choice.
	assert.Equal(t,
		&cdx.Licenses{{License: &cdx.License{ID: "MIT", Acknowledgement: cdx.LicenseAcknowledgementConcluded}}},
		components["dual"].Licenses)
	assert.Equal(t,
		&cdx.Evidence{Licenses: &cdx.Licenses{{Expression: "Apache-2.0 OR MIT"}}},
		components["dual"].Evidence)

	// Expressions carry no acknowledgement.
	assert.Equal(t, &cdx.Licenses{{Expression: "MIT AND BSD-3-Clause"}}, components["compound"].Licenses)

	// Nothing declared: there is no declared evidence.
	assert.Equal(t,
		&cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0", Acknowledgement: cdx.LicenseAcknowledgementConcluded}}},
		components["none"].Licenses)
	assert.Nil(t, components["none"].Evidence)

	// Without an override the declared license is the component license.
	assert.Equal(t, &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}}, components["untouched"].Licenses)
	assert.Nil(t, components["untouched"].Evidence)
}
