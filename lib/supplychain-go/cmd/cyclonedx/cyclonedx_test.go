package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

func writePackageMetadata(t *testing.T, dir, name, label, purl string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	content := `{"label": "` + label + `", "purl": "` + purl + `", "attributes": {}}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func TestGenerateBOM_UsesPURLDownloadQualifier(t *testing.T) {
	dir := t.TempDir()
	depMeta := writePackageMetadata(t, dir, "dep.json", "//lib:dep", "pkg:golang/github.com/example/dep@v1.2.3?download_url=https://example.com/dep.tar.gz")

	bom, err := GenerateBOM(
		sbom.GraphConfig{
			Nodes: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
		},
		sbom.Classifications{
			Dependencies: sbom.DependencyNodes{
				Direct: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
			},
		},
	)
	if err != nil {
		t.Fatalf("GenerateBOM() error = %v", err)
	}

	assertDistributionReference(t, (*bom.Components)[0], "https://example.com/dep.tar.gz")
}

func TestGenerateBOM_UsesPURLURLDownloadQualifier(t *testing.T) {
	dir := t.TempDir()
	depMeta := writePackageMetadata(t, dir, "dep.json", "//lib:dep", "pkg:golang/github.com/example/dep@v1.2.3?url_download=https://example.com/dep.tar.gz")

	bom, err := GenerateBOM(
		sbom.GraphConfig{
			Nodes: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
		},
		sbom.Classifications{
			Dependencies: sbom.DependencyNodes{
				Direct: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
			},
		},
	)
	if err != nil {
		t.Fatalf("GenerateBOM() error = %v", err)
	}

	assertDistributionReference(t, (*bom.Components)[0], "https://example.com/dep.tar.gz")
}

func TestGenerateBOM_WithoutDownloadQualifierOmitsDistributionReference(t *testing.T) {
	dir := t.TempDir()
	depMeta := writePackageMetadata(t, dir, "dep.json", "//lib:dep", "pkg:golang/github.com/example/dep@v1.2.3")

	bom, err := GenerateBOM(
		sbom.GraphConfig{
			Nodes: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
		},
		sbom.Classifications{
			Dependencies: sbom.DependencyNodes{
				Direct: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
			},
		},
	)
	if err != nil {
		t.Fatalf("GenerateBOM() error = %v", err)
	}

	if refs := (*bom.Components)[0].ExternalReferences; refs != nil {
		t.Fatalf("ExternalReferences = %#v, want nil", *refs)
	}
	if licenses := (*bom.Components)[0].Licenses; licenses != nil {
		t.Fatalf("Licenses = %#v, want nil when no component license is known", *licenses)
	}
}

func assertDistributionReference(t *testing.T, component cdx.Component, wantURL string) {
	t.Helper()
	if component.ExternalReferences == nil {
		t.Fatal("ExternalReferences is nil, want distribution reference")
	}
	for _, ref := range *component.ExternalReferences {
		if ref.Type == cdx.ERTypeDistribution {
			if ref.URL != wantURL {
				t.Fatalf("distribution external reference URL = %q, want %q", ref.URL, wantURL)
			}
			return
		}
	}
	t.Fatalf("ExternalReferences = %#v, want distribution reference", *component.ExternalReferences)
}

func TestGenerateBOM_RetainsPackageEdges(t *testing.T) {
	for _, wrappers := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrappers=%t", wrappers), func(t *testing.T) {
			dir := t.TempDir()
			root := sbom.NodeConfig{Label: "//app:root", MetadataFile: writePackageMetadata(t, dir, "root.json", "//fixture:root", "pkg:golang/example.com/app@v1")}
			direct := sbom.NodeConfig{Label: "//module_a:library", MetadataFile: writePackageMetadata(t, dir, "direct.json", "//fixture:direct", "pkg:golang/example.com/module_a@v1")}
			dep := sbom.NodeConfig{Label: "//module_b:other", MetadataFile: writePackageMetadata(t, dir, "dep.json", "//fixture:dep", "pkg:golang/example.com/module_b@v1")}
			alias := sbom.NodeConfig{Label: "//module_b:used", MetadataFile: dep.MetadataFile}
			graph := sbom.GraphConfig{
				RootTarget: root.Label,
				Nodes:      []sbom.NodeConfig{root, direct, dep, alias},
				Edges: []sbom.EdgeConfig{
					{From: root.Label, To: direct.Label, Type: "depends_on"},
					{From: direct.Label, To: alias.Label, Type: "depends_on"},
					{From: alias.Label, To: dep.Label, Type: "depends_on"},
					{From: direct.Label, To: alias.Label, Type: "depends_on"},
				},
			}
			if wrappers {
				graph.Nodes = append(graph.Nodes, sbom.NodeConfig{Label: "//app:wrapper"}, sbom.NodeConfig{Label: "//module_a:wrapper"})
				graph.Edges[0].To = "//app:wrapper"
				graph.Edges[1].To = "//module_a:wrapper"
				graph.Edges[3].To = "//module_a:wrapper"
				graph.Edges = append(graph.Edges,
					sbom.EdgeConfig{From: "//app:wrapper", To: direct.Label, Type: "depends_on"},
					sbom.EdgeConfig{From: "//module_a:wrapper", To: alias.Label, Type: "depends_on"},
				)
			}
			classifications, err := sbom.ComputeClassifications(graph, false)
			if err != nil {
				t.Fatal(err)
			}
			bom, err := GenerateBOM(graph, classifications)
			if err != nil {
				t.Fatal(err)
			}
			if bom.Components == nil || len(*bom.Components) != 2 {
				t.Fatal("expected two dependency components")
			}
			if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.BOMRef != "pkg:golang/example.com/app@v1" {
				t.Fatal("expected app as root component")
			}
			if bom.Dependencies == nil {
				t.Fatal("dependencies is nil")
			}
			got := make(map[string][]string)
			for _, dependency := range *bom.Dependencies {
				if _, exists := got[dependency.Ref]; exists {
					t.Fatalf("duplicate dependency ref %s", dependency.Ref)
				}
				if dependency.Dependencies == nil {
					t.Fatalf("missing children for %s", dependency.Ref)
				}
				got[dependency.Ref] = *dependency.Dependencies
			}
			want := map[string][]string{
				"pkg:golang/example.com/app@v1":      {"pkg:golang/example.com/module_a@v1"},
				"pkg:golang/example.com/module_a@v1": {"pkg:golang/example.com/module_b@v1"},
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("dependencies = %v, want %v", got, want)
			}
		})
	}
}

func writeLicensedPackage(t *testing.T, dir, name, licenseJSON string) sbom.NodeConfig {
	t.Helper()
	attributes := "{}"
	if licenseJSON != "" {
		licensePath := filepath.Join(dir, name+".license.json")
		if err := os.WriteFile(licensePath, []byte(licenseJSON), 0o644); err != nil {
			t.Fatal(err)
		}
		attributes = fmt.Sprintf(`{"build.bazel.attribute.license": %q}`, licensePath)
	}
	path := filepath.Join(dir, name+".metadata.json")
	content := fmt.Sprintf(`{"label": "//fixture:%s", "purl": "pkg:generic/%s@1.0.0", "attributes": %s}`, name, name, attributes)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return sbom.NodeConfig{Label: "//" + name, MetadataFile: path}
}

func TestGenerateBOM_Licenses(t *testing.T) {
	dir := t.TempDir()
	nodes := []sbom.NodeConfig{
		writeLicensedPackage(t, dir, "none", ""),
		writeLicensedPackage(t, dir, "listed", `{"expression":{"kind":{"identifier":"MIT","name":"MIT License"}},"label":"//listed:license"}`),
		writeLicensedPackage(t, dir, "custom", `{"expression":{"kind":{"identifier":"LicenseRef-acme","name":"ACME License"}},"label":"//custom:license"}`),
		// Written by versions of the rule that predate `expression`.
		writeLicensedPackage(t, dir, "either", `{"expression":{"operator":"OR","operands":[{"kind":{"identifier":"MIT"}},{"kind":{"identifier":"Apache-2.0"}}]},"label":"//either:license"}`),
		writeLicensedPackage(t, dir, "orlater", `{"expression":{"or_later":true,"kind":{"identifier":"GPL-3.0"}},"label":"//orlater:license"}`),
		writeLicensedPackage(t, dir, "legacy", `{"kind":{"identifier":"Apache-2.0","name":"Apache"},"label":"//legacy:license"}`),
	}

	bom, err := GenerateBOM(sbom.GraphConfig{}, sbom.Classifications{
		Dependencies: sbom.DependencyNodes{Direct: nodes},
	})
	if err != nil {
		t.Fatalf("GenerateBOM() error = %v", err)
	}

	got := map[string]*cdx.Licenses{}
	for _, component := range *bom.Components {
		got[component.Name] = component.Licenses
	}
	want := map[string]*cdx.Licenses{
		"none":    nil,
		"listed":  {{License: &cdx.License{ID: "MIT"}}},
		"custom":  {{License: &cdx.License{Name: "ACME License"}}},
		"either":  {{Expression: "MIT OR Apache-2.0"}},
		"orlater": {{Expression: "GPL-3.0+"}},
		"legacy":  {{License: &cdx.License{ID: "Apache-2.0"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("licenses = %v, want %v", got, want)
	}
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
