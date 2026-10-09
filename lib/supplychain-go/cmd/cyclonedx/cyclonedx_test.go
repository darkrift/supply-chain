package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

func TestGenerateBOM_RetainsPackageEdgesAcrossAliasesAndWrappers(t *testing.T) {
	dir := t.TempDir()
	root := sbom.NodeConfig{Label: "//app:root", MetadataFile: writePackageMetadata(t, dir, "root.json", "//app:root", "pkg:bazel/app@1.0.0")}
	module := sbom.NodeConfig{Label: "//module:a", MetadataFile: writePackageMetadata(t, dir, "module.json", "//module:a", "pkg:golang/example.com/module@1.0.0")}
	alias := sbom.NodeConfig{Label: "//module:z", MetadataFile: module.MetadataFile}
	dep := sbom.NodeConfig{Label: "//dep:cbor", MetadataFile: writePackageMetadata(t, dir, "dep.json", "//dep:cbor", "pkg:golang/example.com/cbor@1.0.0")}
	graph := sbom.GraphConfig{
		RootTarget: root.Label,
		Nodes:      []sbom.NodeConfig{root, module, alias, dep, {Label: "//app:wrapper"}, {Label: "//module:wrapper"}},
		Edges: []sbom.EdgeConfig{
			{From: root.Label, To: "//app:wrapper", Type: "depends_on"},
			{From: "//app:wrapper", To: alias.Label, Type: "depends_on"},
			{From: alias.Label, To: "//module:wrapper", Type: "depends_on"},
			{From: "//module:wrapper", To: dep.Label, Type: "depends_on"},
		},
	}
	classifications, err := sbom.ComputeClassifications(graph, false)
	if err != nil {
		t.Fatal(err)
	}
	bom, err := GenerateBOM(graph, classifications, sbom.BuildStatus{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if bom.Dependencies == nil {
		t.Fatal("Dependencies is nil")
	}
	got := map[string][]string{}
	for _, dependency := range *bom.Dependencies {
		got[dependency.Ref] = *dependency.Dependencies
	}
	want := map[string][]string{
		"pkg:bazel/app@1.0.0":                 {"pkg:golang/example.com/module@1.0.0"},
		"pkg:golang/example.com/module@1.0.0": {"pkg:golang/example.com/cbor@1.0.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Dependencies = %v, want %v", got, want)
	}
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
		sbom.BuildStatus{},
		"",
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
		sbom.BuildStatus{},
		"",
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
		sbom.BuildStatus{},
		"",
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

func TestGenerateBOM_UsesBuildStatus(t *testing.T) {
	dir := t.TempDir()
	rootMeta := writePackageMetadata(t, dir, "root.json", "//app:root", "pkg:bazel/app@1.0.0")

	graph := sbom.GraphConfig{
		RootTarget: "//app:root",
		Nodes: []sbom.NodeConfig{
			{Label: "//app:root", MetadataFile: rootMeta},
		},
	}
	classifications := sbom.Classifications{
		RootComponent: &sbom.NodeConfig{Label: "//app:root", MetadataFile: rootMeta},
	}
	status := sbom.BuildStatus{
		Created:      time.Unix(1700000000, 0).UTC(),
		BuildVersion: "v1.2.3",
		VCSRevision:  "https://example.com/repo/commit/abc123",
	}

	bom, err := GenerateBOM(graph, classifications, status, "urn:uuid:11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatalf("GenerateBOM() error = %v", err)
	}
	if bom.SerialNumber != "urn:uuid:11111111-2222-3333-4444-555555555555" {
		t.Errorf("SerialNumber = %q, want stamped serial number", bom.SerialNumber)
	}
	if bom.Metadata == nil {
		t.Fatal("Metadata is nil")
	}
	if bom.Metadata.Timestamp != "2023-11-14T22:13:20Z" {
		t.Errorf("Metadata.Timestamp = %q, want timestamp from BUILD_TIMESTAMP", bom.Metadata.Timestamp)
	}
	if bom.Metadata.Component == nil {
		t.Fatal("Metadata.Component is nil")
	}
	if bom.Metadata.Component.Version != "v1.2.3" {
		t.Errorf("Metadata.Component.Version = %q, want stamped build version", bom.Metadata.Component.Version)
	}
	if bom.Metadata.Component.ExternalReferences == nil || len(*bom.Metadata.Component.ExternalReferences) != 1 {
		t.Fatalf("Metadata.Component.ExternalReferences = %v, want one VCS reference", bom.Metadata.Component.ExternalReferences)
	}
	ref := (*bom.Metadata.Component.ExternalReferences)[0]
	if string(ref.Type) != "vcs" || ref.URL != "https://example.com/repo/commit/abc123" {
		t.Errorf("VCS reference = (%q, %q), want stamped VCS revision", ref.Type, ref.URL)
	}
}

func TestReadSerialNumberRejectsInvalidValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serial.txt")
	if err := os.WriteFile(path, []byte("not-a-uuid\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := readSerialNumber(path); err == nil {
		t.Fatal("readSerialNumber() error = nil, want invalid serial number error")
	}
}

func TestGenerateBOM_PURLReferencesUseConsistentEncoding(t *testing.T) {
	dir := t.TempDir()
	root := sbom.NodeConfig{Label: "//app:root", MetadataFile: writePackageMetadata(t, dir, "root.json", "//app:root", "pkg:bazel/app@1.0.0")}
	dep := sbom.NodeConfig{Label: "//lib:dep", MetadataFile: writePackageMetadata(t, dir, "dep.json", "//lib:dep", "pkg:deb/debian/busybox-static@1%3A1.37.0-6%2Bb8?arch=amd64")}
	graph := sbom.GraphConfig{
		Edges: []sbom.EdgeConfig{{From: root.Label, To: dep.Label, Type: "depends_on"}},
	}
	classifications := sbom.Classifications{
		RootComponent: &root,
		Dependencies:  sbom.DependencyNodes{Direct: []sbom.NodeConfig{dep}},
	}
	bom, err := GenerateBOM(graph, classifications, sbom.BuildStatus{Created: time.Unix(0, 0).UTC()}, "")
	if err != nil {
		t.Fatal(err)
	}
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("Components = %v, want one dependency", bom.Components)
	}
	const want = "pkg:deb/debian/busybox-static@1:1.37.0-6%2Bb8?arch=amd64"
	component := (*bom.Components)[0]
	if component.PackageURL != want || component.BOMRef != want {
		t.Errorf("component references = (%q, %q), want %q", component.PackageURL, component.BOMRef, want)
	}
	if component.Version != "1:1.37.0-6+b8" {
		t.Errorf("Version = %q, want decoded version", component.Version)
	}
	if bom.Dependencies == nil || len(*bom.Dependencies) != 1 {
		t.Fatalf("Dependencies = %v, want one edge", bom.Dependencies)
	}
	dependency := (*bom.Dependencies)[0]
	if dependency.Dependencies == nil || len(*dependency.Dependencies) != 1 || (*dependency.Dependencies)[0] != want {
		t.Errorf("dependency references = %v, want %q", dependency.Dependencies, want)
	}
}
