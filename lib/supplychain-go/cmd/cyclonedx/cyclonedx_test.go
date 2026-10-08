package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

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
