package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestGenerateDocument_RetainsPackageEdgesAcrossAliasesAndWrappers(t *testing.T) {
	dir := t.TempDir()
	root := writePackageMetadata(t, dir, "root.json", "//app:root", "pkg:bazel/app@1")
	module := writePackageMetadata(t, dir, "module.json", "//module:a", "pkg:golang/example.com/module@v1")
	dep := writePackageMetadata(t, dir, "dep.json", "//dep:dep", "pkg:golang/example.com/dep@v1")
	graph := sbom.GraphConfig{
		RootTarget: "//app:root",
		Nodes: []sbom.NodeConfig{
			{Label: "//app:root", MetadataFile: root},
			{Label: "//app:wrapper"},
			{Label: "//module:a", MetadataFile: module},
			{Label: "//module:z", MetadataFile: module},
			{Label: "//module:wrapper"},
			{Label: "//dep:dep", MetadataFile: dep},
		},
		Edges: []sbom.EdgeConfig{
			{From: "//app:root", To: "//app:wrapper", Type: "depends_on"},
			{From: "//app:wrapper", To: "//module:z", Type: "depends_on"},
			{From: "//module:z", To: "//module:a", Type: "depends_on"},
			{From: "//module:z", To: "//module:wrapper", Type: "depends_on"},
			{From: "//module:wrapper", To: "//dep:dep", Type: "depends_on"},
		},
	}
	classifications, err := sbom.ComputeClassifications(graph, false)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := GenerateDocument(graph, classifications, sbom.BuildStatus{}, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var output struct {
		Packages      []struct{ SPDXID string }
		Relationships []struct {
			SpdxElementId      string
			RelatedSpdxElement string
			RelationshipType   string
		}
	}
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Packages) != 3 {
		t.Fatalf("got %d packages, want 3", len(output.Packages))
	}
	want := map[string]bool{
		"SPDXRef-dep-0 DEPENDS_ON SPDXRef-dep-1":   true,
		"SPDXRef-dep-1 DEPENDS_ON SPDXRef-dep-2":   true,
		"SPDXRef-DOCUMENT DESCRIBES SPDXRef-dep-0": true,
	}
	for _, relationship := range output.Relationships {
		key := relationship.SpdxElementId + " " + relationship.RelationshipType + " " + relationship.RelatedSpdxElement
		if !want[key] {
			t.Errorf("unexpected relationship %s", key)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("missing relationships: %v", want)
	}
}

func TestGenerateDocument_RequiredFieldsPopulated(t *testing.T) {
	dir := t.TempDir()
	rootMeta := writePackageMetadata(t, dir, "root.json", "//app:root", "pkg:bazel/app@1.0.0")
	depMeta := writePackageMetadata(t, dir, "dep.json", "//lib:dep", "pkg:golang/github.com/example/dep@v1.2.3")

	graph := sbom.GraphConfig{
		RootTarget: "//app:root",
		Nodes: []sbom.NodeConfig{
			{Label: "//app:root", MetadataFile: rootMeta},
			{Label: "//lib:dep", MetadataFile: depMeta},
		},
		Edges: []sbom.EdgeConfig{
			{From: "//app:root", To: "//lib:dep", Type: "depends_on"},
		},
	}
	classifications := sbom.Classifications{
		RootComponent: &sbom.NodeConfig{Label: "//app:root", MetadataFile: rootMeta},
		Dependencies: sbom.DependencyNodes{
			Direct: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
		},
	}

	created := time.Unix(1700000000, 0).UTC()
	doc, err := GenerateDocument(graph, classifications, sbom.BuildStatus{Created: created}, "")
	if err != nil {
		t.Fatalf("GenerateDocument() error = %v", err)
	}

	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("DataLicense = %q, want %q", doc.DataLicense, "CC0-1.0")
	}
	if doc.DocumentName == "" {
		t.Error("DocumentName is empty, want the root component's name")
	}
	if doc.DocumentNamespace == "" {
		t.Error("DocumentNamespace is empty, want a namespace derived from the root component")
	}
	if doc.CreationInfo == nil {
		t.Fatal("CreationInfo is nil")
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("CreationInfo.Creators is empty, want at least one Tool creator")
	}
	wantCreated := "2023-11-14T22:13:20Z"
	if doc.CreationInfo.Created != wantCreated {
		t.Errorf("CreationInfo.Created = %q, want %q", doc.CreationInfo.Created, wantCreated)
	}
	for _, pkg := range doc.Packages {
		if pkg.PackageDownloadLocation == "" {
			t.Errorf("PackageDownloadLocation for %s is empty, want an SPDX sentinel value", pkg.PackageName)
		}
		if pkg.PackageLicenseConcluded != "NOASSERTION" {
			t.Errorf("PackageLicenseConcluded for %s = %q, want NOASSERTION", pkg.PackageName, pkg.PackageLicenseConcluded)
		}
		if pkg.PackageLicenseDeclared != "NOASSERTION" {
			t.Errorf("PackageLicenseDeclared for %s = %q, want NOASSERTION", pkg.PackageName, pkg.PackageLicenseDeclared)
		}
	}
}

func TestGenerateDocument_UsesBuildStatusVersionForSubjectPackage(t *testing.T) {
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

	doc, err := GenerateDocument(graph, classifications, sbom.BuildStatus{Created: time.Unix(0, 0).UTC(), BuildVersion: "v1.2.3"}, "")
	if err != nil {
		t.Fatalf("GenerateDocument() error = %v", err)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("len(Packages) = %d, want 1", len(doc.Packages))
	}
	if doc.Packages[0].PackageVersion != "v1.2.3" {
		t.Errorf("PackageVersion = %q, want stamped build version", doc.Packages[0].PackageVersion)
	}
}

func TestGenerateDocument_NoRootFallsBackToFirstPackage(t *testing.T) {
	dir := t.TempDir()
	depMeta := writePackageMetadata(t, dir, "dep.json", "//lib:dep", "pkg:golang/github.com/example/dep@v1.2.3")

	graph := sbom.GraphConfig{
		Nodes: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
	}
	classifications := sbom.Classifications{
		Dependencies: sbom.DependencyNodes{
			Direct: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
		},
	}

	doc, err := GenerateDocument(graph, classifications, sbom.BuildStatus{Created: time.Unix(0, 0).UTC()}, "")
	if err != nil {
		t.Fatalf("GenerateDocument() error = %v", err)
	}
	if doc.DocumentName != "dep" {
		t.Errorf("DocumentName = %q, want %q", doc.DocumentName, "dep")
	}
}

func TestGenerateDocument_UsesPURLDownloadQualifier(t *testing.T) {
	dir := t.TempDir()
	depMeta := writePackageMetadata(t, dir, "dep.json", "//lib:dep", "pkg:golang/github.com/example/dep@v1.2.3?download_url=https://example.com/dep.tar.gz")

	graph := sbom.GraphConfig{
		Nodes: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
	}
	classifications := sbom.Classifications{
		Dependencies: sbom.DependencyNodes{
			Direct: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
		},
	}

	doc, err := GenerateDocument(graph, classifications, sbom.BuildStatus{Created: time.Unix(0, 0).UTC()}, "")
	if err != nil {
		t.Fatalf("GenerateDocument() error = %v", err)
	}
	if got, want := doc.Packages[0].PackageDownloadLocation, "https://example.com/dep.tar.gz"; got != want {
		t.Errorf("PackageDownloadLocation = %q, want %q", got, want)
	}
}

func TestGenerateDocument_UsesPURLURLDownloadQualifier(t *testing.T) {
	dir := t.TempDir()
	depMeta := writePackageMetadata(t, dir, "dep.json", "//lib:dep", "pkg:golang/github.com/example/dep@v1.2.3?url_download=https://example.com/dep.tar.gz")

	graph := sbom.GraphConfig{
		Nodes: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
	}
	classifications := sbom.Classifications{
		Dependencies: sbom.DependencyNodes{
			Direct: []sbom.NodeConfig{{Label: "//lib:dep", MetadataFile: depMeta}},
		},
	}

	doc, err := GenerateDocument(graph, classifications, sbom.BuildStatus{Created: time.Unix(0, 0).UTC()}, "")
	if err != nil {
		t.Fatalf("GenerateDocument() error = %v", err)
	}
	if got, want := doc.Packages[0].PackageDownloadLocation, "https://example.com/dep.tar.gz"; got != want {
		t.Errorf("PackageDownloadLocation = %q, want %q", got, want)
	}
}

func TestGenerateDocument_EmptyGraphUsesFallbackSubject(t *testing.T) {
	doc, err := GenerateDocument(sbom.GraphConfig{}, sbom.Classifications{}, sbom.BuildStatus{Created: time.Unix(0, 0).UTC()}, "")
	if err != nil {
		t.Fatalf("GenerateDocument() error = %v", err)
	}
	if doc.DocumentName == "" {
		t.Error("DocumentName is empty even with no packages at all")
	}
	if doc.DocumentNamespace == "" {
		t.Error("DocumentNamespace is empty even with no packages at all")
	}
}

func TestGenerateDocument_UsesConfiguredDocumentNamespace(t *testing.T) {
	const namespace = "https://example.com/spdx/0f068793-f9b8-5cdd-9669-3ad9253ad3b7"

	doc, err := GenerateDocument(sbom.GraphConfig{}, sbom.Classifications{}, sbom.BuildStatus{Created: time.Unix(0, 0).UTC()}, namespace)
	if err != nil {
		t.Fatalf("GenerateDocument() error = %v", err)
	}
	if doc.DocumentNamespace != namespace {
		t.Errorf("DocumentNamespace = %q, want %q", doc.DocumentNamespace, namespace)
	}
}

func TestGenerateDocument_RejectsInvalidConfiguredDocumentNamespace(t *testing.T) {
	const namespace = "https://example.com/spdx/name#fragment"

	if _, err := GenerateDocument(sbom.GraphConfig{}, sbom.Classifications{}, sbom.BuildStatus{Created: time.Unix(0, 0).UTC()}, namespace); err == nil {
		t.Fatal("GenerateDocument() error = nil, want invalid namespace error")
	}
}

func TestGenerateDocument_PackageVersionsAndPURLs(t *testing.T) {
	cases := []struct {
		name    string
		purl    string
		want    string
		version string
	}{
		{"debian", "pkg:deb/debian/busybox-static@1%3A1.37.0-6%2Bb8?arch=amd64", "pkg:deb/debian/busybox-static@1:1.37.0-6%2Bb8?arch=amd64", "1:1.37.0-6+b8"},
		{"docker", "pkg:docker/distroless/cc-debian13@sha256%3Aabcdef?repository_url=gcr.io", "pkg:docker/distroless/cc-debian13@sha256:abcdef?repository_url=gcr.io", "sha256:abcdef"},
		{"no version", "pkg:generic/example", "pkg:generic/example", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			root := sbom.NodeConfig{Label: "//app:root", MetadataFile: writePackageMetadata(t, dir, "root.json", "//app:root", "pkg:bazel/app@1.0.0")}
			dep := sbom.NodeConfig{Label: "//lib:dep", MetadataFile: writePackageMetadata(t, dir, "dep.json", "//lib:dep", c.purl)}
			classifications := sbom.Classifications{
				RootComponent: &root,
				Dependencies: sbom.DependencyNodes{
					Direct:     []sbom.NodeConfig{dep},
					Transitive: []sbom.NodeConfig{{Label: "//lib:transitive", MetadataFile: dep.MetadataFile}},
				},
			}
			doc, err := GenerateDocument(sbom.GraphConfig{}, classifications, sbom.BuildStatus{Created: time.Unix(0, 0).UTC(), BuildVersion: "dev"}, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Packages) != 3 {
				t.Fatalf("len(Packages) = %d, want 3", len(doc.Packages))
			}
			if doc.Packages[0].PackageVersion != "dev" {
				t.Errorf("subject version = %q, want dev", doc.Packages[0].PackageVersion)
			}
			for _, pkg := range doc.Packages[1:] {
				if pkg.PackageVersion != c.version {
					t.Errorf("PackageVersion = %q, want %q", pkg.PackageVersion, c.version)
				}
				if got := pkg.PackageExternalReferences[0].Locator; got != c.want {
					t.Errorf("PURL = %q, want %q", got, c.want)
				}
			}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			var serialized struct {
				Packages []map[string]json.RawMessage `json:"packages"`
			}
			if err := json.Unmarshal(data, &serialized); err != nil {
				t.Fatal(err)
			}
			for _, pkg := range serialized.Packages[1:] {
				raw, present := pkg["versionInfo"]
				if c.version == "" {
					if present {
						t.Error("versionInfo must be omitted for an unknown version")
					}
				} else {
					var version string
					if err := json.Unmarshal(raw, &version); err != nil {
						t.Fatal(err)
					}
					if version != c.version {
						t.Errorf("versionInfo = %q, want %q", version, c.version)
					}
				}
			}
		})
	}
}
