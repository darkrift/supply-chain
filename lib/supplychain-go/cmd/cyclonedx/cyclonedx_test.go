package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

func TestGenerateBOMHashesBOMRefsFromComponentFields(t *testing.T) {
	tmp := t.TempDir()

	root := nodeWithMetadata(t, tmp, "//:root", "pkg:generic/root@1.0.0")
	direct := nodeWithMetadata(t, tmp, "//:direct", "pkg:generic/lib@1.0.0")
	transitive := nodeWithMetadata(t, tmp, "//:transitive", "pkg:generic/lib@1.0.0")

	bom, err := GenerateBOM(
		sbom.GraphConfig{
			RootTarget: root.Label,
			Nodes:      []sbom.NodeConfig{root, direct, transitive},
			Edges: []sbom.EdgeConfig{
				{From: root.Label, To: direct.Label, Type: "depends_on"},
				{From: root.Label, To: transitive.Label, Type: "depends_on"},
			},
		},
		sbom.Classifications{
			RootComponent: &root,
			Dependencies: sbom.DependencyNodes{
				Direct:     []sbom.NodeConfig{direct},
				Transitive: []sbom.NodeConfig{transitive},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	components := componentsWithPURL(t, bom, "pkg:generic/lib@1.0.0")
	if got, want := len(components), 2; got != want {
		t.Fatalf("expected %d lib components, got %d: %#v", want, got, components)
	}

	directRef := componentRefWithScope(t, components, "direct")
	transitiveRef := componentRefWithScope(t, components, "transitive")
	if directRef == transitiveRef {
		t.Fatalf("expected direct and transitive components to have different bom-refs, got %q", directRef)
	}
	for _, ref := range []string{directRef, transitiveRef} {
		if !strings.HasPrefix(ref, "pkg:generic/lib@1.0.0#sha256:") {
			t.Fatalf("expected hashed bom-ref for lib component, got %q", ref)
		}
	}
}

func TestGenerateBOMDeduplicatesIdenticalComponentsAndDependencyRefs(t *testing.T) {
	tmp := t.TempDir()

	root := nodeWithMetadata(t, tmp, "//:root", "pkg:generic/root@1.0.0")
	parent := nodeWithMetadata(t, tmp, "//:parent", "pkg:generic/parent@1.0.0")
	duplicateA := nodeWithMetadata(t, tmp, "//:duplicate_a", "pkg:generic/lib@1.0.0")
	duplicateB := nodeWithMetadata(t, tmp, "//:duplicate_b", "pkg:generic/lib@1.0.0")

	bom, err := GenerateBOM(
		sbom.GraphConfig{
			RootTarget: root.Label,
			Nodes:      []sbom.NodeConfig{root, parent, duplicateA, duplicateB},
			Edges: []sbom.EdgeConfig{
				{From: root.Label, To: parent.Label, Type: "depends_on"},
				{From: parent.Label, To: duplicateA.Label, Type: "depends_on"},
				{From: parent.Label, To: duplicateB.Label, Type: "depends_on"},
			},
		},
		sbom.Classifications{
			RootComponent: &root,
			Dependencies: sbom.DependencyNodes{
				Direct:     []sbom.NodeConfig{parent},
				Transitive: []sbom.NodeConfig{duplicateA, duplicateB},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	libComponents := componentsWithPURL(t, bom, "pkg:generic/lib@1.0.0")
	if got, want := len(libComponents), 1; got != want {
		t.Fatalf("expected %d deduplicated lib component, got %d: %#v", want, got, libComponents)
	}

	parentComponents := componentsWithPURL(t, bom, "pkg:generic/parent@1.0.0")
	parentRef := componentRefWithScope(t, parentComponents, "direct")
	libRef := componentRefWithScope(t, libComponents, "transitive")

	dependencyRefs := dependencyRefsFor(t, bom, parentRef)
	if got, want := len(dependencyRefs), 1; got != want {
		t.Fatalf("expected %d dependency ref for deduplicated lib component, got %d: %#v", want, got, dependencyRefs)
	}
	if dependencyRefs[0] != libRef {
		t.Fatalf("expected dependency ref %q, got %q", libRef, dependencyRefs[0])
	}
}

func nodeWithMetadata(t *testing.T, dir, label, purl string) sbom.NodeConfig {
	t.Helper()

	path := filepath.Join(dir, strings.NewReplacer("/", "_", ":", "_").Replace(label)+".json")
	content := `{
  "label": "` + label + `",
  "purl": "` + purl + `",
  "attributes": {}
}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	return sbom.NodeConfig{
		Label:        label,
		MetadataFile: path,
	}
}

func componentsWithPURL(t *testing.T, bom *cdx.BOM, purl string) []cdx.Component {
	t.Helper()

	components := make([]cdx.Component, 0)
	if bom.Components == nil {
		return components
	}

	for _, component := range *bom.Components {
		if component.PackageURL != purl {
			continue
		}
		components = append(components, component)
	}
	return components
}

func componentRefWithScope(t *testing.T, components []cdx.Component, scope string) string {
	t.Helper()

	for _, component := range components {
		if string(component.Scope) == scope {
			return component.BOMRef
		}
	}

	t.Fatalf("expected component with scope %q in %#v", scope, components)
	return ""
}

func dependencyRefsFor(t *testing.T, bom *cdx.BOM, parentRef string) []string {
	t.Helper()

	if bom.Dependencies == nil {
		t.Fatalf("expected BOM dependencies for %q", parentRef)
	}

	for _, dependency := range *bom.Dependencies {
		if dependency.Ref != parentRef {
			continue
		}
		if dependency.Dependencies == nil {
			return nil
		}
		return *dependency.Dependencies
	}

	t.Fatalf("expected dependency entry for %q", parentRef)
	return nil
}
