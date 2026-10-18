package sbom_test

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

const (
	mitLicense  = `{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//:mit"}`
	dualLicense = `{"expression":{"operator":"OR","operands":[
		{"kind":{"identifier":"MIT","name":"MIT License"}},
		{"kind":{"identifier":"Apache-2.0","name":"Apache"}}]},"label":"//:dual"}`
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func manifest(t *testing.T, licenses map[string]string, requireResolved bool, requireMatched ...bool) string {
	t.Helper()
	dir := t.TempDir()
	entries := ""
	n := 0
	for purl, attribute := range licenses {
		n++
		if entries != "" {
			entries += ","
		}
		entries += `"` + purl + `":"` + write(t, dir, fmt.Sprintf("attribute-%d.json", n), attribute) + `"`
	}
	flag := "false"
	if requireResolved {
		flag = "true"
	}
	matched := "false"
	if len(requireMatched) > 0 && requireMatched[0] {
		matched = "true"
	}
	return write(t, dir, "manifest.json", `{"licenses":{`+entries+`},"require_resolved_choices":`+flag+`,"require_matched_concluded_licenses":`+matched+`}`)
}

// pkg writes a package_metadata file for pkg:generic/<name>@<version>, with
// the license attribute when licenseJSON is not empty.
func pkg(t *testing.T, dir, name, version, licenseJSON string) sbom.NodeConfig {
	t.Helper()
	attributes := "{}"
	if licenseJSON != "" {
		attributes = `{"build.bazel.attribute.license": "` + write(t, dir, name+".license.json", licenseJSON) + `"}`
	}
	metadata := write(t, dir, name+".metadata.json",
		`{"label":"@@//`+name+`:package_metadata","purl":"pkg:generic/`+name+`@`+version+`?arch=x86#sub","attributes":`+attributes+`}`)
	return sbom.NodeConfig{Label: "//" + name, MetadataFile: metadata}
}

func load(t *testing.T, licenses map[string]string, requireResolved bool) *sbom.ConcludedLicenses {
	t.Helper()
	c, err := sbom.LoadConcludedLicenses(manifest(t, licenses, requireResolved))
	require.NoError(t, err)
	return c
}

func TestApplyMatchesOnTypeNamespaceNameAndVersion(t *testing.T) {
	dir := t.TempDir()
	match := pkg(t, dir, "lib", "1.0", mitLicense)
	otherVersion := pkg(t, dir, "other", "2.0", mitLicense)
	root := pkg(t, dir, "root", "1.0", "")
	noMetadata := sbom.NodeConfig{Label: "//none"}

	c := load(t, map[string]string{"pkg:generic/lib@1.0": dualLicense, "pkg:generic/root@1.0": mitLicense}, false)
	classifications := sbom.Classifications{
		RootComponent: &root,
		Dependencies: sbom.DependencyNodes{
			Direct:     []sbom.NodeConfig{match, noMetadata},
			Transitive: []sbom.NodeConfig{otherVersion},
		},
	}
	require.NoError(t, c.Apply(&classifications))

	// Qualifiers and subpaths of the package do not take part in the match.
	assert.NotEmpty(t, classifications.Dependencies.Direct[0].ConcludedLicenseFile)
	assert.Empty(t, classifications.Dependencies.Direct[1].ConcludedLicenseFile)
	assert.Empty(t, classifications.Dependencies.Transitive[0].ConcludedLicenseFile)
	assert.NotEmpty(t, classifications.RootComponent.ConcludedLicenseFile)
	assert.Empty(t, root.ConcludedLicenseFile, "the input root is not modified")

	attribute, err := sbom.ReadLicenseAttribute(classifications.Dependencies.Direct[0].ConcludedLicenseFile)
	require.NoError(t, err)
	assert.Equal(t, "MIT OR Apache-2.0", attribute.Root().String())
}

func TestApplyNoOverrides(t *testing.T) {
	dir := t.TempDir()
	node := pkg(t, dir, "lib", "1.0", mitLicense)

	var nilLicenses *sbom.ConcludedLicenses
	for _, c := range []*sbom.ConcludedLicenses{nilLicenses, load(t, nil, false)} {
		classifications := sbom.Classifications{Dependencies: sbom.DependencyNodes{Direct: []sbom.NodeConfig{node}}}
		require.NoError(t, c.Apply(&classifications))
		assert.Empty(t, classifications.Dependencies.Direct[0].ConcludedLicenseFile)
	}

	empty, err := sbom.LoadConcludedLicenses("")
	require.NoError(t, err)
	assert.NoError(t, empty.Apply(&sbom.Classifications{}))
}

func TestApplyUnmatched(t *testing.T) {
	dir := t.TempDir()
	used := pkg(t, dir, "used", "1", mitLicense)
	classifications := func() *sbom.Classifications {
		return &sbom.Classifications{Dependencies: sbom.DependencyNodes{Direct: []sbom.NodeConfig{used}}}
	}
	licenses := map[string]string{"pkg:generic/used@1": mitLicense, "pkg:generic/stale@1": mitLicense}

	// By default, a list shared by many SBOMs may have entries for packages
	// that are not in this one.
	shared := classifications()
	require.NoError(t, load(t, licenses, false).Apply(shared))
	assert.NotEmpty(t, shared.Dependencies.Direct[0].ConcludedLicenseFile)

	c, err := sbom.LoadConcludedLicenses(manifest(t, licenses, false, true))
	require.NoError(t, err)
	err = c.Apply(classifications())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pkg:generic/stale@1")
	assert.NotContains(t, err.Error(), "pkg:generic/used@1")
}

func TestApplyRequireResolvedChoices(t *testing.T) {
	dir := t.TempDir()
	dual := pkg(t, dir, "dual", "1", dualLicense)
	none := pkg(t, dir, "none", "1", "")
	apply := func(c *sbom.ConcludedLicenses, nodes ...sbom.NodeConfig) error {
		return c.Apply(&sbom.Classifications{Dependencies: sbom.DependencyNodes{Direct: nodes}})
	}

	assert.NoError(t, apply(load(t, nil, false), dual), "not required")
	assert.NoError(t, apply(load(t, nil, true), none), "no license")

	err := apply(load(t, nil, true), dual)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MIT OR Apache-2.0")
	assert.Contains(t, err.Error(), "//dual")

	assert.NoError(t, apply(load(t, map[string]string{"pkg:generic/dual@1": mitLicense}, true), dual), "resolved by the conclusion")

	err = apply(load(t, map[string]string{"pkg:generic/dual@1": dualLicense}, true), dual)
	require.Error(t, err, "a conclusion that still offers a choice")
}

func TestConcludedLicensesInvalidKeys(t *testing.T) {
	cases := map[string]string{
		"pkg:generic/lib":            "must have a version",
		"pkg:generic/lib@1?arch=x86": "only have a type, namespace, name and version",
		"pkg:generic/lib@1#sub":      "only have a type, namespace, name and version",
		"not-a-purl":                 "invalid PURL",
	}
	for key, message := range cases {
		_, err := sbom.LoadConcludedLicenses(manifest(t, map[string]string{key: mitLicense}, false))
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), message, key)
	}
}

func TestConcludedLicensesDuplicateKeys(t *testing.T) {
	// Both spellings canonicalize to the same package.
	_, err := sbom.LoadConcludedLicenses(manifest(t, map[string]string{
		"pkg:generic/lib@1": mitLicense,
		"PKG:GENERIC/lib@1": mitLicense,
	}, false))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than once")
}

// The concluded licenses end up in the classifications computed from a graph,
// and in their JSON, which is what the SBOM generators read.
func TestApplyToComputedClassificationsJSON(t *testing.T) {
	dir := t.TempDir()
	root := pkg(t, dir, "root", "1", mitLicense)
	direct := pkg(t, dir, "direct", "1", dualLicense)
	transitive := pkg(t, dir, "transitive", "1", dualLicense)
	untouched := pkg(t, dir, "untouched", "1", mitLicense)
	root.Label, direct.Label, transitive.Label, untouched.Label = "//root", "//direct", "//transitive", "//untouched"

	graph := sbom.GraphConfig{
		RootTarget: "//root",
		Nodes:      []sbom.NodeConfig{root, direct, transitive, untouched},
		Edges: []sbom.EdgeConfig{
			{From: "//root", To: "//direct", Type: "depends_on"},
			{From: "//root", To: "//untouched", Type: "depends_on"},
			{From: "//direct", To: "//transitive", Type: "depends_on"},
		},
	}
	classifications, err := sbom.ComputeClassifications(graph, false)
	require.NoError(t, err)

	c := load(t, map[string]string{
		"pkg:generic/root@1":       mitLicense,
		"pkg:generic/direct@1":     mitLicense,
		"pkg:generic/transitive@1": mitLicense,
	}, false)
	require.NoError(t, c.Apply(&classifications))

	encoded, err := json.Marshal(classifications)
	require.NoError(t, err)
	var decoded sbom.Classifications
	require.NoError(t, json.Unmarshal(encoded, &decoded))

	concluded := map[string]string{}
	for _, node := range append(append([]sbom.NodeConfig{*decoded.RootComponent}, decoded.Dependencies.Direct...), decoded.Dependencies.Transitive...) {
		concluded[node.Label] = node.ConcludedLicenseFile
	}
	assert.NotEmpty(t, concluded["//root"])
	assert.NotEmpty(t, concluded["//direct"])
	assert.NotEmpty(t, concluded["//transitive"])
	assert.Empty(t, concluded["//untouched"])

	// Nodes without a conclusion do not carry the field at all.
	assert.Contains(t, string(encoded), `"concluded_license_file"`)
	var raw struct {
		Dependencies struct {
			Direct []map[string]any `json:"direct"`
		} `json:"dependencies"`
	}
	require.NoError(t, json.Unmarshal(encoded, &raw))
	for _, node := range raw.Dependencies.Direct {
		if node["label"] == "//untouched" {
			assert.NotContains(t, node, "concluded_license_file")
		}
	}
}

// Packages that only differ by their qualifiers (e.g. the arch of a deb
// package) share the concluded license of their type, namespace, name and version.
func TestApplyToPackagesDifferingByQualifiers(t *testing.T) {
	dir := t.TempDir()
	node := func(name, purl string) sbom.NodeConfig {
		license := write(t, dir, name+".license.json", dualLicense)
		metadata := write(t, dir, name+".metadata.json",
			`{"label":"@@//`+name+`:package_metadata","purl":"`+purl+`","attributes":{"build.bazel.attribute.license":"`+license+`"}}`)
		return sbom.NodeConfig{Label: "//" + name, MetadataFile: metadata}
	}
	amd64 := node("libfoo_amd64", "pkg:deb/debian/libfoo@1.0?arch=amd64")
	arm64 := node("libfoo_arm64", "pkg:deb/debian/libfoo@1.0?arch=arm64")
	otherVersion := node("libfoo_other", "pkg:deb/debian/libfoo@2.0?arch=amd64")

	c := load(t, map[string]string{"pkg:deb/debian/libfoo@1.0": mitLicense}, true)
	classifications := sbom.Classifications{Dependencies: sbom.DependencyNodes{
		Direct: []sbom.NodeConfig{amd64, arm64},
	}}
	require.NoError(t, c.Apply(&classifications))
	for _, n := range classifications.Dependencies.Direct {
		assert.NotEmpty(t, n.ConcludedLicenseFile, n.Label)
	}

	// Another version is not concluded, and its choice is unresolved.
	err := load(t, map[string]string{"pkg:deb/debian/libfoo@1.0": mitLicense}, true).Apply(
		&sbom.Classifications{Dependencies: sbom.DependencyNodes{Direct: []sbom.NodeConfig{amd64, otherVersion}}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "//libfoo_other")
}
