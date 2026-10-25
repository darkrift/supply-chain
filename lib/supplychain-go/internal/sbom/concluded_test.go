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
		"pkg:generic/lib@1#sub": "must not have a subpath",
		"not-a-purl":            "invalid PURL",
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

func TestApplyVersionlessKeyMatchesAnyVersion(t *testing.T) {
	dir := t.TempDir()
	v1 := pkg(t, dir, "lib", "1.0", mitLicense)
	v2 := pkg(t, dir, "lib", "2.0", mitLicense)

	c := load(t, map[string]string{"pkg:generic/lib": mitLicense, "pkg:generic/lib@2.0": dualLicense}, false)
	classifications := sbom.Classifications{Dependencies: sbom.DependencyNodes{Direct: []sbom.NodeConfig{v1, v2}}}
	require.NoError(t, c.Apply(&classifications))

	assert.NotEmpty(t, classifications.Dependencies.Direct[0].ConcludedLicenseFile)
	attribute, err := sbom.ReadLicenseAttribute(classifications.Dependencies.Direct[1].ConcludedLicenseFile)
	require.NoError(t, err)
	assert.Equal(t, "MIT OR Apache-2.0", attribute.Root().String(), "the exact version wins")
}

// Every PURL component, specified or not, on the key and on the package.
func TestApplyMatchingPURLComponents(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		pkgPURL string
		match   bool
	}{
		{"all required only", "pkg:npm/lib", "pkg:npm/lib", true},
		{"type differs", "pkg:npm/lib", "pkg:gem/lib", false},
		{"name differs", "pkg:npm/lib", "pkg:npm/other", false},

		{"namespace on both", "pkg:maven/org.acme/lib@1", "pkg:maven/org.acme/lib@1", true},
		{"namespace differs", "pkg:maven/org.acme/lib@1", "pkg:maven/org.other/lib@1", false},
		{"namespace only on key", "pkg:maven/org.acme/lib@1", "pkg:maven/lib@1", false},
		{"namespace only on package", "pkg:maven/lib@1", "pkg:maven/org.acme/lib@1", false},
		{"no namespace on both", "pkg:maven/lib@1", "pkg:maven/lib@1", true},

		{"version on both", "pkg:npm/lib@1.0", "pkg:npm/lib@1.0", true},
		{"version differs", "pkg:npm/lib@1.0", "pkg:npm/lib@2.0", false},
		{"version only on key", "pkg:npm/lib@1.0", "pkg:npm/lib", false},
		{"version only on package", "pkg:npm/lib", "pkg:npm/lib@1.0", true},
		{"version on both unset", "pkg:npm/lib", "pkg:npm/lib", true},
		{"versionless key with namespace", "pkg:maven/org.acme/lib", "pkg:maven/org.acme/lib@3", true},
		{"versionless key other namespace", "pkg:maven/org.acme/lib", "pkg:maven/org.other/lib@3", false},

		{"qualifier on key and package", "pkg:deb/debian/lib@1?arch=amd64", "pkg:deb/debian/lib@1?arch=amd64", true},
		{"qualifier value differs", "pkg:deb/debian/lib@1?arch=amd64", "pkg:deb/debian/lib@1?arch=arm64", false},
		{"qualifier only on key", "pkg:deb/debian/lib@1?arch=amd64", "pkg:deb/debian/lib@1", false},
		{"key qualifiers are a subset", "pkg:deb/debian/lib@1?arch=amd64", "pkg:deb/debian/lib@1?arch=amd64&distro=bookworm", true},
		{"missing second key qualifier", "pkg:deb/debian/lib@1?arch=amd64&distro=bookworm", "pkg:deb/debian/lib@1?arch=amd64", false},
		{"qualifier on versionless key", "pkg:deb/debian/lib?arch=amd64", "pkg:deb/debian/lib@9?arch=amd64", true},
		{"qualifier on versionless key differs", "pkg:deb/debian/lib?arch=amd64", "pkg:deb/debian/lib@9?arch=arm64", false},
		{"qualifiers on package", "pkg:deb/debian/lib@1", "pkg:deb/debian/lib@1?arch=amd64", true},
		{"qualifiers on package, versionless key", "pkg:deb/debian/lib", "pkg:deb/debian/lib@1?arch=amd64", true},
		{"subpath on package", "pkg:github/org/lib@1", "pkg:github/org/lib@1#src/main", true},
		{"qualifiers and subpath on package", "pkg:npm/lib@1", "pkg:npm/lib@1?a=b#c", true},
		{"qualifiers, other version", "pkg:npm/lib@1", "pkg:npm/lib@2?a=b#c", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			metadata := write(t, dir, "metadata.json",
				`{"label":"@@//lib:package_metadata","purl":"`+tc.pkgPURL+`","attributes":{}}`)
			node := sbom.NodeConfig{Label: "//lib", MetadataFile: metadata}

			c := load(t, map[string]string{tc.key: mitLicense}, false)
			classifications := sbom.Classifications{Dependencies: sbom.DependencyNodes{Direct: []sbom.NodeConfig{node}}}
			require.NoError(t, c.Apply(&classifications))
			if tc.match {
				assert.NotEmpty(t, classifications.Dependencies.Direct[0].ConcludedLicenseFile)
			} else {
				assert.Empty(t, classifications.Dependencies.Direct[0].ConcludedLicenseFile)
			}
		})
	}
}

// The key may leave the version and qualifiers out, but never carries a subpath.
func TestConcludedKeyComponents(t *testing.T) {
	valid := []string{"pkg:npm/lib", "pkg:npm/lib@1", "pkg:maven/org.acme/lib", "pkg:maven/org.acme/lib@1",
		"pkg:npm/lib?a=b", "pkg:npm/lib@1?a=b&c=d"}
	for _, key := range valid {
		_, err := sbom.ParseConcludedKey(key)
		assert.NoError(t, err, key)
	}
	invalid := []string{
		"pkg:npm/lib#sub", "pkg:npm/lib@1?a=b#sub", // subpath
		"npm/lib",  // scheme missing
		"pkg:lib",  // type missing
		"pkg:npm/", // name missing
	}
	for _, key := range invalid {
		_, err := sbom.ParseConcludedKey(key)
		assert.Error(t, err, key)
	}
}

func TestApplyMostSpecificKeyWins(t *testing.T) {
	dir := t.TempDir()
	node := func(purl string) sbom.NodeConfig {
		metadata := write(t, dir, "m.json", `{"label":"@@//lib:package_metadata","purl":"`+purl+`","attributes":{}}`)
		return sbom.NodeConfig{Label: "//lib", MetadataFile: metadata}
	}
	concluded := func(keys map[string]string, purl string) (string, error) {
		c := load(t, keys, false)
		classifications := sbom.Classifications{Dependencies: sbom.DependencyNodes{Direct: []sbom.NodeConfig{node(purl)}}}
		err := c.Apply(&classifications)
		if err != nil {
			return "", err
		}
		file := classifications.Dependencies.Direct[0].ConcludedLicenseFile
		if file == "" {
			return "", nil
		}
		attribute, err := sbom.ReadLicenseAttribute(file)
		require.NoError(t, err)
		return attribute.Root().String(), nil
	}
	const mit, dual = "MIT", "MIT OR Apache-2.0"
	pkg := "pkg:deb/debian/lib@1?arch=amd64&distro=bookworm"

	got, err := concluded(map[string]string{
		"pkg:deb/debian/lib": mitLicense, "pkg:deb/debian/lib?arch=amd64": dualLicense}, pkg)
	require.NoError(t, err)
	assert.Equal(t, dual, got, "qualifiers are more specific than none")

	got, err = concluded(map[string]string{
		"pkg:deb/debian/lib@1": mitLicense, "pkg:deb/debian/lib?arch=amd64&distro=bookworm": dualLicense}, pkg)
	require.NoError(t, err)
	assert.Equal(t, mit, got, "a version outweighs qualifiers")

	got, err = concluded(map[string]string{
		"pkg:deb/debian/lib@1": mitLicense, "pkg:deb/debian/lib@1?arch=amd64": dualLicense}, pkg)
	require.NoError(t, err)
	assert.Equal(t, dual, got, "same version, more qualifiers")

	_, err = concluded(map[string]string{
		"pkg:deb/debian/lib?arch=amd64": mitLicense, "pkg:deb/debian/lib?distro=bookworm": dualLicense}, pkg)
	require.Error(t, err, "equally specific keys are ambiguous")
	assert.Contains(t, err.Error(), "equally specific")
}

func TestConcludedLicensesDuplicateKeysWithQualifiers(t *testing.T) {
	_, err := sbom.LoadConcludedLicenses(manifest(t, map[string]string{
		"pkg:generic/lib@1?a=b&c=d": mitLicense, "pkg:generic/lib@1?c=d&a=b": mitLicense}, false))
	require.Error(t, err, "qualifier order does not make keys distinct")
	assert.Contains(t, err.Error(), "more than once")
}
