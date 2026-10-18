package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	supplychain "github.com/bazel-contrib/supply-chain/lib/supplychain-go"
	"github.com/package-url/packageurl-go"
)

// ConcludedLicenses holds the concluded licenses that override the declared
// license of packages, keyed by PURL (type, namespace, name and version only).
//
// A nil *ConcludedLicenses is valid and overrides nothing.
type ConcludedLicenses struct {
	licenses               map[string]concludedLicense
	used                   map[string]bool
	requireResolvedChoices bool
	requireMatched         bool
}

type concludedLicense struct {
	path      string
	attribute *supplychain.LicenseAttribute
}

// concludedLicensesFile is written by the `sbom` rule. Licenses maps a PURL to
// the path of a license attribute file.
type concludedLicensesFile struct {
	Licenses               map[string]string `json:"licenses"`
	RequireResolvedChoices bool              `json:"require_resolved_choices"`
	RequireMatched         bool              `json:"require_matched_concluded_licenses"`
}

// LoadConcludedLicenses reads the concluded licenses manifest at path. An
// empty path yields no overrides.
func LoadConcludedLicenses(path string) (*ConcludedLicenses, error) {
	c := &ConcludedLicenses{
		licenses: map[string]concludedLicense{},
		used:     map[string]bool{},
	}
	if path == "" {
		return c, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading concluded licenses: %w", err)
	}
	var file concludedLicensesFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing concluded licenses: %w", err)
	}
	c.requireResolvedChoices = file.RequireResolvedChoices
	c.requireMatched = file.RequireMatched

	for rawPURL, attributePath := range file.Licenses {
		key, err := ParseConcludedKey(rawPURL)
		if err != nil {
			return nil, err
		}
		if _, ok := c.licenses[key]; ok {
			return nil, fmt.Errorf("concluded license for '%s' is declared more than once", key)
		}
		attribute, err := ReadLicenseAttribute(attributePath)
		if err != nil {
			return nil, fmt.Errorf("reading concluded license of '%s': %w", rawPURL, err)
		}
		c.licenses[key] = concludedLicense{path: attributePath, attribute: attribute}
	}
	return c, nil
}

// ReadLicenseAttribute reads a license attribute file.
func ReadLicenseAttribute(path string) (*supplychain.LicenseAttribute, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return supplychain.LicenseAttributeDescriptor.Parser(f)
}

// ParseConcludedKey validates a PURL used to key a concluded license and
// returns its canonical form. Only the type, namespace, name and version
// identify a package, so qualifiers and subpaths are rejected.
func ParseConcludedKey(raw string) (string, error) {
	purl, err := packageurl.FromString(raw)
	if err != nil {
		return "", fmt.Errorf("invalid PURL '%s' for a concluded license: %w", raw, err)
	}
	if purl.Version == "" {
		return "", fmt.Errorf("PURL '%s' for a concluded license must have a version", raw)
	}
	if len(purl.Qualifiers) > 0 || purl.Subpath != "" {
		return "", fmt.Errorf("PURL '%s' for a concluded license must only have a type, namespace, name and version", raw)
	}
	return PurlKey(purl), nil
}

// PurlKey is the canonical form of the PURL properties that identify a package.
func PurlKey(purl packageurl.PackageURL) string {
	return packageurl.NewPackageURL(purl.Type, purl.Namespace, purl.Name, purl.Version, nil, "").ToString()
}

// Apply sets `ConcludedLicenseFile` on the nodes of the classifications whose
// PURL has a concluded license, so that SBOM generators only have to prefer it
// over the declared license. It fails on overrides that match no node, and on
// choices left unresolved when the manifest requires them to be resolved.
func (c *ConcludedLicenses) Apply(classifications *Classifications) error {
	if c == nil {
		return nil
	}
	if classifications.RootComponent != nil {
		root := *classifications.RootComponent
		if err := c.apply(&root); err != nil {
			return err
		}
		classifications.RootComponent = &root
	}
	for _, nodes := range [][]NodeConfig{classifications.Dependencies.Direct, classifications.Dependencies.Transitive} {
		for i := range nodes {
			if err := c.apply(&nodes[i]); err != nil {
				return err
			}
		}
	}
	return c.unused()
}

func (c *ConcludedLicenses) apply(node *NodeConfig) error {
	if node.MetadataFile == "" {
		return nil
	}
	metadata, err := supplychain.ReadPackageMetadataFromFile(node.MetadataFile)
	if err != nil {
		return err
	}
	effective, err := supplychain.GetLicenseAttribute(metadata)
	if err != nil {
		return fmt.Errorf("reading license of %s: %w", node.Label, err)
	}

	key := PurlKey(metadata.GetPURL())
	if override, ok := c.licenses[key]; ok {
		c.used[key] = true
		node.ConcludedLicenseFile = override.path
		effective = override.attribute
	}
	return c.checkResolved(node.Label, effective)
}

// unused fails if the manifest requires every concluded license to match a
// package of the SBOM and some did not, which typically means a stale or
// mistyped PURL. Otherwise they are ignored, so that one list of concluded
// licenses can be shared by many SBOMs.
func (c *ConcludedLicenses) unused() error {
	if !c.requireMatched {
		return nil
	}
	var unused []string
	for key := range c.licenses {
		if !c.used[key] {
			unused = append(unused, key)
		}
	}
	if len(unused) == 0 {
		return nil
	}
	sort.Strings(unused)
	return fmt.Errorf("concluded licenses do not match any package of the SBOM: %v", unused)
}

// checkResolved fails if the concluded license of a package still offers a
// choice (`OR`) while the SBOM requires every choice to be resolved.
func (c *ConcludedLicenses) checkResolved(label string, concluded *supplychain.LicenseAttribute) error {
	if !c.requireResolvedChoices || concluded == nil {
		return nil
	}
	if root := concluded.Root(); root.HasChoice() {
		return fmt.Errorf("%s is licensed under '%s', which offers a choice; conclude a single license for it with `concluded_licenses`", label, root.String())
	}
	return nil
}
