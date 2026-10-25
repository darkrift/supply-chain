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
// license of packages, keyed by PURL (type, namespace, name and optional version only). A key
// without version applies to every version without a more specific key.
//
// A nil *ConcludedLicenses is valid and overrides nothing.
type ConcludedLicenses struct {
	licenses               map[string]*concludedLicense
	used                   map[string]bool
	requireResolvedChoices bool
	requireMatched         bool
}

type concludedLicense struct {
	key       string
	purl      packageurl.PackageURL
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
		licenses: map[string]*concludedLicense{},
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
		purl, err := parseConcludedPURL(rawPURL)
		if err != nil {
			return nil, err
		}
		key := purl.ToString()
		if _, ok := c.licenses[key]; ok {
			return nil, fmt.Errorf("concluded license for '%s' is declared more than once", key)
		}
		attribute, err := ReadLicenseAttribute(attributePath)
		if err != nil {
			return nil, fmt.Errorf("reading concluded license of '%s': %w", rawPURL, err)
		}
		c.licenses[key] = &concludedLicense{key: key, purl: purl, path: attributePath, attribute: attribute}
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
// returns its canonical form. The version and the qualifiers are optional and
// match any value when left out. Subpaths are rejected.
func ParseConcludedKey(raw string) (string, error) {
	purl, err := parseConcludedPURL(raw)
	if err != nil {
		return "", err
	}
	return purl.ToString(), nil
}

func parseConcludedPURL(raw string) (packageurl.PackageURL, error) {
	purl, err := packageurl.FromString(raw)
	if err != nil {
		return packageurl.PackageURL{}, fmt.Errorf("invalid PURL '%s' for a concluded license: %w", raw, err)
	}
	if purl.Subpath != "" {
		return packageurl.PackageURL{}, fmt.Errorf("PURL '%s' for a concluded license must not have a subpath", raw)
	}
	if err := purl.Qualifiers.Normalize(); err != nil {
		return packageurl.PackageURL{}, fmt.Errorf("invalid PURL '%s' for a concluded license: %w", raw, err)
	}
	return purl, nil
}

// matches reports whether the concluded license applies to the package: type,
// namespace and name are equal, and the version and qualifiers of the key, if
// any, are those of the package.
func (l *concludedLicense) matches(pkg packageurl.PackageURL) bool {
	if l.purl.Type != pkg.Type || l.purl.Namespace != pkg.Namespace || l.purl.Name != pkg.Name {
		return false
	}
	if l.purl.Version != "" && l.purl.Version != pkg.Version {
		return false
	}
	have := pkg.Qualifiers.Map()
	for _, q := range l.purl.Qualifiers {
		if v, ok := have[q.Key]; !ok || v != q.Value {
			return false
		}
	}
	return true
}

// specificity orders matching keys: a version outweighs any number of qualifiers.
func (l *concludedLicense) specificity() (int, int) {
	version := 0
	if l.purl.Version != "" {
		version = 1
	}
	return version, len(l.purl.Qualifiers)
}

// find returns the most specific concluded license matching the package. Keys
// that match with the same specificity are ambiguous.
func (c *ConcludedLicenses) find(pkg packageurl.PackageURL) (*concludedLicense, error) {
	var best *concludedLicense
	var tied []string
	for _, l := range c.licenses {
		if !l.matches(pkg) {
			continue
		}
		if best == nil {
			best = l
			continue
		}
		bv, bq := best.specificity()
		lv, lq := l.specificity()
		switch {
		case lv > bv || (lv == bv && lq > bq):
			best, tied = l, nil
		case lv == bv && lq == bq:
			if tied == nil {
				tied = []string{best.key}
			}
			tied = append(tied, l.key)
		}
	}
	if tied != nil {
		sort.Strings(tied)
		return nil, fmt.Errorf("concluded licenses %v are equally specific for '%s'", tied, pkg.ToString())
	}
	return best, nil
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

	override, err := c.find(metadata.GetPURL())
	if err != nil {
		return fmt.Errorf("%s: %w", node.Label, err)
	}
	if override != nil {
		c.used[override.key] = true
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
