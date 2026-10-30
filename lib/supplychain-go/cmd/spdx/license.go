package main

import (
	"os"
	"sort"
	"strings"

	supplychain "github.com/bazel-contrib/supply-chain/lib/supplychain-go"
	"github.com/spdx/tools-golang/spdx"
)

// licenseCollector gathers the custom licenses used by packages, which SPDX
// requires to be defined in the document as `LicenseRef-` licenses.
type licenseCollector struct {
	byID map[string]*spdx.OtherLicense
	// fallback holds the ids whose text is only the license name, so that a
	// later package providing the real text can replace it.
	fallback map[string]bool
}

func newLicenseCollector() *licenseCollector {
	return &licenseCollector{
		byID:     map[string]*spdx.OtherLicense{},
		fallback: map[string]bool{},
	}
}

// declared returns the SPDX license expression for the package and records
// the custom licenses it references.
//
// SPDX 2.3 only allows exceptions from the SPDX list after `WITH`, so a
// license combined with a custom exception is defined as a `LicenseRef-` for
// the combined terms.
func (c *licenseCollector) declared(attribute *supplychain.LicenseAttribute) string {
	if attribute == nil {
		return "NOASSERTION"
	}
	root := attribute.Root()
	return c.render(attribute, root, root)
}

func (c *licenseCollector) render(attribute *supplychain.LicenseAttribute, root, node supplychain.LicenseExpression) string {
	switch {
	case node.Kind != nil:
		return c.leaf(attribute, root, node)
	case node.Operator == supplychain.LicenseWith:
		leaf := node.Operands[0]
		if !node.Exception.IsCustom() {
			return c.leaf(attribute, root, leaf) + " WITH " + node.Exception.Identifier
		}
		id := "LicenseRef-" + refSuffix(*leaf.Kind, false, leaf.OrLater) + "-WITH-" + refSuffix(*node.Exception, true, false)
		c.define(id, leaf.Kind.Name+" WITH "+node.Exception.Name, extractedText(attribute, root, node.Exception.Name))
		return id
	default:
		parts := make([]string, len(node.Operands))
		for i, o := range node.Operands {
			parts[i] = c.render(attribute, root, o)
			if (o.Operator == supplychain.LicenseAnd || o.Operator == supplychain.LicenseOr) && o.Operator != node.Operator {
				parts[i] = "(" + parts[i] + ")"
			}
		}
		return strings.Join(parts, " "+string(node.Operator)+" ")
	}
}

// leaf renders a license. A custom license cannot be followed by `+` in SPDX,
// so "or later" is part of the defined reference.
func (c *licenseCollector) leaf(attribute *supplychain.LicenseAttribute, root, node supplychain.LicenseExpression) string {
	kind := *node.Kind
	if !kind.IsCustom() {
		return node.String()
	}
	id := "LicenseRef-" + refSuffix(kind, false, node.OrLater)
	name := kind.Name
	if node.OrLater {
		name += " or later"
	}
	c.define(id, name, extractedText(attribute, root, name))
	return id
}

// refSuffix is the part of a custom reference after its `LicenseRef-` or
// `AdditionRef-` prefix.
func refSuffix(kind supplychain.LicenseKind, exception, orLater bool) string {
	suffix := strings.TrimPrefix(strings.TrimPrefix(kind.RefID(exception), "LicenseRef-"), "AdditionRef-")
	if orLater {
		suffix += "-or-later"
	}
	return suffix
}

// define records a custom license, replacing a name-only text by a real one.
func (c *licenseCollector) define(id, name string, text licenseText) {
	if existing, ok := c.byID[id]; ok {
		if c.fallback[id] && text.real {
			existing.ExtractedText = text.text
			delete(c.fallback, id)
		}
		return
	}
	c.byID[id] = &spdx.OtherLicense{
		LicenseIdentifier: id,
		LicenseName:       name,
		ExtractedText:     text.text,
	}
	if !text.real {
		c.fallback[id] = true
	}
}

func (c *licenseCollector) otherLicenses() []*spdx.OtherLicense {
	licenses := make([]*spdx.OtherLicense, 0, len(c.byID))
	for _, l := range c.byID {
		licenses = append(licenses, l)
	}
	sort.Slice(licenses, func(i, j int) bool {
		return licenses[i].LicenseIdentifier < licenses[j].LicenseIdentifier
	})
	return licenses
}

type licenseText struct {
	text string
	// real is whether text was read from a license file.
	real bool
}

// extractedText is the license text file of the package when the license
// consists of a single kind, otherwise the fallback name.
func extractedText(attribute *supplychain.LicenseAttribute, root supplychain.LicenseExpression, fallback string) licenseText {
	if attribute.Text != "" && root.IsSingle() {
		if text, err := os.ReadFile(attribute.Text); err == nil {
			return licenseText{text: string(text), real: true}
		}
	}
	return licenseText{text: fallback}
}
