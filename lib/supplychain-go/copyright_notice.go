package supplychain

import (
	"encoding/json"
	"io"
	"slices"
)

// CopyrightNoticeKind is the kind of the `copyright_notice` package attribute.
const CopyrightNoticeKind = "build.bazel.attribute.copyright_notice"

// CopyrightNotice is the `PackageAttributeDescriptor` of the `copyright_notice` attribute.
var CopyrightNotice = PackageAttributeDescriptor[[]string]{
	Kind: CopyrightNoticeKind,
	Parser: func(r io.Reader) (*[]string, error) {
		var text []string
		if err := json.NewDecoder(r).Decode(&text); err != nil {
			return nil, err
		}
		return &text, nil
	},
}

// GetCopyrightNotice returns the copyright notice entries of the package, or
// nil if the package does not declare a `copyright_notice` attribute.
func GetCopyrightNotice(m PackageMetadata) ([]string, error) {
	if !slices.Contains(m.ListAttributeKinds(), CopyrightNoticeKind) {
		return nil, nil
	}
	text, err := GetPackageAttribute(m, CopyrightNotice)
	if err != nil {
		return nil, err
	}
	return *text, nil
}
