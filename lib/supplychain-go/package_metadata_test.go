package supplychain

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"

	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/label"
)

func TestReadValid(t *testing.T) {
	type ExpectedData struct {
		Label          string
		PURL           packageurl.PackageURL
		AttributeKinds []string
	}

	cases := []struct {
		Name     string
		Input    string
		Expected ExpectedData
	}{
		{
			Name: "no-version",
			Input: `
			{
				"purl": "pkg:github/bazel-contrib/supply-chain",
				"label": "@package_metadata//foo/bar",
				"attributes": {}
			}
			`,
			Expected: ExpectedData{
				Label: "@package_metadata//foo/bar",
				PURL: *packageurl.NewPackageURL(
					/* type= */ "github",
					/* namespace= */ "bazel-contrib",
					/* name= */ "supply-chain",
					/* version= */ "",
					/* qualifiers= */ packageurl.Qualifiers{},
					/* subpath= */ "",
				),
			},
		},
		{
			Name: "version",
			Input: `
			{
				"purl": "pkg:github/bazel-contrib/supply-chain@v0.0.1",
				"label": "@package_metadata//foo/bar",
				"attributes": {}
			}
			`,
			Expected: ExpectedData{
				Label: "@package_metadata//foo/bar",
				PURL: *packageurl.NewPackageURL(
					/* type= */ "github",
					/* namespace= */ "bazel-contrib",
					/* name= */ "supply-chain",
					/* version= */ "v0.0.1",
					/* qualifiers= */ packageurl.Qualifiers{},
					/* subpath= */ "",
				),
			},
		},
		{
			Name: "single-attribute-kind",
			Input: `
			{
				"purl": "pkg:github/bazel-contrib/supply-chain",
				"label": "@package_metadata//foo/bar",
				"attributes": {
				  "foo": "path/to/foo.attributes.json"
				}
			}
			`,
			Expected: ExpectedData{
				Label: "@package_metadata//foo/bar",
				PURL: *packageurl.NewPackageURL(
					/* type= */ "github",
					/* namespace= */ "bazel-contrib",
					/* name= */ "supply-chain",
					/* version= */ "",
					/* qualifiers= */ packageurl.Qualifiers{},
					/* subpath= */ "",
				),
				AttributeKinds: []string{
					"foo",
				},
			},
		},
		{
			Name: "multiple-attribute-kind",
			Input: `
			{
				"purl": "pkg:github/bazel-contrib/supply-chain",
				"label": "@package_metadata//foo/bar",
				"attributes": {
				  "bar": "path/to/bar.attributes.json",
				  "foo": "path/to/foo.attributes.json",
				  "baz": "path/to/foo.attributes.json"
				}
			}
			`,
			Expected: ExpectedData{
				Label: "@package_metadata//foo/bar",
				PURL: *packageurl.NewPackageURL(
					/* type= */ "github",
					/* namespace= */ "bazel-contrib",
					/* name= */ "supply-chain",
					/* version= */ "",
					/* qualifiers= */ packageurl.Qualifiers{},
					/* subpath= */ "",
				),
				AttributeKinds: []string{
					"bar",
					"baz",
					"foo",
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(
			fmt.Sprintf("Deserialize %s", c.Name),
			func(t *testing.T) {
				m, err := ReadPackageMetadata(strings.NewReader(c.Input))
				assert.Nil(t, err)
				assert.Equal(t, label.MustParse(c.Expected.Label), m.GetLabel())
				assert.Equal(t, c.Expected.PURL, m.GetPURL())
				assert.ElementsMatch(t, c.Expected.AttributeKinds, m.ListAttributeKinds())
			})
		t.Run(
			fmt.Sprintf("Serialize %s", c.Name),
			func(t *testing.T) {
				m, err := ReadPackageMetadata(strings.NewReader(c.Input))
				assert.Nil(t, err)

				b, err := json.Marshal(m)
				assert.Nil(t, err)
				assert.JSONEq(t, c.Input, string(b))
			})
	}
}

type FakeAttribute struct {
	Name string
}

func TestGetAttribute(t *testing.T) {
	p := &packageMetadata{
		Label: label.MustParse("@package_metadata//foo/bar"),
		PURL: *packageurl.NewPackageURL(
			/* type= */ "github",
			/* namespace= */ "bazel-contrib",
			/* name= */ "supply-chain",
			/* version= */ "HEAD",
			/* qualifiers= */ packageurl.Qualifiers{},
			/* subpath= */ "",
		),
		Attributes: map[string]string{
			"fake":  os.Args[0],
			"other": "/does/not/exist",
		},
	}

	a, err := GetPackageAttribute(
		p,
		PackageAttributeDescriptor[FakeAttribute]{
			Kind: "fake",
			Parser: func(r io.Reader) (*FakeAttribute, error) {
				return &FakeAttribute{
					Name: "foo",
				}, nil
			},
		})
	assert.Nil(t, err)
	assert.Equal(t, &FakeAttribute{Name: "foo"}, a)
}

func TestPURLCanonicalEncoding(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"debian epoch and plus", "pkg:deb/debian/busybox-static@1%3A1.37.0-6%2Bb8?arch=amd64", "pkg:deb/debian/busybox-static@1:1.37.0-6%2Bb8?arch=amd64"},
		{"docker digest", "pkg:docker/distroless/cc-debian13@sha256%3Aabcdef?repository_url=gcr.io", "pkg:docker/distroless/cc-debian13@sha256:abcdef?repository_url=gcr.io"},
		{"qualifier encoding", "pkg:generic/example?note=space%20and%2Bplus&repository_url=https%3A%2F%2Fexample.com", "pkg:generic/example?note=space%20and%2Bplus&repository_url=https:%2F%2Fexample.com"},
		{"literal percent escape", "pkg:generic/example@literal%253A%252B", "pkg:generic/example@literal%253A%252B"},
		{"sub-delimiters", "pkg:generic/example%28one%29@1.0%2Bbuild%21%2A", "pkg:generic/example%28one%29@1.0%2Bbuild%21%2A"},
		{"namespace and subpath", "pkg:generic/team%3Aone/example#src/a%3Ab%2Bc%20d", "pkg:generic/team:one/example#src/a:b%2Bc%20d"},
		{"npm scope", "pkg:npm/%40scope/example@1.0.0", "pkg:npm/%40scope/example@1.0.0"},
		{"no version", "pkg:generic/example", "pkg:generic/example"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			purl, err := packageurl.FromString(c.input)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, c.want, purl.String())
			decoded, err := packageurl.FromString(purl.String())
			assert.NoError(t, err)
			assert.Equal(t, purl, decoded)

			metadata := &packageMetadata{Label: label.MustParse("//app:metadata"), PURL: purl}
			data, err := json.Marshal(metadata)
			assert.NoError(t, err)
			var raw rawPackageMetadata
			assert.NoError(t, json.Unmarshal(data, &raw))
			assert.Equal(t, c.want, raw.PURL)
		})
	}
}
