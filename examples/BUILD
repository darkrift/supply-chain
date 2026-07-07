load("@package_metadata//licenses/rules:license.bzl", "license")
load("@package_metadata//purl:purl.bzl", "purl")
load("@package_metadata//rules:package_metadata.bzl", "package_metadata")
load("@supply_chain_tools//sbom:cyclonedx.bzl", "cyclonedx")
load("@supply_chain_tools//sbom:sbom.bzl", "sbom")
load(":toolchain_sbom_test.bzl", "toolchain_sbom_test")

package(
    default_package_metadata = [":package_metadata"],
    default_visibility = ["//visibility:public"],
)

package_metadata(
    name = "package_metadata",
    attributes = [
        ":license",
    ],
    purl = purl.bazel(
        module_name(),
        module_version(),
    ),
    visibility = ["//visibility:public"],
)

license(
    name = "license",
    kind = "@package_metadata//licenses/spdx:Apache-2.0",
    text = "LICENSE",
)

sbom(
    name = "bar_binary_sbom",
    require_root_metadata = False,
    tags = ["manual"],
    target = "@bar//:binary",
)

cyclonedx(
    name = "bar_binary_cyclonedx",
    sbom = ":bar_binary_sbom",
    tags = ["manual"],
)

toolchain_sbom_test(
    name = "bar_toolchain_sbom_test",
    target_under_test = "@bar//:binary",
)
