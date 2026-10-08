"""Rules for generating a SBOM out of a target."""

load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")

package(
    default_package_metadata = ["//:package_metadata"],
    default_visibility = ["//visibility:public"],
)

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
)

# Disabled by default: strict generator mode re-parses and re-validates every
# generated JSON SBOM against the (large) vendored CycloneDX/SPDX JSON Schemas
# before the generator exits, which has a real cost across a big dependency
# graph. Opt in per-invocation with:
#   bazel build //some:target --//sbom:strict_validations
# or flip the default for a whole build with --//sbom:strict_validations=true
# in a bazelrc config.
bool_flag(
    name = "strict_validations",
    build_setting_default = False,
)

bzl_library(
    name = "sbom",
    srcs = [
        ":cyclonedx.bzl",
        ":sbom.bzl",
        ":spdx.bzl",
        "//:core_metadata",
        "//gather_metadata",
    ],
    visibility = ["//visibility:public"],
)
