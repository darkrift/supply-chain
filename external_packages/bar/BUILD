load("@package_metadata//:defs.bzl", "package_metadata")
load(":bar_binary.bzl", "bar_binary")
load(":bar_library.bzl", "bar_library")

package_metadata(
    name = "library_metadata",
    purl = "pkg:bar/library@1.0.0",
    visibility = ["//visibility:public"],
)

bar_library(
    name = "library",
    package_metadata = [
        ":library_metadata",
    ],
)

bar_binary(
    name = "binary",
    toolchains = [
        "//toolchains:toolchain_variable",
    ],
    visibility = ["//visibility:public"],
    deps = [":library"],
)
