load("@package_metadata//:defs.bzl", "package_metadata")
load(":bar_toolchain.bzl", "bar_toolchain", "bar_toolchain_variable")

toolchain_type(name = "toolchain_type")

package_metadata(
    name = "toolchain_metadata_variable",
    purl = "pkg:bar/variable@0.0.1",
    visibility = ["//visibility:public"],
)

bar_toolchain_variable(
    name = "toolchain_variable",
    package_metadata = [
        ":toolchain_metadata_variable",
    ],
    visibility = ["//visibility:public"],
)

package_metadata(
    name = "toolchain_metadata",
    purl = "pkg:bar/std@1.2.3",
    visibility = ["//visibility:public"],
)

bar_toolchain(
    name = "barc",
    package_metadata = [
        ":toolchain_metadata",
    ],
)

toolchain(
    name = "barc_linux_linux_toolchain",
    exec_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
    target_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
    toolchain = ":barc",
    toolchain_type = ":toolchain_type",
)

toolchain(
    name = "barc_macos_linux_toolchain",
    exec_compatible_with = [
        "@platforms//os:osx",
        "@platforms//cpu:arm64",
    ],
    target_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
    toolchain = ":barc_linux",
    toolchain_type = ":toolchain_type",
)

toolchain(
    name = "barc_macos_macos_toolchain",
    exec_compatible_with = [
        "@platforms//os:osx",
        "@platforms//cpu:arm64",
    ],
    target_compatible_with = [
        "@platforms//os:osx",
        "@platforms//cpu:arm64",
    ],
    toolchain = ":barc",
    toolchain_type = ":toolchain_type",
)
