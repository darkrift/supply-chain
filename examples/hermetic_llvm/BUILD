load("@package_metadata//licenses/rules:license.bzl", "license")
load("@package_metadata//rules:package_metadata.bzl", "package_metadata")
load("@rules_python//python:defs.bzl", "py_test")
load("@supply_chain_tools//sbom:cyclonedx.bzl", "cyclonedx")
load("@supply_chain_tools//sbom:sbom.bzl", "sbom")
load(":defs.bzl", "glibc_cc_binary", "musl_cc_binary")

package(
    default_package_metadata = [":package_metadata"],
    default_visibility = ["//visibility:public"],
)

package_metadata(
    name = "package_metadata",
    attributes = [
        ":license",
    ],
    purl = "pkg:bazel/supply_chain_examples/hermetic_llvm@0.0.1",
)

license(
    name = "license",
    kind = "@package_metadata//licenses/spdx:Apache-2.0",
    text = "LICENSE",
)

glibc_cc_binary(
    name = "hello_glibc",
    srcs = ["hello.c"],
)

musl_cc_binary(
    name = "hello_musl",
    srcs = ["hello.c"],
)

sbom(
    name = "hello_glibc_sbom",
    target = ":hello_glibc",
)

cyclonedx(
    name = "hello_glibc_cyclonedx",
    sbom = ":hello_glibc_sbom",
)

sbom(
    name = "hello_musl_sbom",
    target = ":hello_musl",
)

cyclonedx(
    name = "hello_musl_cyclonedx",
    sbom = ":hello_musl_sbom",
)

py_test(
    name = "hello_glibc_sbom_test",
    srcs = ["llvm_libc_sbom_test.py"],
    args = [
        "$(location :hello_glibc_cyclonedx)",
        "pkg:generic/glibc@2.28",
        "pkg:generic/musl@1.2.6",
    ],
    data = [":hello_glibc_cyclonedx"],
    main = "llvm_libc_sbom_test.py",
)

py_test(
    name = "hello_musl_sbom_test",
    srcs = ["llvm_libc_sbom_test.py"],
    args = [
        "$(location :hello_musl_cyclonedx)",
        "pkg:generic/musl@1.2.6",
        "pkg:generic/glibc@2.28",
    ],
    data = [":hello_musl_cyclonedx"],
    main = "llvm_libc_sbom_test.py",
)
