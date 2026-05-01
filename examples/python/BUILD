load("@rules_python//python:defs.bzl", "py_binary", "py_library")
load("@pypi//:requirements.bzl", "requirement")
load("@supply_chain_tools//sbom:cyclonedx.bzl", "cyclonedx")
load("@supply_chain_tools//sbom:sbom.bzl", "sbom")
load("@supply_chain_tools//sbom:spdx.bzl", "spdx")

package(default_visibility = ["//visibility:public"])

py_library(
    name = "message_format",
    srcs = ["message_format.py"],
)

py_library(
    name = "greeting",
    srcs = ["greeting.py"],
    data = ["salutation.txt"],
    deps = [
        ":message_format",
        requirement("packaging"),
    ],
)

py_binary(
    name = "hello_python",
    srcs = ["hello_python.py"],
    deps = [":greeting"],
    python_version = "PY3",
)

sbom(
    name = "hello_python_sbom",
    target = ":hello_python",
)

cyclonedx(
    name = "hello_python_cyclonedx",
    sbom = ":hello_python_sbom",
)

spdx(
    name = "hello_python_spdx",
    sbom = ":hello_python_sbom",
)
