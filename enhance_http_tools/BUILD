package(
    default_visibility = ["//visibility:public"],
)

exports_files([
    "defs.bzl",
])

filegroup(
    name = "srcs",
    srcs = [
        "BUILD",
        "MODULE.bazel",
        "defs.bzl",
    ] + [
        "//private:srcs",
    ],
)
