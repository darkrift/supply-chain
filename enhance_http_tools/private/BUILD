load("//private:http_test.bzl", "http_test")

exports_files(
    [
        "http.bzl",
        "http_test.bzl",
    ],
    visibility = ["//visibility:public"],
)

http_test(
    name = "http_test",
)

filegroup(
    name = "srcs",
    srcs = [
        "BUILD",
        "http.bzl",
        "http_test.bzl",
    ],
    visibility = ["//visibility:public"],
)
