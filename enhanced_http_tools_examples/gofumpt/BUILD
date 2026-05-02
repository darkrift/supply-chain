load("//:metadata_test.bzl", "metadata_test")

package(default_visibility = ["//visibility:public"])

metadata_test(
    name = "package_metadata_test",
    artifacts = [
        "@com_github_mvdan_gofumpt_linux_amd64//:gofumpt",
        "@com_github_mvdan_gofumpt_linux_amd64//file",
        "@com_github_mvdan_gofumpt_linux_arm64//:gofumpt",
        "@com_github_mvdan_gofumpt_linux_arm64//file",
        "@com_github_mvdan_gofumpt_darwin_amd64//:gofumpt",
        "@com_github_mvdan_gofumpt_darwin_amd64//file",
        "@com_github_mvdan_gofumpt_darwin_arm64//:gofumpt",
        "@com_github_mvdan_gofumpt_darwin_arm64//file",
    ],
    expected = {
        "darwin_amd64": "b7d05e092da45c5ec96344ab635b1d6547c3e27c840ba39bc76989934efd7ce3",
        "darwin_arm64": "08f23114760a090b090706d92b8c52b9875b9eb352d76c77aa354d6aa20b045a",
        "linux_amd64": "6ff459c1dcae3b0b00844c1a5a4a5b0f547237d8a4f3624aaea8d424aeef24c6",
        "linux_arm64": "00c18c88ef50437629626ba20d677f4648684cb280952814cdd887677d42cbd3",
    },
    file_name_pattern = "gofumpt",
    metadata = [
        "@com_github_mvdan_gofumpt_linux_amd64//:package_metadata",
        "@com_github_mvdan_gofumpt_linux_arm64//:package_metadata",
        "@com_github_mvdan_gofumpt_darwin_amd64//:package_metadata",
        "@com_github_mvdan_gofumpt_darwin_arm64//:package_metadata",
    ],
    purl_prefix = "pkg:github/mvdan/gofumpt@0.7.0",
)

filegroup(
    name = "srcs",
    srcs = ["BUILD"],
)
