load(":metadata_test.bzl", "golangci_lint_metadata_test")

package(default_visibility = ["//visibility:public"])

golangci_lint_metadata_test(
    name = "package_metadata_test",
    artifacts = [
        "@golangci_lint_linux_amd64//:golangci-lint",
        "@golangci_lint_linux_arm64//:golangci-lint",
        "@golangci_lint_darwin_amd64//:golangci-lint",
        "@golangci_lint_darwin_arm64//:golangci-lint",
    ],
    expected = {
        "darwin-amd64": "632e96e6d5294fbbe7b2c410a49c8fa01c60712a0af85a567de85bcc1623ea21",
        "darwin-arm64": "234463f059249f82045824afdcdd5db5682d0593052f58f6a3039a0a1c3899f6",
        "linux-amd64": "ca21c961a33be3bc15e4292dc40c98c8dcc5463a7b6768a3afc123761630c09c",
        "linux-arm64": "8eb0cee9b1dbf0eaa49871798c7f8a5b35f2960c52d776a5f31eb7d886b92746",
    },
    metadata = [
        "@golangci_lint_linux_amd64//:package_metadata",
        "@golangci_lint_linux_arm64//:package_metadata",
        "@golangci_lint_darwin_amd64//:package_metadata",
        "@golangci_lint_darwin_arm64//:package_metadata",
    ],
)

filegroup(
    name = "srcs",
    srcs = [
        "BUILD",
        "metadata_test.bzl",
    ],
)
