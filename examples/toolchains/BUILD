load("@supply_chain_tools//sbom:cyclonedx.bzl", "cyclonedx")
load("@supply_chain_tools//sbom:sbom.bzl", "sbom")
load("@supply_chain_tools//sbom:spdx.bzl", "spdx")

sbom(
    name = "sbom",
    target = "@bar//:binary",
)

cyclonedx(
    name = "cyclonedx",
    sbom = ":sbom",
)

sbom(
    name = "tools_sbom",
    target = "@supply-chain-go//cmd/cyclonedx",
)

cyclonedx(
    name = "tools_cyclonedx",
    sbom = ":tools_sbom",
)

spdx(
    name = "tools_spdx",
    sbom = ":tools_sbom",
)
