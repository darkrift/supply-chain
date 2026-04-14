load("@supply_chain_tools//sbom:cyclonedx.bzl", "cyclonedx")
load("@supply_chain_tools//sbom:sbom.bzl", "sbom")

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
    target = "@supply-chain-go//:supplychain-go",
)

cyclonedx(
    name = "tools_cyclonedx",
    sbom = ":tools_sbom",
)
