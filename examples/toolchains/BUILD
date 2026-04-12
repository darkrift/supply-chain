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
