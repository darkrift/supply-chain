"""Analysis test for toolchain-contributed package metadata in SBOM graphs."""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("@supply_chain_tools//gather_metadata:gather_metadata.bzl", "gather_metadata_info")
load("@supply_chain_tools//gather_metadata:providers.bzl", "TransitiveMetadataInfo")
load("@supply_chain_tools//gather_metadata:serialization.bzl", "metadata_info_to_json")

def _toolchain_sbom_test_impl(ctx):
    env = analysistest.begin(ctx)

    target_under_test = analysistest.target_under_test(env)
    parsed = json.decode(metadata_info_to_json(target_under_test[TransitiveMetadataInfo])[0])

    toolchain_label = ""
    for node in parsed["nodes"]:
        if ("//toolchains:barc" in node["label"] and
            node["metadata_file"].endswith("toolchain_metadata.package-metadata.json")):
            toolchain_label = node["label"]

    asserts.true(
        env,
        bool(toolchain_label),
        "Expected the resolved bar toolchain metadata node in {}".format(parsed["nodes"]),
    )

    has_toolchain_edge = False
    for edge in parsed["edges"]:
        if edge["to"] == toolchain_label:
            has_toolchain_edge = True

    asserts.true(
        env,
        has_toolchain_edge,
        "Expected an incoming edge to {} in {}".format(toolchain_label, parsed["edges"]),
    )

    return analysistest.end(env)

toolchain_sbom_test = analysistest.make(
    _toolchain_sbom_test_impl,
    extra_target_under_test_aspects = [gather_metadata_info],
)
