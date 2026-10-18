"""Analysis tests for the `concluded_licenses` of `sbom` targets."""

load("@package_metadata//licenses/rules:license.bzl", "license")
load("@rules_testing//lib:analysis_test.bzl", "analysis_test")
load("@rules_testing//lib:truth.bzl", "matching")
load("@supply_chain_tools//sbom:sbom.bzl", "sbom")

def sbom_concluded_licenses_failure_test(*, name, purl, message):
    """Asserts that an `sbom` concluding a license for `purl` fails with `message`."""
    native.filegroup(
        name = name + "_subject",
        tags = ["manual"],
    )
    license(
        name = name + "_license",
        kind = "@package_metadata//licenses/spdx:MIT",
        tags = ["manual"],
    )
    sbom(
        name = name + "_sbom",
        concluded_licenses = {purl: ":" + name + "_license"},
        target = ":" + name + "_subject",
        require_root_metadata = False,
        tags = ["manual"],
    )
    analysis_test(
        name = name,
        impl = lambda env, target: env.expect.that_target(target).failures().contains_predicate(
            matching.str_matches("*" + message + "*"),
        ),
        target = name + "_sbom",
        expect_failure = True,
    )
