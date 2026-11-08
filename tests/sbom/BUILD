load("@package_metadata//attributes:copyright_notice.bzl", "copyright_notice")
load("@package_metadata//rules:package_metadata.bzl", "package_metadata")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("@supply_chain_tools//sbom:cyclonedx.bzl", "cyclonedx")
load("@supply_chain_tools//sbom:sbom.bzl", "sbom")
load("@supply_chain_tools//sbom:spdx.bzl", "spdx")

package_metadata(
    name = "with_copyright_metadata",
    attributes = [":copyright"],
    purl = "pkg:generic/with-copyright@1.0.0",
)

copyright_notice(
    name = "copyright",
    text = [
        "Copyright © 2026 The authors of this stuff.",
        "Copyright © 1999 A. Cöntributor",
    ],
)

package_metadata(
    name = "without_copyright_metadata",
    purl = "pkg:generic/without-copyright@1.0.0",
)

filegroup(
    name = "with_copyright",
    package_metadata = [":with_copyright_metadata"],
)

filegroup(
    name = "without_copyright",
    package_metadata = [":without_copyright_metadata"],
)

[
    [
        sbom(
            name = "{}_sbom".format(name),
            target = ":{}".format(name),
        ),
        spdx(
            name = "{}_spdx".format(name),
            sbom = ":{}_sbom".format(name),
        ),
        cyclonedx(
            name = "{}_cyclonedx".format(name),
            sbom = ":{}_sbom".format(name),
        ),
    ]
    for name in [
        "with_copyright",
        "without_copyright",
    ]
]

sh_test(
    name = "copyright_notice_test",
    srcs = ["copyright_notice_test.sh"],
    data = [
        ":with_copyright_cyclonedx",
        ":with_copyright_spdx",
        ":without_copyright_cyclonedx",
        ":without_copyright_spdx",
    ],
    args = [
        "$(rootpath :with_copyright_spdx)",
        "$(rootpath :with_copyright_cyclonedx)",
        "$(rootpath :without_copyright_spdx)",
        "$(rootpath :without_copyright_cyclonedx)",
    ],
)
