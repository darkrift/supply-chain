"""Stamped SBOM helper macros for examples."""

load("@aspect_bazel_lib//lib:expand_template.bzl", "expand_template")
load("@supply_chain_tools//sbom:cyclonedx.bzl", "cyclonedx")
load("@supply_chain_tools//sbom:providers.bzl", "SbomInfo")
load("@supply_chain_tools//sbom:spdx.bzl", "spdx")

def _maybe_out(out):
    return {} if out == None else {"out": out}

def _stamped_cyclonedx_impl(name, sbom, format, out, serial_number_template, visibility):
    kwargs = _maybe_out(out)
    if serial_number_template != "{SERIAL_NUMBER}":
        serial_number = "{}_serial_number".format(name)
        expand_template(
            name = serial_number,
            out = "{}.txt".format(serial_number),
            stamp = -1,
            stamp_substitutions = {
                "{SERIAL_NUMBER}": "{{SBOM_SERIAL_NUMBER}}",
            },
            substitutions = {
                "{SERIAL_NUMBER}": "urn:uuid:00000000-0000-0000-0000-000000000000",
            },
            template = [serial_number_template],
        )
        kwargs["serial_number"] = ":{}".format(serial_number)

    cyclonedx(
        name = name,
        format = format,
        sbom = sbom,
        stamp = 1,
        visibility = visibility,
        **kwargs
    )

stamped_cyclonedx = macro(
    implementation = _stamped_cyclonedx_impl,
    attrs = {
        "format": attr.string(
            default = "json",
            values = ["json", "xml"],
            configurable = False,
            doc = "The output format for the CycloneDX SBOM.",
        ),
        "out": attr.output(
            doc = "The output file for the CycloneDX SBOM.",
        ),
        "sbom": attr.label(
            mandatory = True,
            configurable = False,
            providers = [SbomInfo],
            doc = "The sbom target to generate the CycloneDX SBOM from.",
        ),
        "serial_number_template": attr.string(
            default = "{SERIAL_NUMBER}",
            configurable = False,
            doc = "Template for the CycloneDX serialNumber file. {SERIAL_NUMBER} expands from SBOM_SERIAL_NUMBER.",
        ),
    },
)

def _stamped_spdx_impl(name, sbom, format, out, document_namespace_template, visibility):
    document_namespace = "{}_document_namespace".format(name)
    expand_template(
        name = document_namespace,
        out = "{}.txt".format(document_namespace),
        stamp = -1,
        stamp_substitutions = {
            "{BUILD_VERSION}": "{{STABLE_BUILD_VERSION}}",
            "{GIT_COMMIT}": "{{STABLE_GIT_COMMIT}}",
            "{VCS_REVISION}": "{{STABLE_VCS_REVISION}}",
        },
        substitutions = {
            "{BUILD_VERSION}": "dev",
            "{GIT_COMMIT}": "unknown",
            "{VCS_REVISION}": "unknown",
        },
        template = [document_namespace_template],
    )

    spdx(
        name = name,
        document_namespace = ":{}".format(document_namespace),
        format = format,
        sbom = sbom,
        stamp = 1,
        visibility = visibility,
        **_maybe_out(out)
    )

stamped_spdx = macro(
    implementation = _stamped_spdx_impl,
    attrs = {
        "document_namespace_template": attr.string(
            default = "https://spdx.org/spdxdocs/{BUILD_VERSION}-{GIT_COMMIT}",
            configurable = False,
            doc = "Template for the SPDX document namespace file. Supports {BUILD_VERSION}, {GIT_COMMIT}, and {VCS_REVISION}.",
        ),
        "format": attr.string(
            default = "json",
            values = ["json", "yaml", "tag-value"],
            configurable = False,
            doc = "The output format for the SPDX SBOM.",
        ),
        "out": attr.output(
            doc = "The output file for the SPDX SBOM.",
        ),
        "sbom": attr.label(
            mandatory = True,
            configurable = False,
            providers = [SbomInfo],
            doc = "The sbom target to generate the SPDX SBOM from.",
        ),
    },
)
