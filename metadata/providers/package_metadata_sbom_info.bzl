"""Declares providers for toolchain-contributed package metadata in SBOMs."""

visibility("public")

def _init_toolchain_usage(metadata, relationship, applies_to = "consumer", notes = ""):
    return {
        "metadata": metadata,
        "relationship": relationship,
        "applies_to": applies_to,
        "notes": notes,
    }

PackageMetadataToolchainUsageInfo, _package_metadata_toolchain_usage_info_create = provider(
    doc = """
Describes how a toolchain contributes a package to an SBOM.

> **Fields in this provider are not covered by the stability guarantee.**
""".strip(),
    fields = {
        "metadata": "The `PackageMetadataInfo` provider describing the component.",
        "relationship": "Relationship kind between the consumer/output and this component.",
        "applies_to": "Whether the relationship applies to the consumer or the built output.",
        "notes": "Optional free-form notes for emitters.",
    },
    init = _init_toolchain_usage,
)

def _init_toolchain_sbom(toolchain_type, toolchain_label, usages = []):
    return {
        "toolchain_type": toolchain_type,
        "toolchain_label": toolchain_label,
        "usages": usages,
    }

PackageMetadataToolchainSbomInfo, _package_metadata_toolchain_sbom_info_create = provider(
    doc = """
SBOM-relevant package usages contributed by a toolchain.

> **Fields in this provider are not covered by the stability guarantee.**
""".strip(),
    fields = {
        "toolchain_type": "The label of the toolchain type used to resolve this toolchain.",
        "toolchain_label": "The label of the resolved toolchain target.",
        "usages": "Sequence of `PackageMetadataToolchainUsageInfo` providers.",
    },
    init = _init_toolchain_sbom,
)
