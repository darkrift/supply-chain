"""Providers for the sbom rules.

Warning: This is private to the aspect that walks the tree. The API is subject
to change at any release.
"""

def _init_toolchain_component_usage(metadata, relationship, applies_to = "consumer", notes = ""):
    return {
        "metadata": metadata,
        "relationship": relationship,
        "applies_to": applies_to,
        "notes": notes,
    }

ToolchainComponentUsageInfo, _toolchain_component_usage_info_create = provider(
    doc = "Describes how a toolchain contributes a package to the SBOM.",
    fields = {
        "metadata": "The PackageMetadataInfo provider describing the component.",
        "relationship": "Relationship kind between the consumer/output and this component.",
        "applies_to": "Whether the relationship applies to the consumer or the built output.",
        "notes": "Optional free-form notes for emitters.",
    },
    init = _init_toolchain_component_usage,
)

def _init_toolchain_sbom(toolchain_type, toolchain_label, usages = []):
    return {
        "toolchain_type": toolchain_type,
        "toolchain_label": toolchain_label,
        "usages": usages,
    }

ToolchainSbomInfo, _toolchain_sbom_info_create = provider(
    doc = "SBOM-relevant package usages contributed by a toolchain.",
    fields = {
        "toolchain_type": "The label of the toolchain type used to resolve this toolchain.",
        "toolchain_label": "The label of the resolved toolchain target.",
        "usages": "Sequence of ToolchainComponentUsageInfo providers.",
    },
    init = _init_toolchain_sbom,
)

null_toolchain_sbom_info = ToolchainSbomInfo(
    toolchain_type = None,
    toolchain_label = None,
    usages = [],
)

def _init_sbom_node(target, metadata):
    return {
        "target": target,
        "metadata": metadata,
    }

SbomNodeInfo, _sbom_node_info_create = provider(
    doc = "A package metadata node included in the SBOM graph.",
    fields = {
        "target": "The Bazel label the metadata was attached to.",
        "metadata": "The PackageMetadataInfo provider for this node.",
    },
    init = _init_sbom_node,
)

def _init_sbom_relationship(
        from_target,
        to_metadata,
        relationship,
        origin,
        applies_to = "consumer",
        toolchain_type = None,
        toolchain_label = None,
        notes = ""):
    return {
        "from_target": from_target,
        "to_metadata": to_metadata,
        "relationship": relationship,
        "origin": origin,
        "applies_to": applies_to,
        "toolchain_type": toolchain_type,
        "toolchain_label": toolchain_label,
        "notes": notes,
    }

SbomRelationshipInfo, _sbom_relationship_info_create = provider(
    doc = "A relationship edge in the SBOM graph.",
    fields = {
        "from_target": "The Bazel label the relationship originates from.",
        "to_metadata": "The PackageMetadataInfo provider describing the related component.",
        "relationship": "The semantic relationship type.",
        "origin": "How this relationship was discovered, e.g. dependency or toolchain.",
        "applies_to": "Whether the relationship applies to the consumer or the built output.",
        "toolchain_type": "Optional toolchain type label for toolchain-derived relationships.",
        "toolchain_label": "Optional resolved toolchain label for toolchain-derived relationships.",
        "notes": "Optional free-form notes for emitters.",
    },
    init = _init_sbom_relationship,
)

def _init_transitive_sbom(nodes = depset(), relationships = depset(), top_level_target = None, traces = []):
    return {
        "nodes": nodes,
        "relationships": relationships,
        "top_level_target": top_level_target,
        "traces": traces,
    }

TransitiveSbomInfo, _transitive_sbom_info_create = provider(
    doc = "Transitive SBOM graph information for a target.",
    fields = {
        "nodes": "depset of SbomNodeInfo values.",
        "relationships": "depset of SbomRelationshipInfo values.",
        "top_level_target": "The top-level target being described.",
        "traces": "Diagnostic traces for why a node or relationship was included.",
    },
    init = _init_transitive_sbom,
)

null_transitive_sbom_info = TransitiveSbomInfo(
    nodes = depset(),
    relationships = depset(),
    top_level_target = None,
    traces = [],
)

SbomInfo = provider(
    doc = "A provider that contains the configuration for generating an SBOM.",
    fields = {
        "config": "The configuration file for generating the SBOM.",
    }
)
