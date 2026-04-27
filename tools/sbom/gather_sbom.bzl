"""Aspect for collecting SBOM nodes and relationships, including toolchain usage."""

load(
    "@package_metadata//:defs.bzl",
    "PackageMetadataInfo",
    "PackageMetadataToolchainSbomInfo",
)
load(
    "@supply_chain_tools//gather_metadata:core.bzl",
    "TOOLCHAINS",
    "should_traverse",
)
load("@supply_chain_tools//gather_metadata:trace.bzl", "TraceInfo")
load(
    ":providers.bzl",
    "SbomNodeInfo",
    "SbomRelationshipInfo",
    "ToolchainSbomInfo",
    "TransitiveSbomInfo",
    "null_toolchain_sbom_info",
    "null_transitive_sbom_info",
)

def _iter_toolchain_dependencies(ctx):
    toolchains = []
    if ctx.rule.toolchains:
        for toolchain_type in TOOLCHAINS:
            toolchain_label = Label(toolchain_type)
            if toolchain_label in ctx.rule.toolchains:
                toolchains.append((toolchain_type, ctx.rule.toolchains[toolchain_label]))
            elif toolchain_type in ctx.rule.toolchains:
                toolchains.append((toolchain_type, ctx.rule.toolchains[toolchain_type]))
    return toolchains

def _package_metadata_deps(rule):
    if not rule:
        return []

    if hasattr(rule.attr, "kind") and rule.attr.kind == "build.bazel.attribute.license":
        return []

    if hasattr(rule.attr, "package_metadata"):
        return rule.attr.package_metadata
    if hasattr(rule.attr, "applicable_licenses"):
        return rule.attr.applicable_licenses
    return []

def _metadata_infos_for_target(target):
    metadata_infos = []
    if not hasattr(target, "rule"):
        if TransitiveSbomInfo in target:
            for node in target[TransitiveSbomInfo].nodes.to_list():
                if node.target == target.label:
                    metadata_infos.append(node.metadata)
        return metadata_infos

    for metadata_dependency in _package_metadata_deps(target.rule):
        if PackageMetadataInfo in metadata_dependency:
            metadata_infos.append(metadata_dependency[PackageMetadataInfo])
    if not metadata_infos and TransitiveSbomInfo in target:
        for node in target[TransitiveSbomInfo].nodes.to_list():
            if node.target == target.label:
                metadata_infos.append(node.metadata)
    return metadata_infos

def _metadata_infos_for_rule(rule):
    metadata_infos = []
    for metadata_dependency in _package_metadata_deps(rule):
        if PackageMetadataInfo in metadata_dependency:
            metadata_infos.append(metadata_dependency[PackageMetadataInfo])
    return metadata_infos

def _direct_nodes_and_relationships(target, ctx):
    nodes = []
    relationships = []

    for metadata in _metadata_infos_for_rule(ctx.rule):
        nodes.append(SbomNodeInfo(
            target = target.label,
            metadata = metadata,
        ))

    attrs = [attr for attr in dir(ctx.rule.attr)]
    for name in attrs:
        if not should_traverse(ctx, name):
            continue
        if name in ["package_metadata", "applicable_licenses"]:
            continue

        attr_value = getattr(ctx.rule.attr, name)
        if type(attr_value) != type([]):
            attr_value = [attr_value]

        for dep in attr_value:
            if type(dep) != "Target":
                continue
            for metadata in _metadata_infos_for_target(dep):
                nodes.append(SbomNodeInfo(
                    target = dep.label,
                    metadata = metadata,
                ))
                relationships.append(SbomRelationshipInfo(
                    from_target = target.label,
                    to_metadata = metadata,
                    relationship = "dependency",
                    origin = "dependency",
                    applies_to = "consumer",
                ))

    for toolchain_type, dep in _iter_toolchain_dependencies(ctx):
        if ToolchainSbomInfo not in dep:
            continue
        toolchain_sbom = dep[ToolchainSbomInfo]
        for usage in toolchain_sbom.usages:
            nodes.append(SbomNodeInfo(
                target = toolchain_sbom.toolchain_label,
                metadata = usage.metadata,
            ))
            relationships.append(SbomRelationshipInfo(
                from_target = target.label,
                to_metadata = usage.metadata,
                relationship = usage.relationship,
                origin = "toolchain",
                applies_to = usage.applies_to,
                toolchain_type = toolchain_sbom.toolchain_type,
                toolchain_label = toolchain_sbom.toolchain_label,
                notes = usage.notes,
            ))

    return nodes, relationships

def _collect_from_children(ctx, traces):
    transitive_nodes = []
    transitive_relationships = []

    attrs = [attr for attr in dir(ctx.rule.attr)]
    for name in attrs:
        if not should_traverse(ctx, name):
            continue

        attr_value = getattr(ctx.rule.attr, name)
        if type(attr_value) != type([]):
            attr_value = [attr_value]

        for dep in attr_value:
            if type(dep) != "Target":
                continue
            if TransitiveSbomInfo not in dep:
                continue

            info = dep[TransitiveSbomInfo]
            if hasattr(info, "traces") and getattr(info, "traces"):
                for trace in info.traces:
                    traces.append("(" + ", ".join([str(ctx.label), ctx.rule.kind, name]) + ") -> " + trace)
            if info != null_transitive_sbom_info:
                transitive_nodes.append(info.nodes)
                transitive_relationships.append(info.relationships)

    return transitive_nodes, transitive_relationships

def _gather_sbom_info_impl(target, ctx):
    if "-exec-" in ctx.bin_dir.path:
        return [null_transitive_sbom_info, null_toolchain_sbom_info]

    direct_nodes, direct_relationships = _direct_nodes_and_relationships(target, ctx)

    traces = []
    transitive_nodes, transitive_relationships = _collect_from_children(ctx, traces)

    if hasattr(ctx.attr, "_trace"):
        if ctx.attr._trace[TraceInfo].trace and ctx.attr._trace[TraceInfo].trace in str(ctx.label):
            traces = [ctx.attr._trace[TraceInfo].trace]

    if len(traces) > 10:
        traces = traces[0:10]

    if not direct_nodes and not direct_relationships and not transitive_nodes and not transitive_relationships:
        if PackageMetadataToolchainSbomInfo in target:
            raw_toolchain_sbom = target[PackageMetadataToolchainSbomInfo]
            return [
                null_transitive_sbom_info,
                ToolchainSbomInfo(
                    toolchain_type = raw_toolchain_sbom.toolchain_type,
                    toolchain_label = raw_toolchain_sbom.toolchain_label,
                    usages = raw_toolchain_sbom.usages,
                ),
            ]
        return [null_transitive_sbom_info, null_toolchain_sbom_info]

    providers = [TransitiveSbomInfo(
        nodes = depset(direct = direct_nodes, transitive = transitive_nodes),
        relationships = depset(direct = direct_relationships, transitive = transitive_relationships),
        top_level_target = target.label,
        traces = traces,
    )]

    if PackageMetadataToolchainSbomInfo in target:
        raw_toolchain_sbom = target[PackageMetadataToolchainSbomInfo]
        providers.append(ToolchainSbomInfo(
            toolchain_type = raw_toolchain_sbom.toolchain_type,
            toolchain_label = raw_toolchain_sbom.toolchain_label,
            usages = raw_toolchain_sbom.usages,
        ))
    else:
        providers.append(null_toolchain_sbom_info)

    return providers

gather_sbom_info = aspect(
    doc = "Collects SBOM graph nodes and relationships, including toolchain usages.",
    implementation = _gather_sbom_info_impl,
    attr_aspects = ["*"],
    toolchains_aspects = TOOLCHAINS,
    attrs = {
        "_trace": attr.label(default = "@supply_chain_tools//gather_metadata:trace_target"),
    },
    provides = [TransitiveSbomInfo, ToolchainSbomInfo],
    apply_to_generating_rules = False,
)
