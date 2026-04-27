load(
    ":gather_sbom.bzl",
    "gather_sbom_info",
)
load(
    ":providers.bzl",
    "SbomInfo",
    "TransitiveSbomInfo",
)

def _sbom_impl(ctx):
    transitive_sbom_info = ctx.attr.target[TransitiveSbomInfo]
    transitive_inputs = []
    config = {
        "subject": {
            "label": str(ctx.attr.target.label),
        },
        "nodes": [],
        "relationships": [],
    }
    seen_metadata = {}
    node_ids = {}

    for node in transitive_sbom_info.nodes.to_list():
        metadata = node.metadata
        path = metadata.metadata.path
        if path in seen_metadata:
            continue
        seen_metadata[path] = True
        node_id = path
        node_ids[path] = node_id
        config["nodes"].append({
            "id": node_id,
            "label": str(node.target),
            "metadata": path,
        })
        transitive_inputs.append(metadata.files)

    for relationship in transitive_sbom_info.relationships.to_list():
        path = relationship.to_metadata.metadata.path
        if path not in node_ids:
            node_ids[path] = path
            config["nodes"].append({
                "id": path,
                "label": str(relationship.to_metadata.metadata.owner),
                "metadata": path,
            })
            transitive_inputs.append(relationship.to_metadata.files)
        config["relationships"].append({
            "from": str(relationship.from_target),
            "to": node_ids[path],
            "relationship": relationship.relationship,
            "origin": relationship.origin,
            "applies_to": relationship.applies_to,
            "toolchain_type": str(relationship.toolchain_type) if relationship.toolchain_type else "",
            "toolchain_label": str(relationship.toolchain_label) if relationship.toolchain_label else "",
            "notes": relationship.notes,
        })

    sbom_gen_config = ctx.actions.declare_file("{name}.sbom.config.json".format(name = ctx.attr.name))
    ctx.actions.write(sbom_gen_config, json.encode(config))

    return [
        DefaultInfo(files = depset(
            [sbom_gen_config],
            transitive = transitive_inputs,
        )),
        SbomInfo(config = sbom_gen_config),
    ]

def sbom_rule(gathering_aspect):
    return rule(
        _sbom_impl,
        attrs = {
            "target": attr.label(aspects = [gathering_aspect], doc = "The target for which to generate an SBOM."),
        },
    )

sbom = sbom_rule(gathering_aspect = gather_sbom_info)
