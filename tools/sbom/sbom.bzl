load("@package_metadata//:defs.bzl", "PackageAttributeInfo")
load("providers.bzl", "SbomInfo")
load(
    "@supply_chain_tools//gather_metadata:gather_metadata.bzl",
    "gather_metadata_info",
)
load(
    "@supply_chain_tools//gather_metadata:serialization.bzl",
    "metadata_info_to_json",
)
load(
    "@supply_chain_tools//gather_metadata:providers.bzl",
    "TransitiveMetadataInfo",
)

# The `kind` of the attributes written by `@package_metadata//licenses/rules:license.bzl`.
_LICENSE_KIND = "build.bazel.attribute.license"

def _concluded_licenses_manifest(ctx):
    """Writes the concluded licenses manifest; returns it with the files it refers to."""
    if not ctx.attr.concluded_licenses and not ctx.attr.require_resolved_choices and not ctx.attr.require_matched_concluded_licenses:
        return None, []

    licenses = {}
    files = []
    for purl, target in ctx.attr.concluded_licenses.items():
        if not purl.startswith("pkg:") or "#" in purl:
            fail("'{}' in `concluded_licenses` is not a valid key: expected a PURL without subpath, such as 'pkg:maven/org.acme/lib@1.0.0'".format(purl))
        info = target[PackageAttributeInfo]
        if info.kind != _LICENSE_KIND:
            fail("'{}' in `concluded_licenses` must be a `license` target, got an attribute of kind '{}'".format(target.label, info.kind))
        licenses[purl] = info.attributes.path
        files.append(info.files)

    manifest = ctx.actions.declare_file("{name}.concluded-licenses.json".format(name = ctx.attr.name))
    ctx.actions.write(manifest, json.encode({
        "licenses": licenses,
        "require_resolved_choices": ctx.attr.require_resolved_choices,
        "require_matched_concluded_licenses": ctx.attr.require_matched_concluded_licenses,
    }))
    return manifest, files

def _sbom_impl(ctx):
    transitive_metadata_info = ctx.attr.target[TransitiveMetadataInfo]

    # Get graph-only format from gather_metadata
    json_strings = metadata_info_to_json(transitive_metadata_info)
    graph_json_content = json_strings[0] if json_strings else "{}"

    # Write graph JSON
    graph_json = ctx.actions.declare_file("{name}.graph.json".format(name=ctx.attr.name))
    ctx.actions.write(graph_json, graph_json_content)

    concluded_licenses, concluded_files = _concluded_licenses_manifest(ctx)

    # Collect all metadata files as transitive inputs
    transitive_inputs = []
    for transitive_metadata in transitive_metadata_info.transitive.to_list():
        for m in transitive_metadata.metadata.to_list():
            if hasattr(m, "files"):
                transitive_inputs.append(m.files)

    # Run cmd/sbom action to compute classifications. Concluded licenses are
    # applied here, so the report generators only see the resolved licenses.
    classifications_json = ctx.actions.declare_file("{name}.sbom-classifications.json".format(name=ctx.attr.name))

    args = [
        "--input",
        graph_json.path,
        "--output",
        classifications_json.path,
    ]

    if not ctx.attr.require_root_metadata:
        args.append("--allow_missing_root_metadata")

    if concluded_licenses:
        args += ["--concluded-licenses", concluded_licenses.path]

    ctx.actions.run(
        outputs = [classifications_json],
        inputs = depset(
            [graph_json] + ([concluded_licenses] if concluded_licenses else []),
            transitive = transitive_inputs + concluded_files,
        ),
        executable = ctx.attr._sbom_cmd[DefaultInfo].files_to_run,
        arguments = args,
        mnemonic = "SbomClassify",
    )

    return [
        DefaultInfo(files = depset(
            [graph_json, classifications_json] + ([concluded_licenses] if concluded_licenses else []),
            transitive = transitive_inputs + concluded_files,
        )),
        SbomInfo(
            graph = graph_json,
            classifications = classifications_json,
        ),
    ]

def sbom_rule(gathering_aspect):
    return rule(
        _sbom_impl,
        attrs = {
            "target": attr.label(aspects = [gathering_aspect], doc = "The target for which to generate an SBOM."),
            "require_root_metadata": attr.bool(
                default = True,
                doc = "If True, fail if the root target has no package metadata. If False, generate an SBOM without a root component.",
            ),
            "concluded_licenses": attr.string_keyed_label_dict(
                providers = [PackageAttributeInfo],
                doc = """Overrides the license of packages in the reports with the license concluded for them.

The keys are PURLs and the values are `license` targets. Package metadata PURLs identify a
package uniquely (version, commit, etc.), so a key that leaves a component out matches every
package that has any value for it.

How a key matches a package:

* `type`, `namespace` and `name` must be equal. Leaving out the namespace does not match
  any namespace: `pkg:npm/lib` and `pkg:npm/@scope/lib` are different packages.
* `version` is optional. `pkg:maven/org.acme/lib@1.0` matches only that version,
  `pkg:maven/org.acme/lib` matches all of its versions.
* `qualifiers` are optional. Each qualifier of the key must be present with the same value on the
  package, which may have more: `pkg:deb/debian/lib@1?arch=amd64` matches the amd64 package
  whatever its other qualifiers, `pkg:deb/debian/lib@1` matches all architectures.
* `subpath` is not allowed in keys.

When several keys match a package, the most specific one wins: a key with a version beats
one without, then the one with the most qualifiers. Keys that match with the same specificity
(e.g., `pkg:deb/debian/lib?arch=amd64` and `pkg:deb/debian/lib?distro=bookworm`) fail the build.
Qualifiers can be written in any order, and the same key cannot be given twice.

Take care with keys that leave out the version: they conclude the license of versions that
may not have been reviewed. Prefer exact versions, and use `require_matched_concluded_licenses`
to detect keys that no longer match.

The declared license of the package is kept as is: SPDX reports it as the declared
license and the override as the concluded license, and CycloneDX reports the override
as the license of the component and the declared license as evidence. Packages that are
not overridden conclude to their declared license.

Keys that do not match any package of the SBOM are ignored, so that one list can be shared
by many SBOMs. See `require_matched_concluded_licenses`.""",
            ),
            "require_matched_concluded_licenses": attr.bool(
                default = False,
                doc = "If True, fail if a key of `concluded_licenses` does not match any package of the SBOM, which catches stale or mistyped PURLs.",
            ),
            "require_resolved_choices": attr.bool(
                default = False,
                doc = "If True, fail if the concluded license of a package still offers a choice (`OR`), so that each choice must be resolved by `concluded_licenses`.",
            ),
            "_sbom_cmd": attr.label(
                default = "@supply-chain-go//cmd/sbom",
                executable = True,
                cfg = "exec",
            ),
        },
    )

sbom = sbom_rule(gathering_aspect=gather_metadata_info)
