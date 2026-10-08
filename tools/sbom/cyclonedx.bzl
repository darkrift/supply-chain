load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("providers.bzl", "SbomInfo")

def _cyclonedx_impl(ctx):
    out_path = ctx.attr.out.name if ctx.attr.out != None else "%s.json" % ctx.attr.name
    out = ctx.actions.declare_file(out_path)

    extra_inputs = []
    extra_args = []
    if ctx.attr.format == "json" and ctx.attr._strict_validations[BuildSettingInfo].value:
        extra_inputs = [ctx.file._cdx_schema] + ctx.files._cdx_schema_aux
        extra_args = [
            "--strict",
            "--schema",
            ctx.file._cdx_schema.path,
        ] + [arg for f in ctx.files._cdx_schema_aux for arg in ("--aux_schema", f.path)]

    inputs = depset(
        extra_inputs,
        transitive = [
            ctx.attr._cyclonedx[DefaultInfo].data_runfiles.files,
            ctx.attr.sbom[DefaultInfo].files,
        ],
    )
    ctx.actions.run(
        outputs = [out],
        inputs = inputs,
        executable = ctx.attr._cyclonedx[DefaultInfo].files_to_run,
        arguments = [
            "--graph",
            ctx.attr.sbom[SbomInfo].graph.path,
            "--classifications",
            ctx.attr.sbom[SbomInfo].classifications.path,
            "--out",
            out.path,
            "--format",
            ctx.attr.format,
        ] + extra_args,
    )

    return [
        DefaultInfo(files = depset([out])),
    ]

cyclonedx = rule(
    _cyclonedx_impl,
    attrs = {
        "sbom": attr.label(doc = "The sbom target to generate the CycloneDX SBOM from."),
        "format": attr.string(default = "json", values = ["json", "xml"], doc = "The output format for the CycloneDX SBOM."),
        "out": attr.output(doc = "The output file for the CycloneDX SBOM."),
        "_cyclonedx": attr.label(default = "@supply-chain-go//cmd/cyclonedx", doc = "The cyclonedx tool to use.", executable = True, cfg = "exec"),
        "_cdx_schema": attr.label(
            default = "//sbom/schemas/cyclonedx:bom-1.6.schema.json",
            allow_single_file = True,
            doc = "The vendored root CycloneDX JSON Schema.",
        ),
        "_cdx_schema_aux": attr.label_list(
            default = [
                "//sbom/schemas/cyclonedx:spdx.schema.json",
                "//sbom/schemas/cyclonedx:jsf-0.82.schema.json",
            ],
            allow_files = True,
            doc = "Vendored schemas referenced by _cdx_schema via \"$ref\".",
        ),
        "_strict_validations": attr.label(
            default = "//sbom:strict_validations",
            doc = "Whether to pass --strict to the generator for JSON schema validation. See //sbom:strict_validations.",
        ),
    },
)
