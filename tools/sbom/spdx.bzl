load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("providers.bzl", "SbomInfo")

def _spdx_impl(ctx):
    out_path = (
        ctx.attr.out.name if ctx.attr.out != None else
        "%s.txt" % ctx.attr.name if ctx.attr.format == "tag-value" else
        "%s.json" % ctx.attr.name if ctx.attr.format == "json" else
        "%s.yaml" % ctx.attr.name
    )

    out = ctx.actions.declare_file(out_path)

    # creationInfo.created (SPDX 2.3, mandatory) comes from Bazel's own
    # build-stamping mechanism: ctx.version_file (volatile-status.txt) holds
    # a real BUILD_TIMESTAMP only when the build is invoked with --stamp;
    # otherwise Bazel substitutes a fixed placeholder, which keeps this
    # action's output (and therefore its cache key) deterministic by
    # default. See https://bazel.build/reference/be/make-variables#stamp-flag.
    extra_inputs = []
    extra_args = []
    if ctx.version_file:
        extra_inputs.append(ctx.version_file)
        extra_args.extend(["--created_from_status_file", ctx.version_file.path])

    if ctx.attr.format == "json" and ctx.attr._strict_validations[BuildSettingInfo].value:
        extra_inputs.append(ctx.file._spdx_schema)
        extra_args.extend([
            "--strict",
            "--schema",
            ctx.file._spdx_schema.path,
        ])

    inputs = depset(
        extra_inputs,
        transitive = [
            ctx.attr._spdx[DefaultInfo].data_runfiles.files,
            ctx.attr.sbom[DefaultInfo].files,
        ],
    )
    ctx.actions.run(
        outputs = [out],
        inputs = inputs,
        executable = ctx.attr._spdx[DefaultInfo].files_to_run,
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

spdx = rule(
    _spdx_impl,
    attrs = {
        "sbom": attr.label(doc = "The sbom target to generate the SPDX SBOM from."),
        "format": attr.string(default = "json", values = ["json", "yaml", "tag-value"], doc = "The output format for the SPDX SBOM."),
        "out": attr.output(doc = "The output file for the SPDX SBOM."),
        "_spdx": attr.label(default = "@supply-chain-go//cmd/spdx", doc = "The spdx tool to use.", executable = True, cfg = "exec"),
        "_spdx_schema": attr.label(
            default = "//sbom/schemas/spdx:spdx-schema.json",
            allow_single_file = True,
            doc = "The vendored SPDX 2.3 JSON Schema.",
        ),
        "_strict_validations": attr.label(
            default = "//sbom:strict_validations",
            doc = "Whether to pass --strict to the generator for JSON schema validation. See //sbom:strict_validations.",
        ),
    },
)
