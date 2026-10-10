load("@aspect_bazel_lib//lib:stamping.bzl", "STAMP_ATTRS", "maybe_stamp")
load("@bazel_skylib//lib:dicts.bzl", "dicts")
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("providers.bzl", "SbomInfo")

def _spdx_out_path(ctx):
    return (
        ctx.attr.out.name if ctx.attr.out != None else "%s.txt" % ctx.attr.name if ctx.attr.format == "tag-value" else "%s.json" % ctx.attr.name if ctx.attr.format == "json" else "%s.yaml" % ctx.attr.name
    )

def _spdx_validator_args(ctx):
    if not ctx.attr._strict_validations[BuildSettingInfo].value:
        return [], []

    validator = ctx.toolchains["//sbom:spdx_validator_toolchain_type"]
    return ["--validator", validator.validator.path], [validator.files_to_run]

def _spdx_generate_action(ctx, out, extra_inputs = [], extra_args = [], extra_tools = []):
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
        tools = extra_tools,
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

def _spdx_stamp_action(ctx, src, out, extra_args, extra_inputs, extra_tools):
    ctx.actions.run(
        outputs = [out],
        inputs = [src] + extra_inputs,
        tools = extra_tools,
        executable = ctx.attr._spdxstamp[DefaultInfo].files_to_run,
        arguments = [
            "--in",
            src.path,
            "--out",
            out.path,
            "--format",
            ctx.attr.format,
        ] + extra_args,
    )

def _spdx_impl(ctx):
    out = ctx.actions.declare_file(_spdx_out_path(ctx))
    validator_args, validator_tools = _spdx_validator_args(ctx)
    stamp = maybe_stamp(ctx)

    if not stamp:
        extra_inputs = []
        extra_args = []
        if ctx.file.document_namespace != None:
            extra_inputs.append(ctx.file.document_namespace)
            extra_args.extend(["--document_namespace_file", ctx.file.document_namespace.path])

        _spdx_generate_action(ctx, out, extra_inputs = extra_inputs, extra_args = extra_args + validator_args, extra_tools = validator_tools)
        return [DefaultInfo(files = depset([out]))]

    unstamped = ctx.actions.declare_file("%s.unstamped.%s" % (ctx.attr.name, "txt" if ctx.attr.format == "tag-value" else ctx.attr.format))
    _spdx_generate_action(ctx, unstamped)

    stamp_inputs = []
    stamp_args = []
    stamp_inputs.append(stamp.volatile_status_file)
    stamp_args.extend(["--created_from_status_file", stamp.volatile_status_file.path])
    stamp_inputs.append(stamp.stable_status_file)
    stamp_args.extend(["--stable_status_file", stamp.stable_status_file.path])
    if ctx.file.document_namespace != None:
        stamp_inputs.append(ctx.file.document_namespace)
        stamp_args.extend(["--document_namespace_file", ctx.file.document_namespace.path])

    _spdx_stamp_action(ctx, unstamped, out, stamp_args + validator_args, stamp_inputs, validator_tools)

    return [
        DefaultInfo(files = depset([out])),
    ]

spdx = rule(
    _spdx_impl,
    attrs = dicts.add({
        "sbom": attr.label(doc = "The sbom target to generate the SPDX SBOM from."),
        "document_namespace": attr.label(
            allow_single_file = True,
            doc = "Optional file target whose content is used as the SPDX document namespace. With stamp = True, it is applied in the stamping action.",
        ),
        "format": attr.string(default = "json", values = ["json", "yaml", "tag-value"], doc = "The output format for the SPDX SBOM."),
        "out": attr.output(doc = "The output file for the SPDX SBOM."),
        "_spdx": attr.label(default = "@supply-chain-go//cmd/spdx", doc = "The spdx tool to use.", executable = True, cfg = "exec"),
        "_spdxstamp": attr.label(default = "@supply-chain-go//cmd/spdxstamp", doc = "The spdx stamping tool to use.", executable = True, cfg = "exec"),
        "_strict_validations": attr.label(
            default = "//sbom:strict_validations",
            doc = "Whether to validate generated reports with upstream SPDX tools-java. See //sbom:strict_validations.",
        ),
    }, STAMP_ATTRS),
    toolchains = ["//sbom:spdx_validator_toolchain_type"],
)
