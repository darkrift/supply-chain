load("@aspect_bazel_lib//lib:stamping.bzl", "STAMP_ATTRS", "maybe_stamp")
load("@bazel_skylib//lib:dicts.bzl", "dicts")
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("providers.bzl", "SbomInfo")

def _cyclonedx_out_path(ctx):
    return ctx.attr.out.name if ctx.attr.out != None else "%s.%s" % (ctx.attr.name, ctx.attr.format)

def _cyclonedx_validator_args(ctx):
    if not ctx.attr._strict_validations[BuildSettingInfo].value:
        return [], []

    validator = ctx.toolchains["//sbom:cyclonedx_validator_toolchain_type"]
    return [
        "--validator",
        validator.validator.path,
    ], [validator.files_to_run]

def _cyclonedx_generate_action(ctx, out, extra_inputs = [], extra_args = [], extra_tools = []):
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
        tools = extra_tools,
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

def _cyclonedx_stamp_action(ctx, src, out, extra_args, extra_inputs, extra_tools):
    ctx.actions.run(
        outputs = [out],
        inputs = [src] + extra_inputs,
        tools = extra_tools,
        executable = ctx.attr._cyclonedxstamp[DefaultInfo].files_to_run,
        arguments = [
            "--in",
            src.path,
            "--out",
            out.path,
            "--format",
            ctx.attr.format,
        ] + extra_args,
    )

def _cyclonedx_impl(ctx):
    out = ctx.actions.declare_file(_cyclonedx_out_path(ctx))
    stamp = maybe_stamp(ctx)
    validator_args, validator_tools = _cyclonedx_validator_args(ctx)

    if not stamp:
        _cyclonedx_generate_action(ctx, out, extra_args = validator_args, extra_tools = validator_tools)
        return [DefaultInfo(files = depset([out]))]

    unstamped = ctx.actions.declare_file("%s.unstamped.%s" % (ctx.attr.name, ctx.attr.format))
    _cyclonedx_generate_action(ctx, unstamped)

    stamp_inputs = []
    stamp_args = []
    stamp_inputs.append(stamp.volatile_status_file)
    stamp_args.extend(["--created_from_status_file", stamp.volatile_status_file.path])
    stamp_inputs.append(stamp.stable_status_file)
    stamp_args.extend(["--stable_status_file", stamp.stable_status_file.path])
    if ctx.file.serial_number != None:
        stamp_inputs.append(ctx.file.serial_number)
        stamp_args.extend(["--serial_number_file", ctx.file.serial_number.path])

    _cyclonedx_stamp_action(ctx, unstamped, out, stamp_args + validator_args, stamp_inputs, validator_tools)

    return [
        DefaultInfo(files = depset([out])),
    ]

cyclonedx = rule(
    _cyclonedx_impl,
    attrs = dicts.add({
        "sbom": attr.label(doc = "The sbom target to generate the CycloneDX SBOM from."),
        "serial_number": attr.label(
            allow_single_file = True,
            doc = "Optional file target whose content is used as the CycloneDX BOM serialNumber when stamping is enabled.",
        ),
        "format": attr.string(default = "json", values = ["json", "xml"], doc = "The output format for the CycloneDX SBOM."),
        "out": attr.output(doc = "The output file for the CycloneDX SBOM."),
        "_cyclonedx": attr.label(default = "@supply-chain-go//cmd/cyclonedx", doc = "The cyclonedx tool to use.", executable = True, cfg = "exec"),
        "_cyclonedxstamp": attr.label(default = "@supply-chain-go//cmd/cyclonedxstamp", doc = "The cyclonedx stamping tool to use.", executable = True, cfg = "exec"),
        "_strict_validations": attr.label(
            default = "//sbom:strict_validations",
            doc = "Whether to validate generated reports with the upstream CycloneDX CLI. See //sbom:strict_validations.",
        ),
    }, STAMP_ATTRS),
    toolchains = ["//sbom:cyclonedx_validator_toolchain_type"],
)
