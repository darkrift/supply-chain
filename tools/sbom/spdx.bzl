load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("providers.bzl", "SbomInfo")

def _spdx_impl(ctx):
    out_path = (
        ctx.attr.out.name if ctx.attr.out != None else "%s.txt" % ctx.attr.name if ctx.attr.format == "tag-value" else "%s.json" % ctx.attr.name if ctx.attr.format == "json" else "%s.yaml" % ctx.attr.name
    )

    out = ctx.actions.declare_file(out_path)
    unstamped_out = ctx.actions.declare_file("%s.unstamped.%s" % (ctx.attr.name, "txt" if ctx.attr.format == "tag-value" else ctx.attr.format))

    generator_inputs = []
    generator_args = [
        "--build_version",
        "dev",
    ]
    stamp_inputs = [unstamped_out]
    stamp_args = []
    stamp_tools = []
    if ctx.version_file:
        stamp_inputs.append(ctx.version_file)
        stamp_args.extend(["--created_from_status_file", ctx.version_file.path])
    if ctx.info_file:
        stamp_inputs.append(ctx.info_file)
        stamp_args.extend(["--stable_status_file", ctx.info_file.path])
    if ctx.file.document_namespace != None:
        stamp_inputs.append(ctx.file.document_namespace)
        stamp_args.extend(["--document_namespace_file", ctx.file.document_namespace.path])
        generator_args.extend([
            "--document_namespace",
            "https://spdx.org/spdxdocs/%s-unstamped" % ctx.attr.name,
        ])

    if ctx.attr._strict_validations[BuildSettingInfo].value:
        spdx_validator = ctx.toolchains["//sbom:spdx_validator_toolchain_type"]
        stamp_args.extend(["--validator", spdx_validator.validator.path])
        stamp_tools.append(spdx_validator.files_to_run)

    inputs = depset(
        generator_inputs,
        transitive = [
            ctx.attr._spdx[DefaultInfo].data_runfiles.files,
            ctx.attr.sbom[DefaultInfo].files,
        ],
    )
    ctx.actions.run(
        outputs = [unstamped_out],
        inputs = inputs,
        executable = ctx.attr._spdx[DefaultInfo].files_to_run,
        arguments = [
            "--graph",
            ctx.attr.sbom[SbomInfo].graph.path,
            "--classifications",
            ctx.attr.sbom[SbomInfo].classifications.path,
            "--out",
            unstamped_out.path,
            "--format",
            ctx.attr.format,
        ] + generator_args,
    )

    ctx.actions.run(
        outputs = [out],
        inputs = stamp_inputs,
        tools = stamp_tools,
        executable = ctx.attr._spdxstamp[DefaultInfo].files_to_run,
        arguments = [
            "--in",
            unstamped_out.path,
            "--out",
            out.path,
            "--format",
            ctx.attr.format,
        ] + stamp_args,
    )

    return [
        DefaultInfo(files = depset([out])),
    ]

spdx = rule(
    _spdx_impl,
    attrs = {
        "sbom": attr.label(doc = "The sbom target to generate the SPDX SBOM from."),
        "document_namespace": attr.label(
            allow_single_file = True,
            doc = "Optional file target whose content is used as the SPDX document namespace. If unset, a deterministic namespace is derived from the document subject.",
        ),
        "format": attr.string(default = "json", values = ["json", "yaml", "tag-value"], doc = "The output format for the SPDX SBOM."),
        "out": attr.output(doc = "The output file for the SPDX SBOM."),
        "_spdx": attr.label(default = "@supply-chain-go//cmd/spdx", doc = "The spdx tool to use.", executable = True, cfg = "exec"),
        "_spdxstamp": attr.label(default = "@supply-chain-go//cmd/spdxstamp", doc = "The spdx stamping tool to use.", executable = True, cfg = "exec"),
        "_strict_validations": attr.label(
            default = "//sbom:strict_validations",
            doc = "Whether to validate generated reports with upstream SPDX tools-java. See //sbom:strict_validations.",
        ),
    },
    toolchains = ["//sbom:spdx_validator_toolchain_type"],
)
