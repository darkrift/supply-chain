"""Toolchain rules for upstream SBOM validators."""

def _cyclonedx_validator_toolchain_impl(ctx):
    return [
        platform_common.ToolchainInfo(
            binary = ctx.file.binary,
            files_to_run = ctx.attr.binary[DefaultInfo].files_to_run,
        ),
    ]

cyclonedx_validator_toolchain = rule(
    implementation = _cyclonedx_validator_toolchain_impl,
    attrs = {
        "binary": attr.label(
            allow_single_file = True,
            mandatory = True,
            doc = "CycloneDX CLI executable for the exec platform.",
        ),
    },
)

def _spdx_validator_toolchain_impl(ctx):
    return [
        platform_common.ToolchainInfo(
            files_to_run = ctx.attr.validator[DefaultInfo].files_to_run,
            validator = ctx.executable.validator,
        ),
    ]

spdx_validator_toolchain = rule(
    implementation = _spdx_validator_toolchain_impl,
    attrs = {
        "validator": attr.label(
            cfg = "exec",
            executable = True,
            mandatory = True,
            doc = "Executable SPDX tools-java validator wrapper for the exec platform.",
        ),
    },
)
