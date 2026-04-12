BarcInfo = provider(
    doc = "Information about how to invoke the barc compiler.",
    fields = [],
)

def _bar_toolchain_impl(ctx):
    toolchain_info = platform_common.ToolchainInfo(
        barcinfo = BarcInfo(),
    )
    return [toolchain_info]

bar_toolchain = rule(
    implementation = _bar_toolchain_impl,
    attrs = {
    },
)

def _bar_toolchain_variable_impl(ctx):
    return [
        platform_common.TemplateVariableInfo({"FOO": "bar"}),
    ]

bar_toolchain_variable = rule(
    implementation = _bar_toolchain_variable_impl,
    attrs = {
    },
)
