def _bar_binary_impl(ctx):
    pass

bar_binary = rule(
    implementation = _bar_binary_impl,
    attrs = {
        "deps": attr.label_list(
            doc = "Dependencies of this binary.",
        ),
    },
    toolchains = ["@bar//toolchains:toolchain_type"],
)
