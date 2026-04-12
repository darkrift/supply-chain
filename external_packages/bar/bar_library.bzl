def _bar_library_impl(ctx):
    pass

bar_library = rule(
    implementation = _bar_library_impl,
    attrs = {
        "deps": attr.label_list(
            doc = "Dependencies of this library.",
        ),
    },
    toolchains = ["@bar//toolchains:toolchain_type"],
)
