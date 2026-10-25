"""Exposes the concluded licenses manifest of an `sbom` target."""

def _manifest_impl(ctx):
    files = [f for f in ctx.attr.sbom[DefaultInfo].files.to_list() if f.basename.endswith(".concluded-licenses.json")]
    if len(files) != 1:
        fail("expected one concluded licenses manifest, got {}".format(files))
    return [DefaultInfo(files = depset(files))]

concluded_licenses_manifest = rule(
    _manifest_impl,
    attrs = {"sbom": attr.label(mandatory = True)},
)
