"""Test that compares the JSON emitted by a `license` target with a golden file."""

def _license_json_test_impl(ctx):
    actual = ctx.attr.license[DefaultInfo].files.to_list()
    if len(actual) != 1:
        fail("expected exactly one output file from {}".format(ctx.attr.license.label))

    script = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(
        output = script,
        content = """#!/bin/sh
set -eu
if ! diff -u "{expected}" "{actual}"; then
  echo "license JSON does not match the golden file" >&2
  exit 1
fi
""".format(expected = ctx.file.expected.short_path, actual = actual[0].short_path),
        is_executable = True,
    )
    return [DefaultInfo(
        executable = script,
        runfiles = ctx.runfiles(files = [ctx.file.expected] + actual),
    )]

license_json_test = rule(
    implementation = _license_json_test_impl,
    attrs = {
        "expected": attr.label(allow_single_file = True, mandatory = True),
        "license": attr.label(mandatory = True),
    },
    test = True,
)
