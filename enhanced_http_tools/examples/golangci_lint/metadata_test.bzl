"""Execution test for the golangci-lint enhanced HTTP example."""

def _metadata_test_impl(ctx):
    checks = []
    for platform, checksum in sorted(ctx.attr.expected.items()):
        archive = "golangci-lint-1.55.2-{}.tar.gz".format(platform)
        checks.append("""
grep -R -q '"purl":"pkg:github/golangci/golangci-lint@1.55.2?' "${{metadata_dir}}" || {{
  echo "Missing golangci-lint package PURL" >&2
  exit 1
}}
grep -R -q 'checksum=sha256:{checksum}' "${{metadata_dir}}" || {{
  echo "Missing checksum qualifier for {platform}" >&2
  exit 1
}}
grep -R -q 'file_name={archive}' "${{metadata_dir}}" || {{
  echo "Missing file_name qualifier for {platform}" >&2
  exit 1
}}
""".format(
            archive = archive,
            checksum = checksum,
            platform = platform,
        ))

    script = ctx.actions.declare_file(ctx.attr.name + ".sh")
    metadata_paths = []
    for f in ctx.files.metadata:
        short_path = f.short_path
        if short_path.startswith("../"):
            short_path = short_path[3:]
        metadata_paths.append(short_path)
    ctx.actions.write(
        output = script,
        content = """#!/usr/bin/env bash
set -euo pipefail

metadata_dir="${{TEST_TMPDIR}}/metadata"
mkdir -p "${{metadata_dir}}"

{copy_metadata}

{checks}
""".format(
            checks = "\n".join(checks),
            copy_metadata = "\n".join([
                "cp \"${{TEST_SRCDIR}}/{}\" \"${{metadata_dir}}/metadata_{}.json\"".format(metadata_paths[i], i)
                for i in range(len(metadata_paths))
            ]),
        ),
        is_executable = True,
    )

    return [
        DefaultInfo(
            executable = script,
            files = depset([script]),
            runfiles = ctx.runfiles(files = ctx.files.metadata + ctx.files.artifacts),
        ),
    ]

golangci_lint_metadata_test = rule(
    implementation = _metadata_test_impl,
    attrs = {
        "artifacts": attr.label_list(allow_files = True),
        "expected": attr.string_dict(mandatory = True),
        "metadata": attr.label_list(allow_files = True, mandatory = True),
    },
    test = True,
)
