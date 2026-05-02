"""Tests for enhanced HTTP helper functions."""

load(
    "//private:http.bzl",
    "build_file_with_package_metadata",
    "build_http_file_file_package",
    "build_http_file_root_package",
    "build_metadata_purl",
    "repo_file_with_package_metadata",
)

def _test_impl(ctx):
    failures = []

    actual = build_metadata_purl(
        name = "zlib",
        version = "1.3.1",
        purl_pattern = "pkg:generic/zlib@{version}?repository_url=https://zlib.net",
        sha256 = "38ef96b8d0a7d57784f7f444b587d7c4f9c931b6d4f3f3d8e8f4b4e4adf3f8b8",
        download_url = "https://zlib.net/zlib-1.3.1.tar.gz",
        file_name = "zlib-1.3.1.tar.gz",
        vcs_url = "git+https://github.com/madler/zlib.git",
    )
    expected = "pkg:generic/zlib@1.3.1?checksum=sha256:38ef96b8d0a7d57784f7f444b587d7c4f9c931b6d4f3f3d8e8f4b4e4adf3f8b8&download_url=https:%2F%2Fzlib.net%2Fzlib-1.3.1.tar.gz&file_name=zlib-1.3.1.tar.gz&repository_url=https:%2F%2Fzlib.net&vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fmadler%2Fzlib.git"
    if actual != expected:
        failures.append("expected {}, got {}".format(expected, actual))

    actual = build_metadata_purl(
        name = "requests",
        version = "",
        sha256 = "0123456789abcdef",
        purl_pattern = "pkg:pypi/requests",
        vers = "vers:pypi/>=2.0.0|<3.0.0",
    )
    expected = "pkg:pypi/requests?checksum=sha256:0123456789abcdef&vers=vers:pypi%2F%3E%3D2.0.0%7C%3C3.0.0"
    if actual != expected:
        failures.append("expected {}, got {}".format(expected, actual))

    actual = build_metadata_purl(
        name = "tool",
        version = "2.1.0",
        purl_pattern = "pkg:github/{owner}/{repo}@{version}",
        sha256 = "abcdef",
        substitutions = {
            "{owner}": "example",
            "{repo}": "tool",
        },
    )
    expected = "pkg:github/example/tool@2.1.0?checksum=sha256:abcdef"
    if actual != expected:
        failures.append("expected {}, got {}".format(expected, actual))

    actual = build_metadata_purl(
        name = "empty",
        version = "0",
        integrity = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
        purl_pattern = "pkg:generic/empty@{version}",
    )
    expected = "pkg:generic/empty@0?checksum=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if actual != expected:
        failures.append("expected {}, got {}".format(expected, actual))

    repo_file = repo_file_with_package_metadata()
    expected_repo_file = """repo(default_package_metadata = ["//:package_metadata"])
"""
    if repo_file != expected_repo_file:
        failures.append("expected REPO.bazel {}, got {}".format(expected_repo_file, repo_file))

    build_file = build_file_with_package_metadata(
        "pkg:generic/zlib@1.3.1",
        """load("//tools:defs.bzl", "tool")

tool(name = "tool")""",
    )
    expected_build_file = """load("@package_metadata//rules:package_metadata.bzl", "package_metadata")

load("//tools:defs.bzl", "tool")

tool(name = "tool")

package_metadata(
    name = "package_metadata",
    purl = "pkg:generic/zlib@1.3.1",
    visibility = ["//visibility:public"],
)
"""
    if build_file != expected_build_file:
        failures.append("expected BUILD.bazel {}, got {}".format(expected_build_file, build_file))

    file_package = build_http_file_file_package("bin/tool")
    expected_file_package = """package(default_visibility = ["//visibility:public"])

filegroup(
    name = "file",
    srcs = ["bin/tool"],
)
"""
    if file_package != expected_file_package:
        failures.append("expected file/BUILD {}, got {}".format(expected_file_package, file_package))

    root_package = build_http_file_root_package("pkg:github/example/tool@1.0.0", "tool")
    expected_root_package = """load("@package_metadata//rules:package_metadata.bzl", "package_metadata")

package(default_visibility = ["//visibility:public"])

package_metadata(
    name = "package_metadata",
    purl = "pkg:github/example/tool@1.0.0",
    visibility = ["//visibility:public"],
)

alias(
    name = "file",
    actual = "//file",
)
alias(
    name = "tool",
    actual = "//file:tool",
)
"""
    if root_package != expected_root_package:
        failures.append("expected root BUILD.bazel {}, got {}".format(expected_root_package, root_package))

    script = ctx.actions.declare_file(ctx.attr.name + ".sh")
    ctx.actions.write(
        output = script,
        content = "#!/usr/bin/env bash\n{body}\n".format(
            body = "exit 0" if not failures else "echo '{}' && exit 1".format(json.encode(failures)),
        ),
        is_executable = True,
    )
    return [DefaultInfo(executable = script, files = depset([script]))]

http_test = rule(
    implementation = _test_impl,
    test = True,
)
