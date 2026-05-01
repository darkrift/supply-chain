"""HTTP repository rules that add package metadata for downloaded artifacts."""

load("@package_metadata//purl:purl.bzl", "purl")

COMMON_QUALIFIERS = [
    "checksum",
    "download_url",
    "file_name",
    "repository_url",
    "vcs_url",
    "vers",
]

def _replace_tokens(value, *, name, version, checksum):
    if value == None:
        return None
    return (value
            .replace("{name}", name)
            .replace("{version}", version)
            .replace("{checksum}", checksum))

def _first_url(urls):
    return urls[0] if urls else None

def _basename(path):
    normalized = path.split("?")[0].split("#")[0]
    parts = [part for part in normalized.split("/") if part]
    return parts[-1] if parts else None

def _checksum_qualifier(checksum):
    if not checksum:
        return None
    if ":" in checksum:
        return checksum
    return "sha256:{}".format(checksum)

def _download_sha256(checksum):
    if not checksum:
        return ""
    if checksum.startswith("sha256:"):
        return checksum[len("sha256:"):]
    if ":" in checksum:
        fail("Only raw SHA-256 or sha256:<hex> checksums are supported for Bazel downloads")
    return checksum

def _merge_qualifiers(base, added):
    qualifiers = dict(base or {})
    for key, value in added.items():
        if value != None and value != "":
            qualifiers[key] = value
    return qualifiers if qualifiers else None

def _common_qualifiers(
        *,
        checksum,
        download_url,
        file_name,
        repository_url,
        vcs_url,
        vers):
    return {
        "checksum": _checksum_qualifier(checksum),
        "download_url": download_url,
        "file_name": file_name,
        "repository_url": repository_url,
        "vcs_url": vcs_url,
        "vers": vers,
    }

def _archive_attrs():
    attrs = dict(_COMMON_ATTRS)
    attrs.update({
        "build_file_content": attr.string(
            doc = "BUILD file content for the extracted repository. The package_metadata target is appended.",
        ),
        "strip_prefix": attr.string(
            doc = "Directory prefix to strip after extraction, matching native http_archive.",
        ),
        "type": attr.string(
            doc = "Archive type override, matching native http_archive.",
        ),
    })
    return attrs

def _file_attrs():
    attrs = dict(_COMMON_ATTRS)
    attrs.update({
        "downloaded_file_path": attr.string(
            doc = "Output file path inside the generated repository.",
        ),
        "executable": attr.bool(
            default = False,
            doc = "Whether the downloaded file should be executable.",
        ),
    })
    return attrs

def _build_purl_from_parts(parts):
    builder = purl.builder().type(parts["type"]).name(parts["name"])
    if parts.get("namespace"):
        builder = builder.namespace(parts["namespace"])
    if parts.get("version"):
        builder = builder.version(parts["version"])
    for key, value in sorted((parts.get("qualifiers") or {}).items()):
        builder = builder.add_qualifier(key, value)
    if parts.get("subpath"):
        builder = builder.subpath(parts["subpath"])
    return builder.build()

def build_metadata_purl(
        *,
        name,
        version,
        checksum,
        purl_pattern,
        download_url = None,
        file_name = None,
        repository_url = None,
        vcs_url = None,
        vers = None,
        qualifiers = {}):
    """Builds a canonical PURL with common qualifiers added.

    Qualifiers follow https://github.com/package-url/purl-spec/blob/main/docs/common-qualifiers.md.
    """

    rendered_purl = _replace_tokens(
        purl_pattern,
        name = name,
        version = version,
        checksum = checksum,
    )
    parsed, err = purl.parse(rendered_purl)
    if err:
        fail("Invalid purl_pattern after expansion: {}".format(err))

    if parsed.get("version") and vers:
        fail("The 'vers' qualifier is mutually exclusive with the PURL version component")

    added_qualifiers = _common_qualifiers(
        checksum = checksum,
        download_url = download_url,
        file_name = file_name,
        repository_url = repository_url,
        vcs_url = vcs_url,
        vers = vers,
    )
    added_qualifiers.update(qualifiers)
    parsed["qualifiers"] = _merge_qualifiers(parsed.get("qualifiers"), added_qualifiers)

    return _build_purl_from_parts(parsed)

def _urls(ctx):
    if ctx.attr.urls:
        return [
            _replace_tokens(url, name = ctx.name, version = ctx.attr.version, checksum = ctx.attr.checksum)
            for url in ctx.attr.urls
        ]
    if ctx.attr.path_pattern:
        return [
            _replace_tokens(ctx.attr.path_pattern, name = ctx.name, version = ctx.attr.version, checksum = ctx.attr.checksum),
        ]
    fail("One of 'urls' or 'path_pattern' must be provided")

def _metadata_purl(ctx, urls, output_name = None):
    download_url = _replace_tokens(
        ctx.attr.download_url,
        name = ctx.name,
        version = ctx.attr.version,
        checksum = ctx.attr.checksum,
    ) if ctx.attr.download_url else _first_url(urls)
    file_name = _replace_tokens(
        ctx.attr.file_name,
        name = ctx.name,
        version = ctx.attr.version,
        checksum = ctx.attr.checksum,
    ) if ctx.attr.file_name else output_name or _basename(download_url)
    return build_metadata_purl(
        name = ctx.name,
        version = ctx.attr.version,
        checksum = ctx.attr.checksum,
        purl_pattern = ctx.attr.purl_pattern,
        download_url = download_url,
        file_name = file_name,
        repository_url = _replace_tokens(ctx.attr.repository_url, name = ctx.name, version = ctx.attr.version, checksum = ctx.attr.checksum),
        vcs_url = _replace_tokens(ctx.attr.vcs_url, name = ctx.name, version = ctx.attr.version, checksum = ctx.attr.checksum),
        vers = _replace_tokens(ctx.attr.vers, name = ctx.name, version = ctx.attr.version, checksum = ctx.attr.checksum),
        qualifiers = ctx.attr.qualifiers,
    )

def _metadata_load_fragment():
    return """
load("@package_metadata//rules:package_metadata.bzl", "package_metadata")
""".strip()

def _metadata_rule_fragment(metadata_purl):
    return """
package_metadata(
    name = "package_metadata",
    purl = {purl},
    visibility = ["//visibility:public"],
)
""".format(purl = repr(metadata_purl)).strip() + "\n"

def _metadata_repo_file_content():
    return """repo(default_package_metadata = ["//:package_metadata"])
"""

def build_file_with_package_metadata(metadata_purl, build_file_content = None):
    metadata_load = _metadata_load_fragment()
    metadata_rule = _metadata_rule_fragment(metadata_purl)
    if build_file_content:
        return metadata_load + "\n\n" + build_file_content + "\n\n" + metadata_rule
    return metadata_load + "\n\n" + metadata_rule + """
filegroup(
    name = "all_files",
    srcs = glob(["**/*"]),
    visibility = ["//visibility:public"],
)
"""

def repo_file_with_package_metadata():
    return _metadata_repo_file_content()

def _http_archive_impl(ctx):
    urls = _urls(ctx)
    ctx.download_and_extract(
        url = urls,
        sha256 = _download_sha256(ctx.attr.checksum),
        stripPrefix = ctx.attr.strip_prefix,
        type = ctx.attr.type,
    )
    metadata_purl = _metadata_purl(ctx, urls)
    ctx.file("BUILD.bazel", build_file_with_package_metadata(metadata_purl, ctx.attr.build_file_content))
    ctx.file("REPO.bazel", repo_file_with_package_metadata())

def _http_file_impl(ctx):
    urls = _urls(ctx)
    downloaded_file_path = ctx.attr.downloaded_file_path or _basename(_first_url(urls)) or ctx.name
    ctx.download(
        url = urls,
        output = downloaded_file_path,
        sha256 = _download_sha256(ctx.attr.checksum),
        executable = ctx.attr.executable,
    )
    metadata_purl = _metadata_purl(ctx, urls, output_name = downloaded_file_path)
    ctx.file("BUILD.bazel", build_file_with_package_metadata(metadata_purl, """
exports_files(
    [{downloaded_file_path}],
    visibility = ["//visibility:public"],
)

filegroup(
    name = "file",
    srcs = [{downloaded_file_path}],
    visibility = ["//visibility:public"],
)
""".format(downloaded_file_path = repr(downloaded_file_path))))
    ctx.file("REPO.bazel", repo_file_with_package_metadata())

_COMMON_ATTRS = {
    "checksum": attr.string(
        mandatory = True,
        doc = "The artifact SHA-256 checksum as raw hex or sha256:<hex>. It is also added to the PURL as the checksum common qualifier.",
    ),
    "download_url": attr.string(
        doc = "Optional direct package download URL qualifier. Defaults to the first resolved download URL.",
    ),
    "file_name": attr.string(
        doc = "Optional file_name qualifier. Defaults to the downloaded file name when it can be derived.",
    ),
    "path_pattern": attr.string(
        doc = "Download URL pattern. Supports {name}, {version}, and {checksum}.",
    ),
    "purl_pattern": attr.string(
        mandatory = True,
        doc = "PURL pattern. Supports {name}, {version}, and {checksum}. Common qualifiers are merged after parsing.",
    ),
    "qualifiers": attr.string_dict(
        doc = "Additional PURL qualifiers to merge into the parsed PURL.",
    ),
    "repository_url": attr.string(
        doc = "Optional repository_url common qualifier.",
    ),
    "urls": attr.string_list(
        doc = "Download URL patterns. Supports {name}, {version}, and {checksum}. Takes precedence over path_pattern.",
    ),
    "vcs_url": attr.string(
        doc = "Optional vcs_url common qualifier.",
    ),
    "vers": attr.string(
        doc = "Optional vers common qualifier. Mutually exclusive with the PURL version component.",
    ),
    "version": attr.string(
        mandatory = True,
        doc = "Version used to expand path_pattern, urls, and purl_pattern.",
    ),
}

enhanced_http_archive = repository_rule(
    implementation = _http_archive_impl,
    attrs = _archive_attrs(),
    doc = "Downloads and extracts an archive, then adds a package_metadata target for SBOM generation.",
)

enhanced_http_file = repository_rule(
    implementation = _http_file_impl,
    attrs = _file_attrs(),
    doc = "Downloads a file, then adds a package_metadata target for SBOM generation.",
)
