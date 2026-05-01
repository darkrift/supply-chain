"""Utils to normalize [purl](https://github.com/package-url/purl-spec)s."""

visibility([
    "//purl/private",
])

def _split_path(value):
    return [segment for segment in value.split("/") if segment] if value else None

def _normalize_pypi_name(name):
    normalized = []
    previous_separator = False
    for c in name.elems():
        is_separator = c == "." or c == "_" or c == "-"
        if is_separator:
            if not previous_separator:
                normalized.append("-")
            previous_separator = True
        else:
            normalized.append(c.lower())
            previous_separator = False
    return "".join(normalized)

def _normalize_qualifiers(qualifiers):
    if not qualifiers:
        return None

    normalized = {}
    for key, value in qualifiers.items():
        if value == None or value == "":
            continue
        normalized[key.lower()] = value

    return normalized if normalized else None

def _namespace_to_segments(namespace):
    if type(namespace) == type([]):
        return namespace
    return _split_path(namespace)

def _subpath_to_segments(subpath):
    if type(subpath) == type([]):
        return subpath
    if not subpath:
        return None

    segments = []
    for segment in subpath.split("/"):
        if segment == "" or segment == "." or segment == "..":
            continue
        segments.append(segment)
    return segments if segments else None

def normalize(
        *,
        type = None,
        namespace = None,
        name = None,
        version = None,
        qualifiers = {},
        subpath = None):
    if not type:
        return None, "Mandatory property 'type' not set"

    normalized_type = type.lower()
    normalized_qualifiers = _normalize_qualifiers(qualifiers)
    namespace_segments = _namespace_to_segments(namespace)
    subpath_segments = _subpath_to_segments(subpath)
    normalized_name = name
    normalized_version = version

    if normalized_type == "pypi":
        normalized_name = _normalize_pypi_name(name)
    elif normalized_type in ["composer", "github", "bitbucket"]:
        normalized_name = name.lower()
        if namespace_segments:
            namespace_segments = [segment.lower() for segment in namespace_segments]
    elif normalized_type == "mlflow":
        repository_url = normalized_qualifiers.get("repository_url") if normalized_qualifiers else None
        if repository_url and "databricks" in repository_url.lower():
            normalized_name = name.lower()
    elif normalized_type == "huggingface":
        if version:
            normalized_version = version.lower()

    purl = struct(
        type = normalized_type,
        namespace = namespace_segments,
        name = normalized_name,
        version = normalized_version,
        qualifiers = normalized_qualifiers,
        subpath = subpath_segments,
    )
    return purl, None
