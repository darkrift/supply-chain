"""Normalization for PyPI PURLs."""

visibility([
    "//purl/private/normalization/...",
])

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

def normalize_pypi(*, type, namespace, name, version, qualifiers, subpath):
    return struct(
        namespace = namespace,
        name = _normalize_pypi_name(name),
        version = version,
        qualifiers = qualifiers,
        subpath = subpath,
    )

