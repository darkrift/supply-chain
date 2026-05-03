"""Normalization for Composer PURLs."""

visibility([
    "//purl/private/normalization/...",
])

def normalize_composer(*, type, namespace, name, version, qualifiers, subpath):
    return struct(
        namespace = [segment.lower() for segment in namespace] if namespace else namespace,
        name = name.lower(),
        version = version,
        qualifiers = qualifiers,
        subpath = subpath,
    )

