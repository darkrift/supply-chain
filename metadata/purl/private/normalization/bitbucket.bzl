"""Normalization for Bitbucket PURLs."""

visibility([
    "//purl/private/normalization/...",
])

def normalize_bitbucket(*, type, namespace, name, version, qualifiers, subpath):
    return struct(
        type = type,
        namespace = [segment.lower() for segment in namespace] if namespace else namespace,
        name = name.lower(),
        version = version,
        qualifiers = qualifiers,
        subpath = subpath,
    )

