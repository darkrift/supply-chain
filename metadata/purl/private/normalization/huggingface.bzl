"""Normalization for Hugging Face PURLs."""

visibility([
    "//purl/private/normalization/...",
])

def normalize_huggingface(*, type, namespace, name, version, qualifiers, subpath):
    return struct(
        namespace = namespace,
        name = name,
        version = version.lower() if version else version,
        qualifiers = qualifiers,
        subpath = subpath,
    )

