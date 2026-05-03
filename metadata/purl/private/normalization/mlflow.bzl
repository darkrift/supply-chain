"""Normalization for MLflow PURLs."""

visibility([
    "//purl/private/normalization/...",
])

def normalize_mlflow(*, type, namespace, name, version, qualifiers, subpath):
    repository_url = qualifiers.get("repository_url") if qualifiers else None
    normalized_name = name
    if repository_url and "databricks" in repository_url.lower():
        normalized_name = name.lower()

    return struct(
        namespace = namespace,
        name = normalized_name,
        version = version,
        qualifiers = qualifiers,
        subpath = subpath,
    )

