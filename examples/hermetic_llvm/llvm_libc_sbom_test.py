import json
import os
import sys


def _read(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    test_srcdir = os.environ.get("TEST_SRCDIR")
    if test_srcdir:
        candidate = os.path.join(test_srcdir, path)
        if os.path.exists(candidate):
            with open(candidate, "r", encoding="utf-8") as f:
                return f.read()

    raise FileNotFoundError(path)


def _component_refs_by_purl(sbom):
    refs_by_purl = {}
    for component in sbom.get("components", []):
        purl = component.get("purl")
        ref = component.get("bom-ref")
        if purl and ref:
            refs_by_purl.setdefault(purl, set()).add(ref)
    return refs_by_purl


def _assert_unique_bom_refs(sbom):
    refs = [
        component.get("bom-ref")
        for component in sbom.get("components", [])
        if component.get("bom-ref")
    ]
    duplicates = sorted({ref for ref in refs if refs.count(ref) > 1})
    if duplicates:
        raise AssertionError("Expected unique component bom-ref values, found duplicates: {}".format(duplicates))


def _reachable_dependencies(sbom):
    root = sbom.get("metadata", {}).get("component", {}).get("bom-ref")
    if not root:
        raise AssertionError("SBOM has no metadata.component.bom-ref")

    dependency_map = {
        dependency.get("ref"): dependency.get("dependsOn", [])
        for dependency in sbom.get("dependencies", [])
    }
    seen = set()
    pending = list(dependency_map.get(root, []))
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        seen.add(ref)
        pending.extend(dependency_map.get(ref, []))
    return seen


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: llvm_libc_sbom_test.py <sbom.json> <expected-purl> <unexpected-purl>"
        )

    sbom_path, expected_purl, unexpected_purl = sys.argv[1:]
    sbom = json.loads(_read(sbom_path))
    _assert_unique_bom_refs(sbom)
    component_refs_by_purl = _component_refs_by_purl(sbom)
    reachable_dependencies = _reachable_dependencies(sbom)

    if expected_purl not in component_refs_by_purl:
        raise AssertionError("Expected {} in SBOM components: {}".format(expected_purl, sorted(component_refs_by_purl)))

    if not component_refs_by_purl[expected_purl].intersection(reachable_dependencies):
        raise AssertionError(
            "Expected final binary to include {} via reachable dependencies: {}".format(
                expected_purl,
                sorted(reachable_dependencies),
            )
        )

    if unexpected_purl in component_refs_by_purl:
        raise AssertionError("Did not expect {} in SBOM components: {}".format(unexpected_purl, sorted(component_refs_by_purl)))


if __name__ == "__main__":
    main()
