"""Bzlmod extension for generated PURL type validation."""

_REQUIREMENTS = ["optional", "prohibited", "required"]
_DEFAULT_STANDARD_SOURCE_URL = "https://github.com/package-url/purl-spec/archive/refs/heads/main.tar.gz"
_DEFAULT_STRIP_PREFIX = "purl-spec-main"

def _check_object(spec, path, required, allowed):
    if type(spec) != "dict":
        fail("{} must be an object".format(path))

    for key in required:
        if key not in spec:
            fail("{} must contain {}".format(path, key))

    for key in spec.keys():
        if key not in allowed:
            fail("{} contains unsupported property {}".format(path, key))

def _check_requirement(spec, path, allowed):
    requirement = spec.get("requirement")
    if requirement not in allowed:
        fail("{} requirement must be one of {}, got {}".format(path, allowed, requirement))

def _validate_type_definition(spec, source):
    _check_object(
        spec,
        source,
        ["$id", "type", "type_name", "description", "repository", "namespace_definition", "name_definition", "examples"],
        [
            "$schema",
            "$id",
            "type",
            "type_name",
            "description",
            "repository",
            "namespace_definition",
            "name_definition",
            "version_definition",
            "qualifiers_definition",
            "subpath_definition",
            "examples",
            "note",
            "reference_urls",
        ],
    )

    _check_object(spec["repository"], source + ".repository", ["use_repository"], ["use_repository", "default_repository_url", "note"])
    _check_component_definition(spec["namespace_definition"], source + ".namespace_definition", _REQUIREMENTS)
    _check_component_definition(spec["name_definition"], source + ".name_definition", ["required"])

    if "version_definition" in spec:
        _check_component_definition(spec["version_definition"], source + ".version_definition", ["optional"])
    if "subpath_definition" in spec:
        _check_component_definition(spec["subpath_definition"], source + ".subpath_definition", ["optional"])

    if "qualifiers_definition" in spec:
        qualifiers = spec["qualifiers_definition"]
        if type(qualifiers) != "list":
            fail("{}.qualifiers_definition must be a list".format(source))
        seen = {}
        for i, qualifier in enumerate(qualifiers):
            qualifier_path = "{}.qualifiers_definition[{}]".format(source, i)
            _check_object(
                qualifier,
                qualifier_path,
                ["key", "description"],
                ["key", "requirement", "description", "default_value", "native_name"],
            )
            if qualifier["key"] in seen:
                fail("{} duplicates qualifier key {}".format(qualifier_path, qualifier["key"]))
            seen[qualifier["key"]] = True
            if "requirement" in qualifier and qualifier["requirement"] not in ["optional", "required"]:
                fail("{} requirement must be optional or required".format(qualifier_path))

def _check_component_definition(spec, path, requirements):
    _check_object(
        spec,
        path,
        ["requirement"],
        [
            "requirement",
            "permitted_characters",
            "case_sensitive",
            "normalization_rules",
            "native_name",
            "note",
        ],
    )
    _check_requirement(spec, path, requirements)

def _read_json(ctx, path):
    return json.decode(ctx.read(path))

def _component_spec(definition):
    if not definition:
        return None

    result = {
        "requirement": definition.get("requirement", "optional"),
    }
    if "permitted_characters" in definition:
        result["pattern"] = definition["permitted_characters"]
    if "case_sensitive" in definition:
        result["case_sensitive"] = definition["case_sensitive"]
    return result

def _qualifier_spec(definition):
    result = {
        "requirement": definition.get("requirement", "optional"),
    }
    if "permitted_characters" in definition:
        result["pattern"] = definition["permitted_characters"]
    if "case_sensitive" in definition:
        result["case_sensitive"] = definition["case_sensitive"]
    return result

def _runtime_spec(spec, overlays):
    spec = _apply_overlays(spec, overlays)
    qualifiers = {}
    for qualifier in spec.get("qualifiers_definition", []):
        qualifiers[qualifier["key"]] = _qualifier_spec(qualifier)

    return {
        "type": spec["type"],
        "namespace": _component_spec(spec["namespace_definition"]),
        "name": _component_spec(spec["name_definition"]),
        "version": _component_spec(spec.get("version_definition")),
        "subpath": _component_spec(spec.get("subpath_definition")),
        "qualifiers": qualifiers,
    }

def _merge_dict(value, overlay):
    result = dict(value)
    result.update(overlay)
    return result

def _apply_overlays(spec, overlays):
    result = dict(spec)
    for overlay in overlays.get(spec["type"], []):
        if overlay.get("qualifier"):
            result["qualifiers_definition"] = _apply_qualifier_overlay(
                result.get("qualifiers_definition", []),
                overlay["qualifier"],
                overlay["values"],
            )
            continue

        component = overlay["component"]
        result[component] = _merge_dict(result.get(component, {}), overlay["values"])
    return result

def _apply_qualifier_overlay(qualifiers, key, values):
    result = []
    found = False

    for qualifier in qualifiers:
        if qualifier["key"] == key:
            result.append(_merge_dict(qualifier, values))
            found = True
        else:
            result.append(qualifier)

    if not found:
        qualifier = {
            "key": key,
            "description": "Generated overlay for {} qualifier".format(key),
        }
        qualifier.update(values)
        result.append(qualifier)

    return result

def _generate_validation_bzl(specs, overlays):
    runtime_specs = {}
    for entry in specs:
        source = entry["source"]
        spec = entry["spec"]
        _validate_type_definition(spec, source)
        type_name = spec["type"].lower()
        expected_type = entry["type"]
        if expected_type and type_name != expected_type:
            fail("{} declares PURL type {}, expected {}".format(source, type_name, expected_type))
        if type_name in runtime_specs and not entry["override"]:
            fail("Duplicate PURL type definition for {}".format(type_name))
        runtime_specs[type_name] = _runtime_spec(spec, overlays)

    return """# Generated by //purl:extensions.bzl. Do not edit.

load("@re.bzl", "re")

_TYPE_SPECS = {specs}

def _matches(pattern, value):
    return re.search(pattern, value) != None

def type_spec(type):
    return _TYPE_SPECS.get(type)

def _validate_component(type, component, spec, value):
    if spec == None:
        return None

    requirement = spec.get("requirement", "optional")
    if requirement == "required" and not value:
        return "{{}} PURLs require a {{}}".format(type, component)
    if requirement == "prohibited" and value:
        return "{{}} PURLs must not have a {{}}".format(type, component)

    pattern = spec.get("pattern")
    if pattern and value and not _matches(pattern, value):
        return "{{}} PURL {{}} does not match {{}}".format(type, component, pattern)

    return None

def validate_type(
        *,
        type = None,
        namespace = None,
        name = None,
        version = None,
        qualifiers = {{}},
        subpath = None):
    spec = _TYPE_SPECS.get(type.lower())
    if not spec:
        return None

    for component, value in [
        ("namespace", namespace),
        ("name", name),
        ("version", version),
        ("subpath", subpath),
    ]:
        err = _validate_component(type, component, spec.get(component), value)
        if err:
            return err

    qualifiers = qualifiers or {{}}
    for key, qualifier_spec in spec.get("qualifiers", {{}}).items():
        if qualifier_spec.get("requirement") == "required" and not qualifiers.get(key):
            return "{{}} PURLs require qualifier {{}}".format(type, key)
        pattern = qualifier_spec.get("pattern")
        value = qualifiers.get(key)
        if pattern and value and not _matches(pattern, value):
            return "{{}} PURL qualifier {{}} does not match {{}}".format(type, key, pattern)

    return None
""".format(specs = repr(runtime_specs))

def _purl_type_validation_repo_impl(ctx):
    specs = []
    test_specs = []
    overlays = _decode_overlays(ctx.attr.overlays)

    if ctx.attr.discover_standard_types:
        kwargs = {}
        if ctx.attr.standard_sha256:
            kwargs["sha256"] = ctx.attr.standard_sha256
        if ctx.attr.standard_integrity:
            kwargs["integrity"] = ctx.attr.standard_integrity
        if ctx.attr.standard_strip_prefix:
            kwargs["stripPrefix"] = ctx.attr.standard_strip_prefix

        ctx.download_and_extract(
            url = ctx.attr.standard_url,
            output = "purl-spec",
            **kwargs
        )

        if ctx.attr.discover_standard_types:
            standard_spec_paths = []
            for entry in ctx.path("purl-spec/types").readdir():
                path = str(entry)
                if not path.endswith("-definition.json"):
                    continue
                standard_spec_paths.append(path)

            for path in sorted(standard_spec_paths):
                spec = _read_json(ctx, path)
                type_name = spec["type"]
                test_path = "purl-spec/tests/types/{}-test.json".format(type_name)
                specs.append({
                    "type": type_name,
                    "source": path,
                    "spec": spec,
                    "override": False,
                })
                if ctx.path(test_path).exists:
                    test_specs.append({
                        "type": type_name,
                        "source": test_path,
                        "tests": _read_json(ctx, test_path),
                    })

    custom_types = [json.decode(entry) for entry in ctx.attr.custom_types]
    for entry in custom_types:
        spec_file = ctx.attr.specs[entry["spec_index"]]
        specs.append({
            "type": entry["type"],
            "source": str(spec_file),
            "spec": _read_json(ctx, spec_file),
            "override": entry["override"],
        })
        if entry["test_index"] >= 0:
            test_file = ctx.attr.tests[entry["test_index"]]
            test_specs.append({
                "type": entry["type"],
                "source": str(test_file),
                "tests": _read_json(ctx, test_file),
            })

    ctx.file("BUILD.bazel", "exports_files([\"type_tests.bzl\", \"type_tests.json\", \"validation.bzl\"], visibility = [\"//visibility:public\"])\n")
    ctx.file("validation.bzl", _generate_validation_bzl(specs, overlays))
    ctx.file("type_tests.bzl", "type_tests = {}\n".format(repr(test_specs)))
    ctx.file("type_tests.json", json.encode_indent(test_specs))

def _decode_overlays(encoded):
    overlays = {}
    for entry in encoded:
        overlay = json.decode(entry)
        type_name = overlay["type"]
        if type_name not in overlays:
            overlays[type_name] = []
        overlays[type_name].append(overlay)
    return overlays

purl_type_validation_repository = repository_rule(
    implementation = _purl_type_validation_repo_impl,
    attrs = {
        "custom_types": attr.string_list(),
        "discover_standard_types": attr.bool(default = False),
        "overlays": attr.string_list(),
        "specs": attr.label_list(allow_files = [".json"]),
        "tests": attr.label_list(allow_files = [".json"]),
        "standard_url": attr.string(default = _DEFAULT_STANDARD_SOURCE_URL),
        "standard_strip_prefix": attr.string(default = _DEFAULT_STRIP_PREFIX),
        "standard_sha256": attr.string(),
        "standard_integrity": attr.string(),
    },
)

_type_tag = tag_class(
    attrs = {
        "name": attr.string(mandatory = True),
        "spec": attr.label(mandatory = True, allow_single_file = [".json"]),
        "test": attr.label(allow_single_file = [".json"]),
        "override": attr.bool(default = False),
    },
)

_standard_types_tag = tag_class(
    attrs = {
        "test": attr.bool(default = True),
    },
)

_standard_source_tag = tag_class(
    attrs = {
        "url": attr.string(default = _DEFAULT_STANDARD_SOURCE_URL),
        "strip_prefix": attr.string(default = _DEFAULT_STRIP_PREFIX),
        "sha256": attr.string(),
        "integrity": attr.string(),
    },
)

_overlay_tag = tag_class(
    attrs = {
        "type": attr.string(mandatory = True),
        "component": attr.string(mandatory = True),
        "permitted_characters": attr.string(),
        "requirement": attr.string(),
        "case_sensitive": attr.string(),
    },
)

_qualifier_overlay_tag = tag_class(
    attrs = {
        "type": attr.string(mandatory = True),
        "key": attr.string(mandatory = True),
        "permitted_characters": attr.string(),
        "requirement": attr.string(),
        "case_sensitive": attr.string(),
    },
)

def _purl_types_impl(module_ctx):
    specs = []
    tests = []
    custom_types = []
    discover_standard_types = False
    overlays = []

    standard_source_set = False
    standard_source = struct(
        url = _DEFAULT_STANDARD_SOURCE_URL,
        strip_prefix = _DEFAULT_STRIP_PREFIX,
        sha256 = "",
        integrity = "",
    )

    for module in module_ctx.modules:
        for tag in module.tags.type:
            spec_index = len(specs)
            specs.append(tag.spec)
            test_index = -1
            if tag.test:
                test_index = len(tests)
                tests.append(tag.test)
            custom_types.append(json.encode({
                "type": tag.name,
                "spec_index": spec_index,
                "test_index": test_index,
                "override": tag.override,
            }))

        for tag in module.tags.standard_types:
            if discover_standard_types:
                fail("Only one purl_types.standard_types() tag is supported")
            discover_standard_types = True

        for tag in module.tags.standard_source:
            if standard_source_set:
                fail("Only one purl_types.standard_source() tag is supported")
            standard_source_set = True
            standard_source = struct(
                url = tag.url,
                strip_prefix = tag.strip_prefix,
                sha256 = tag.sha256,
                integrity = tag.integrity,
            )

        for tag in module.tags.overlay:
            values = {}
            if tag.permitted_characters:
                values["permitted_characters"] = tag.permitted_characters
            if tag.requirement:
                values["requirement"] = tag.requirement
            if tag.case_sensitive:
                if tag.case_sensitive not in ["true", "false"]:
                    fail("purl_types.overlay() case_sensitive must be 'true' or 'false'")
                values["case_sensitive"] = tag.case_sensitive == "true"
            if not values:
                fail("purl_types.overlay() for {} {} has no values".format(tag.type, tag.component))
            overlays.append(json.encode({
                "type": tag.type,
                "component": tag.component,
                "values": values,
            }))

        for tag in module.tags.qualifier_overlay:
            values = {}
            if tag.permitted_characters:
                values["permitted_characters"] = tag.permitted_characters
            if tag.requirement:
                if tag.requirement not in ["optional", "required"]:
                    fail("purl_types.qualifier_overlay() requirement must be 'optional' or 'required'")
                values["requirement"] = tag.requirement
            if tag.case_sensitive:
                if tag.case_sensitive not in ["true", "false"]:
                    fail("purl_types.qualifier_overlay() case_sensitive must be 'true' or 'false'")
                values["case_sensitive"] = tag.case_sensitive == "true"
            if not values:
                fail("purl_types.qualifier_overlay() for {} {} has no values".format(tag.type, tag.key))
            overlays.append(json.encode({
                "type": tag.type,
                "qualifier": tag.key,
                "values": values,
            }))

    purl_type_validation_repository(
        name = "purl_type_validation",
        custom_types = custom_types,
        discover_standard_types = discover_standard_types,
        overlays = overlays,
        specs = specs,
        tests = tests,
        standard_url = standard_source.url,
        standard_strip_prefix = standard_source.strip_prefix,
        standard_sha256 = standard_source.sha256,
        standard_integrity = standard_source.integrity,
    )

purl_types = module_extension(
    implementation = _purl_types_impl,
    tag_classes = {
        "overlay": _overlay_tag,
        "qualifier_overlay": _qualifier_overlay_tag,
        "type": _type_tag,
        "standard_source": _standard_source_tag,
        "standard_types": _standard_types_tag,
    },
)
