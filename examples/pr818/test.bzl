"""Example test for registering a PURL type spec from purl-spec PR 818."""

load("@purl_type_validation//:type_tests.bzl", "type_tests")
load("@purl_type_validation//:validation.bzl", "type_spec")
load("@package_metadata//purl:purl.bzl", "purl")

_INPUT = "pkg:apk/alpine/libcrypto3@3.5.5-r0?arch=x86_64&distro=alpine-edge&upstream=openssl"

_EXPECTED = {
    "type": "apk",
    "namespace": "alpine",
    "name": "libcrypto3",
    "version": "3.5.5-r0",
    "qualifiers": {
        "arch": "x86_64",
        "distro": "alpine-edge",
        "upstream": "openssl",
    },
    "subpath": None,
}

_bash_executable = """
#!/usr/bin/env bash

echo '{message}'
exit {status}
""".strip()

_bat_executable = """
echo '{message}'
exit /b {status}
""".strip()

def _pr818_example_test_impl(ctx):
    failures = []

    apk_spec = type_spec("apk")
    if apk_spec == None:
        failures.append("Generated validator does not include the apk type")
    elif "distro" not in apk_spec.get("qualifiers", {}):
        failures.append("Generated apk validator does not include the distro qualifier from PR 818")
    elif "upstream" not in apk_spec.get("qualifiers", {}):
        failures.append("Generated apk validator does not include the upstream qualifier from PR 818")

    has_pr_test = False
    for entry in type_tests:
        if entry["type"] != "apk":
            continue
        for test in entry["tests"]["tests"]:
            if test["input"] == _INPUT:
                has_pr_test = True
                break
    if not has_pr_test:
        failures.append("Generated type test metadata does not include the PR 818 apk test input")

    actual, err = purl.parse(_INPUT)
    if err:
        failures.append("Expected parse success, got {}".format(err))
    elif actual != _EXPECTED:
        failures.append("Expected parsed components {}, got {}".format(_EXPECTED, actual))

    actual = purl.builder() \
        .type(_EXPECTED["type"]) \
        .namespace(_EXPECTED["namespace"]) \
        .name(_EXPECTED["name"]) \
        .version(_EXPECTED["version"]) \
        .add_qualifier("arch", _EXPECTED["qualifiers"]["arch"]) \
        .add_qualifier("distro", _EXPECTED["qualifiers"]["distro"]) \
        .add_qualifier("upstream", _EXPECTED["qualifiers"]["upstream"]) \
        .build()
    err = None
    if err:
        failures.append("Expected build success, got {}".format(err))
    elif actual != _INPUT:
        failures.append("Expected built PURL {}, got {}".format(_INPUT, actual))

    content = _bash_executable if (ctx.configuration.host_path_separator == ":") else _bat_executable
    executable = ctx.actions.declare_file("{}.bat".format(ctx.attr.name))
    ctx.actions.write(
        output = executable,
        content = content.format(
            message = json.encode_indent(failures),
            status = 1 if failures else 0,
        ),
        is_executable = True,
    )

    return [DefaultInfo(
        files = depset([executable]),
        executable = executable,
    )]

pr818_example_test = rule(
    implementation = _pr818_example_test_impl,
    test = True,
)
