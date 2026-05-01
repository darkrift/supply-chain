"""Test runner for PURL spec tests."""

load("//purl/private:builder.bzl", "build")
load("//purl/private:parser.bzl", "parse")
load("//purl/private/tests:spec.bzl", "tests")

visibility([
    "//purl/private/tests/...",
])

_bash_executable = """
#!/usr/bin/env bash

echo '{message}'
exit {status}
""".strip()

_bat_executable = """
echo '{message}'
exit /b {status}
""".strip()

def _check_build_test(test, failures):
    actual, err = build(**test["input"])
    if test["expected_failure"]:
        if err:
            return

        failures.append({
            "description": test["description"],
            "message": "Expected failure: {}".format(test["expected_failure_reason"]),
        })
    else:
        if err:
            failures.append({
                "description": test["description"],
                "message": "Expected no failure, got {}".format(err),
            })
            return
        expected = test["expected_output"]
        if expected != actual:
            failures.append({
                "description": test["description"],
                "message": "Expected {}, got {}".format(expected, actual),
            })

def _check_parse_test(test, failures):
    actual, err = parse(test["input"])
    if test["expected_failure"]:
        if err:
            return

        failures.append({
            "description": test["description"],
            "message": "Expected failure: {}".format(test["expected_failure_reason"]),
        })
    else:
        if err:
            failures.append({
                "description": test["description"],
                "message": "Expected no failure, got {}".format(err),
            })
            return
        expected = test["expected_output"]
        if expected != actual:
            failures.append({
                "description": test["description"],
                "message": "Expected {}, got {}".format(expected, actual),
            })

def _check_roundtrip_test(test, failures):
    parsed, err = parse(test["input"])
    if test["expected_failure"]:
        if err:
            return

        _, err = build(**parsed)
        if err:
            return

        failures.append({
            "description": test["description"],
            "message": "Expected failure: {}".format(test["expected_failure_reason"]),
        })
    else:
        if err:
            failures.append({
                "description": test["description"],
                "message": "Expected no parse failure, got {}".format(err),
            })
            return
        actual, err = build(**parsed)
        if err:
            failures.append({
                "description": test["description"],
                "message": "Expected no build failure, got {}".format(err),
            })
            return
        expected = test["expected_output"]
        if expected != actual:
            failures.append({
                "description": test["description"],
                "message": "Expected {}, got {}".format(expected, actual),
            })

def _purl_spec_test_impl(ctx):
    failures = []
    for test in tests:
        if test["test_group"] not in ["base", "advanced"]:
            fail("Unexpected test group {}".format(test["test_group"]))
        if test["test_type"] == "build":
            _check_build_test(test, failures)
        elif test["test_type"] == "parse":
            _check_parse_test(test, failures)
        elif test["test_type"] == "roundtrip":
            _check_roundtrip_test(test, failures)
        else:
            fail("Unexpected test type {}".format(test["test_type"]))

    content = _bash_executable if (ctx.configuration.host_path_separator == ":") else _bat_executable

    # Unix does not care about the file extension, so always use `.bat` so it
    # also works on Windows.
    executable = ctx.actions.declare_file("{}.bat".format(ctx.attr.name))
    ctx.actions.write(
        output = executable,
        content = content.format(
            message = json.encode_indent(failures),
            status = 1 if len(failures) else 0,
        ),
        is_executable = True,
    )

    return [
        DefaultInfo(
            files = depset(
                direct = [
                    executable,
                ],
            ),
            executable = executable,
        ),
    ]

purl_spec_test = rule(
    implementation = _purl_spec_test_impl,
    test = True,
)
