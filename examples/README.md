# Examples for supply_chain_tools

This set of files provides an example of how license rules can be used.

Terminology
-   Organization: A company, organization or other entity that wants to use
    license rules to enforce their particular compliance needs. These examples
    use the work organization throughout.
-   SCM: source code management system. These examples assume that
    an organization has a SCM that can enforce ownership restrictions on
    specific folder trees. Targets are divided into BUILD files that are
    reviewed by engineers vs. those that are reviewed by an organizations
    compliance team.

## Overview

TODO

## Python Runtime SBOM

The `//python:hello_python` example is a `py_binary` with internal
`py_library` dependencies, runtime data, and a PyPI dependency from
`pip.parse`. The examples module applies `rules_python_runtime_sbom.patch`,
which instruments generated wheel libraries with package metadata and the
resolved Python toolchain as a `runtime_dependency` because Python programs
require the runtime interpreter and its own files to execute.
