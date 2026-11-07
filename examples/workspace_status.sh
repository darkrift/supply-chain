#!/usr/bin/env bash
set -euo pipefail

git_commit_timestamp="$(git log -1 --format=%ct 2>/dev/null || true)"
if [[ -z "${git_commit_timestamp}" ]]; then
  git_commit_timestamp="0"
fi

git_commit="$(git rev-parse HEAD 2>/dev/null || true)"
if [[ -z "${git_commit}" ]]; then
  git_commit="unknown"
fi

build_version="$(git describe --tags --always --dirty 2>/dev/null || true)"
if [[ -z "${build_version}" ]]; then
  build_version="dev"
fi

if command -v uuidgen >/dev/null 2>&1; then
  sbom_serial_number="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"
else
  sbom_serial_number="urn:uuid:00000000-0000-0000-0000-000000000000"
fi

echo "BUILD_TIMESTAMP ${git_commit_timestamp}"
echo "STABLE_EXAMPLE_VERSION ${git_commit_timestamp}"
echo "STABLE_BUILD_VERSION ${build_version}"
echo "STABLE_GIT_COMMIT ${git_commit}"
echo "STABLE_VCS_REVISION ${git_commit}"
echo "SBOM_SERIAL_NUMBER ${sbom_serial_number}"
