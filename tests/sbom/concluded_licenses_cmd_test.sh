#!/usr/bin/env bash
# Runs cmd/sbom, as the `sbom` rule does, to check how concluded licenses are
# applied and how invalid ones fail.

set -o nounset

readonly SBOM_CMD="$1"
readonly TMP="${TEST_TMPDIR}"

failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

mit_license='{"kind":{"identifier":"MIT","name":"MIT License"},"label":"//:mit"}'
dual_license='{"expression":{"operator":"OR","operands":[
  {"kind":{"identifier":"MIT","name":"MIT License"}},
  {"kind":{"identifier":"Apache-2.0","name":"Apache"}}]},"label":"//:dual"}'

# write_package <name> <license json>
write_package() {
  local name="$1" license="$2"
  echo "${license}" > "${TMP}/${name}.license.json"
  cat > "${TMP}/${name}.metadata.json" <<EOF
{"label":"@@//${name}:package_metadata","purl":"pkg:generic/${name}@1.0.0",
 "attributes":{"build.bazel.attribute.license":"${TMP}/${name}.license.json"}}
EOF
}

write_package root "${mit_license}"
write_package dual "${dual_license}"
echo "${mit_license}" > "${TMP}/conclusion.json"

cat > "${TMP}/graph.json" <<EOF
{"schema_version":"1.0","root_target":"//root","nodes":[
  {"label":"//root","metadata_file":"${TMP}/root.metadata.json"},
  {"label":"//dual","metadata_file":"${TMP}/dual.metadata.json"}],
 "edges":[{"from":"//root","to":"//dual","type":"depends_on"}]}
EOF

# write_manifest <require_resolved_choices> [<purl> ...]: every purl is
# concluded to the MIT license. ${require_matched} (default false) sets
# `require_matched_concluded_licenses`.
require_matched=false
write_manifest() {
  local require_resolved="$1"
  shift
  local entries="" purl
  for purl in "$@"; do
    entries="${entries:+${entries},}\"${purl}\":\"${TMP}/conclusion.json\""
  done
  echo "{\"licenses\":{${entries}},\"require_resolved_choices\":${require_resolved},\"require_matched_concluded_licenses\":${require_matched}}" > "${TMP}/manifest.json"
}

# run_sbom [flags...]: runs cmd/sbom; the status is in `status`, the stderr in
# `stderr` and the classifications in `${TMP}/classifications.json`.
run_sbom() {
  rm -f "${TMP}/classifications.json"
  "${SBOM_CMD}" --input "${TMP}/graph.json" --output "${TMP}/classifications.json" "$@" 2> "${TMP}/stderr"
  status=$?
  stderr="$(cat "${TMP}/stderr")"
}

expect_failure() {
  local description="$1" message="$2"
  if [[ "${status}" -eq 0 ]]; then
    fail "${description}: expected a failure"
  elif [[ "${stderr}" != *"${message}"* ]]; then
    fail "${description}: expected '${message}' in the error, got: ${stderr}"
  fi
}

expect_success() {
  if [[ "${status}" -ne 0 ]]; then
    fail "$1: unexpected failure: ${stderr}"
  fi
}

# Without concluded licenses nothing is concluded.
run_sbom
expect_success "no concluded licenses"
if grep -q concluded_license_file "${TMP}/classifications.json"; then
  fail "no concluded licenses: classifications must not have a concluded license"
fi

# A conclusion ends up on the node of the matching package only.
write_manifest false "pkg:generic/dual@1.0.0"
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_success "concluded license"
if [[ "$(grep -c concluded_license_file "${TMP}/classifications.json")" -ne 1 ]]; then
  fail "concluded license: exactly one node should be concluded: $(cat "${TMP}/classifications.json")"
fi
if ! grep -q "\"concluded_license_file\": \"${TMP}/conclusion.json\"" "${TMP}/classifications.json"; then
  fail "concluded license: missing the concluded license file: $(cat "${TMP}/classifications.json")"
fi

# A conclusion of the root package.
write_manifest false "pkg:generic/root@1.0.0"
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_success "concluded license of the root"
if ! grep -B3 -A3 '"root_component"' "${TMP}/classifications.json" | grep -q concluded_license_file; then
  fail "concluded license of the root: $(cat "${TMP}/classifications.json")"
fi

# A conclusion that matches no package is ignored by default, so that a list
# can be shared by many SBOMs.
write_manifest false "pkg:generic/dual@1.0.0" "pkg:generic/stale@1.0.0"
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_success "unmatched conclusion"

# ... and is stale when every conclusion is required to match.
require_matched=true
write_manifest false "pkg:generic/dual@1.0.0" "pkg:generic/stale@1.0.0"
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_failure "unmatched required conclusion" "pkg:generic/stale@1.0.0"

write_manifest false "pkg:generic/dual@1.0.0" "pkg:generic/root@1.0.0"
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_success "matched required conclusions"
require_matched=false

# The version is part of the key.
require_matched=true
write_manifest false "pkg:generic/dual@2.0.0"
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_failure "other version" "pkg:generic/dual@2.0.0"
require_matched=false

# Invalid keys.
write_manifest false "pkg:generic/dual"
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_failure "key without a version" "must have a version"

write_manifest false "pkg:generic/dual@1.0.0?arch=x86"
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_failure "key with qualifiers" "must only have a type, namespace, name and version"

# Choices left unresolved.
write_manifest true
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_failure "unresolved choice" "//dual is licensed under 'MIT OR Apache-2.0', which offers a choice"

write_manifest true "pkg:generic/dual@1.0.0"
run_sbom --concluded-licenses "${TMP}/manifest.json"
expect_success "resolved choice"

if [[ "${failures}" -ne 0 ]]; then
  echo "${failures} check(s) failed" >&2
  exit 1
fi
