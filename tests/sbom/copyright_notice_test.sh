#!/bin/bash
set -euo pipefail

with_spdx="$1"
with_cdx="$2"
without_spdx="$3"
without_cdx="$4"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

grep -qF '"copyrightText":"Copyright © 2026 The authors of this stuff.\nCopyright © 1999 A. Cöntributor"' "$with_spdx" ||
  fail "SPDX copyrightText missing in $with_spdx"
grep -qF '"copyright":"Copyright © 2026 The authors of this stuff.\nCopyright © 1999 A. Cöntributor"' "$with_cdx" ||
  fail "CycloneDX copyright missing in $with_cdx"

grep -qF '"copyrightText":"NOASSERTION"' "$without_spdx" ||
  fail "SPDX copyrightText should be NOASSERTION in $without_spdx"
if grep -q '"copyright"' "$without_cdx"; then
  fail "CycloneDX copyright should be absent in $without_cdx"
fi
