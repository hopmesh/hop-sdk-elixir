#!/usr/bin/env bash
# Regenerate the libhop C ABI header (include/hop.h) from the Rust source, then publish it to the
# cross-language SDK locations. Run after editing cabi.rs. The header is the bearer/client contract;
# NEVER hand-edit any copy; edit cabi.rs + rerun. Every copy is identical and generated.
set -euo pipefail
cd "$(dirname "$0")"
CRATE="$(pwd)"
ROOT="$(cd "$CRATE/../.." && pwd)"

cbindgen --config cbindgen.toml --crate hop --output include/hop.h
echo "regenerated include/hop.h"

# Publish copies for the SDK + its language wrappers (kept in lockstep; consumers don't run cbindgen).
publish() { mkdir -p "$(dirname "$1")"; cp -f include/hop.h "$1"; echo "published $1"; }
publish "$ROOT/sdk/hop.h"
