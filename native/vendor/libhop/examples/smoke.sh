#!/usr/bin/env bash
# Build libhop, regenerate hop.h, compile smoke.c against the C ABI, and run it.
# Proves the generated header + the dylib drive the real protocol from pure C.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$CRATE/../.." && pwd)"

cargo build -p hop --manifest-path "$ROOT/Cargo.toml"
"$CRATE/regen-header.sh"

LIBDIR="$ROOT/target/debug"
clang "$HERE/smoke.c" -I "$CRATE/include" -L "$LIBDIR" -lhop -Wl,-rpath,"$LIBDIR" -o "$HERE/smoke"
"$HERE/smoke"
