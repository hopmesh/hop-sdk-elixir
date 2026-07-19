#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
LIBDIR="$ROOT/target/debug"
BIN="$(mktemp "${TMPDIR:-/tmp}/hop-wire-vectors.XXXXXX")"
trap 'rm -f "$BIN"' EXIT

cargo build -p hop --manifest-path "$ROOT/Cargo.toml" --no-default-features --features minimal --locked
clang -std=c11 -Wall -Wextra -Werror -pedantic \
  "$HERE/wire_vectors.c" -I "$ROOT/sdk" -L "$LIBDIR" -lhop \
  -Wl,-rpath,"$LIBDIR" -o "$BIN"
"$BIN" "$ROOT/core/hop-core/vectors/bundle-v10.json"
