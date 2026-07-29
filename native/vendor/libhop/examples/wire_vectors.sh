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
# Resolve the corpus by glob: it is renamed on every BUNDLE_VERSION bump (bundle-v<N>.json), so a
# pinned filename rots silently. Exactly one is committed at a time.
CORPUS=$(ls "$ROOT"/core/hop-core/vectors/bundle-v*.json 2>/dev/null | head -1)
[ -n "$CORPUS" ] || { echo "no bundle-v<N>.json corpus found" >&2; exit 1; }
"$BIN" "$CORPUS"
