#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$ROOT/out"
mkdir -p "$OUT"
find "$OUT" -type f -delete
"$ROOT/dirtyfrag/build.sh" "$OUT/dirtyfrag.ko"
"$ROOT/splicehelper/build.sh" "$OUT/splicehelper"
"$ROOT/libexp/build.sh" "$OUT/dirtyfrag.ko" "$OUT/splicehelper" "$OUT/libexp.so"
"$ROOT/runner/build.sh" "$OUT/runner.jar"
sha256sum "$OUT/dirtyfrag.ko" "$OUT/splicehelper" "$OUT/libexp.so" "$OUT/runner.jar" "$ROOT/ksud/ksud"
