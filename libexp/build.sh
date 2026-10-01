#!/bin/sh
set -eu
[ "$#" -eq 3 ] || { echo "uso: $0 DIRTYFRAG.KO SPLICEHELPER LIBEXP.SO" >&2; exit 2; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KO=$1
HELPER=$2
OUT=$3
NDK=${ANDROID_NDK_HOME:-/home/matias/Android/Sdk/ndk/26.3.11579264}
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang"
TMP=$(mktemp -d /tmp/libexp.XXXXXX)
trap 'find "$TMP" -type f -delete; find "$TMP" -depth -type d -empty -delete' EXIT
cp "$KO" "$TMP/dirtyfrag.ko"
cp "$HELPER" "$TMP/splicehelper"
mkdir -p "$(dirname "$OUT")"
(cd "$TMP" && "$CC" -shared -fPIC -O2 -Wall -Wextra -I"$ROOT/src" \
    -Wl,--no-undefined,-z,max-page-size=16384 -o "$OUT" \
    "$ROOT/src/runner.c" "$ROOT/src/dirtyfrag.c" "$ROOT/src/payload.c" \
    "$ROOT/src/elf.c" "$ROOT/src/shellcode.S")
