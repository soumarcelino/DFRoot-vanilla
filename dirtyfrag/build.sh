#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-$ROOT/dirtyfrag.ko}
NDK=${ANDROID_NDK_HOME:-/home/matias/Android/Sdk/ndk/26.3.11579264}
TMP=$(mktemp -d /tmp/dirtyfrag.XXXXXX)
trap 'find "$TMP" -type f -delete; find "$TMP" -depth -type d -empty -delete' EXIT
cp "${DIRTYFRAG_SOURCE:-$ROOT/dirtyfrag.c}" "$TMP/dirtyfrag.c"
cp "$ROOT/Makefile" "$TMP/"
if docker info >/dev/null 2>&1; then DOCKER=docker; else DOCKER="sudo docker"; fi
$DOCKER run --rm --pid=host --network=none --user "$(id -u):$(id -g)" \
    -v "$TMP:/src" -w /src ghcr.io/ylarod/ddk-min:android13-5.15 make
mkdir -p "$(dirname "$OUT")"
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy" --strip-unneeded \
    -R .comment -R .note.gnu.build-id -R .note.gnu.property -R .note.Linux \
    -R .note.GNU-stack -R .BTF -R .BTF.base -R .llvm_addrsig \
    -R .hyp.text -R .hyp.bss -R .hyp.rodata -R .hyp.event_ids \
    -R .hyp.patchable_function_entries -R .hyp.data \
    "$TMP/dirtyfrag.ko" "$OUT"
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy" \
    --set-section-alignment .text=4 "$OUT"
