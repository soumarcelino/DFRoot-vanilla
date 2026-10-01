#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-$ROOT/splicehelper}
NDK=${ANDROID_NDK_HOME:-/home/matias/Android/Sdk/ndk/26.3.11579264}
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang"
mkdir -p "$(dirname "$OUT")"
"$CC" "$ROOT/splicehelper.c" -o "$OUT" -nodefaultlibs -nostartfiles -ffreestanding -static
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" "$OUT"
