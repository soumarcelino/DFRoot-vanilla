#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SDK=${DFROOT_ANDROID_SDK:-/home/matias/Android/Sdk}
NDK=${ANDROID_NDK_HOME:-$SDK/ndk/26.3.11579264}
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang"
D8="$SDK/build-tools/37.0.0/d8"
ANDROID_JAR="$SDK/platforms/android-37/android.jar"
OUT="$ROOT/build"
TMP=$(mktemp -d /tmp/dfroot-build.XXXXXX)
trap 'find "$TMP" -type f -delete; find "$TMP" -depth -type d -empty -delete' EXIT

mkdir -p "$OUT" "$TMP/embed" "$TMP/classes" "$TMP/dex"
find "$OUT" -type f -delete

# The module must be built against the Android 13 / 5.15 GKI ABI.
mkdir "$TMP/module"
cp "$ROOT/module/dirtyfrag.c" "$ROOT/module/Makefile" "$TMP/module/"
if docker info >/dev/null 2>&1; then
    DOCKER=docker
else
    DOCKER="sudo docker"
fi
$DOCKER run --rm --pid=host --network=none \
    --user "$(id -u):$(id -g)" \
    -v "$TMP/module:/src" -w /src \
    ghcr.io/ylarod/ddk-min:android13-5.15 make
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy" --strip-unneeded \
    -R .comment -R .note.gnu.build-id -R .note.gnu.property -R .note.Linux \
    -R .note.GNU-stack -R .BTF -R .BTF.base -R .llvm_addrsig \
    -R .hyp.text -R .hyp.bss -R .hyp.rodata -R .hyp.event_ids \
    -R .hyp.patchable_function_entries -R .hyp.data \
    "$TMP/module/dirtyfrag.ko" "$OUT/dirtyfrag.ko"

"$CC" "$ROOT/src/native/splicehelper.c" -o "$TMP/embed/splicehelper" \
    -nodefaultlibs -nostartfiles -ffreestanding -static
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" "$TMP/embed/splicehelper"
cp "$OUT/dirtyfrag.ko" "$TMP/embed/dirtyfrag.ko"

(cd "$TMP/embed" && "$CC" -shared -fPIC -O2 -Wall -Wextra \
    -I"$ROOT/src/native" -Wl,--no-undefined,-z,max-page-size=16384 \
    -o "$OUT/libexp.so" \
    "$ROOT/src/native/runner.c" "$ROOT/src/native/dirtyfrag.c" \
    "$ROOT/src/native/payload.c" "$ROOT/src/native/elf.c" \
    "$ROOT/src/native/shellcode.S")

javac -Xlint:-options -source 11 -target 11 -cp "$ANDROID_JAR" -d "$TMP/classes" \
    $(find "$ROOT/src/java" -name '*.java' -print)
jar cf "$TMP/classes.jar" -C "$TMP/classes" .
"$D8" --min-api 28 --output "$TMP/dex" "$TMP/classes.jar"
(cd "$TMP/dex" && zip -q -j "$OUT/runner.jar" classes.dex)

sha256sum "$OUT/dirtyfrag.ko" "$OUT/runner.jar" "$OUT/libexp.so" "$ROOT/payload/ksud"
