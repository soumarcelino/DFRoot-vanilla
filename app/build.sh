#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APP="$ROOT/app"
GEN="$APP/app/build/generated"
TMP=$(mktemp -d /tmp/dfroot-app.XXXXXX)
trap 'find "$TMP" -type f -delete; find "$TMP" -depth -type d -empty -delete' EXIT

mkdir -p "$GEN/jniLibs/arm64-v8a" "$GEN/assets"
sed 's#/data/local/tmp/ksud#/data/user_de/0/df.root/ksud#' \
    "$ROOT/dirtyfrag/dirtyfrag.c" > "$TMP/dirtyfrag.c"
DIRTYFRAG_SOURCE="$TMP/dirtyfrag.c" \
    "$ROOT/dirtyfrag/build.sh" "$TMP/dirtyfrag.ko"
"$ROOT/splicehelper/build.sh" "$TMP/splicehelper"
"$ROOT/libexp/build.sh" "$TMP/dirtyfrag.ko" "$TMP/splicehelper" \
    "$GEN/jniLibs/arm64-v8a/libexp.so"
cp "$ROOT/ksud/ksud" "$GEN/assets/ksud"

(cd "$APP" && gradle --no-daemon :app:assembleDebug)
cp "$APP/app/build/outputs/apk/debug/app-debug.apk" "$APP/dfroot.apk"
echo "$APP/dfroot.apk"
