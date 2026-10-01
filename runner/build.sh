#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-$ROOT/runner.jar}
SDK=${DFROOT_ANDROID_SDK:-/home/matias/Android/Sdk}
TMP=$(mktemp -d /tmp/dfroot-runner.XXXXXX)
trap 'find "$TMP" -type f -delete; find "$TMP" -depth -type d -empty -delete' EXIT
mkdir "$TMP/classes" "$TMP/dex"
javac -Xlint:-options -source 11 -target 11 -cp "$SDK/platforms/android-37/android.jar" \
    -d "$TMP/classes" $(find "$ROOT/src" -name '*.java' -print)
jar cf "$TMP/classes.jar" -C "$TMP/classes" .
"$SDK/build-tools/37.0.0/d8" --min-api 28 --output "$TMP/dex" "$TMP/classes.jar"
mkdir -p "$(dirname "$OUT")"
(cd "$TMP/dex" && zip -q -j "$OUT" classes.dex)
