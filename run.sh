#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SERIAL=${1:-RXCX602E20X}
REMOTE=/data/local/tmp/dfroot

adb -s "$SERIAL" get-state >/dev/null
BOOT=$(adb -s "$SERIAL" shell cat /proc/sys/kernel/random/boot_id | tr -d '\r')
LAST=$(adb -s "$SERIAL" shell "cat $REMOTE/last-boot 2>/dev/null || true" | tr -d '\r')
[ "$BOOT" != "$LAST" ] || { echo "Já executado neste boot. Reinicie o device." >&2; exit 2; }

"$ROOT/build.sh"
adb -s "$SERIAL" shell "mkdir -p $REMOTE"
adb -s "$SERIAL" push "$ROOT/build/runner.jar" "$REMOTE/runner.jar" >/dev/null
adb -s "$SERIAL" push "$ROOT/build/libexp.so" "$REMOTE/libexp.so" >/dev/null
adb -s "$SERIAL" push "$ROOT/payload/ksud" /data/local/tmp/ksud >/dev/null
adb -s "$SERIAL" shell "chmod 755 /data/local/tmp/ksud; printf '%s\n' '$BOOT' >$REMOTE/last-boot"

adb -s "$SERIAL" shell \
    "CLASSPATH=$REMOTE/runner.jar app_process -Ddfroot.lib=$REMOTE/libexp.so /system/bin df.root.CliRunner"

[ "$BOOT" = "$(adb -s "$SERIAL" shell cat /proc/sys/kernel/random/boot_id | tr -d '\r')" ]
adb -s "$SERIAL" shell su -c id
