#!/bin/sh
# Start a capture emulator from its `onboarded` snapshot without saving over it.
#
# Usage: start-capture.sh -r <patched-ramdisk.img> [-p <port>] [-a <avd>] [-- <emulator args>...]
#
# ANDROID_SDK_ROOT names the SDK. The console port sets the adb serial
# (emulator-<port>); it defaults to 5556. Arguments after `--` go to the
# emulator unchanged, such as `-no-window -no-audio`.
#
# The renderer is fixed per host because a snapshot loads only under the
# renderer it was saved with; under another one the emulator cold-boots.
# Windows uses swiftshader_indirect: the host renderer changes when the
# window is turned off, and swiftshader does not. On macOS, host (Metal)
# stays the same without a window.
set -eu

usage() {
  echo "usage: $0 -r <patched-ramdisk.img> [-p <port>] [-a <avd>] [-- <emulator args>...]" >&2
  exit 2
}

port=5556
avd=
ramdisk=
while getopts a:p:r:h option; do
  case "$option" in
    a) avd=$OPTARG ;;
    p) port=$OPTARG ;;
    r) ramdisk=$OPTARG ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))
[ "${1:-}" = "--" ] && shift

[ -n "$ramdisk" ] || usage
[ -f "$ramdisk" ] || { echo "$0: no ramdisk at $ramdisk" >&2; exit 1; }
: "${ANDROID_SDK_ROOT:?set ANDROID_SDK_ROOT to the Android SDK directory}"
case "$port" in
  *[!0-9]* | "") usage ;;
esac
# The emulator takes even console ports from 5554 to 5682; adb uses port + 1.
if [ "$port" -lt 5554 ] || [ "$port" -gt 5682 ] || [ $((port % 2)) -ne 0 ]; then
  echo "$0: the console port must be even, from 5554 to 5682" >&2
  exit 2
fi

case "$(uname -s)" in
  Darwin)
    : "${avd:=phantom-pixel7-arm}"
    set -- -gpu host -memory 6144 -cores 6 "$@"
    ;;
  *)
    : "${avd:=phantom-pixel7}"
    set -- -gpu swiftshader_indirect -memory 8192 "$@"
    ;;
esac

# The emulator sends the guest's TCP through the host's HTTP proxy when one is
# set, so the proxy variables are cleared.
exec env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  -u http_proxy -u https_proxy -u all_proxy \
  "$ANDROID_SDK_ROOT/emulator/emulator" -avd "$avd" -port "$port" \
  -snapshot onboarded -no-snapshot-save -ramdisk "$ramdisk" \
  -timezone America/Los_Angeles -no-boot-anim -no-metrics \
  -netspeed full -netdelay none "$@"
