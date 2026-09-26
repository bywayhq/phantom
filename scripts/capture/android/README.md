# Android capture emulators

Build the two emulators that the
[Android captures](../README.md#android-browsers) run on, and keep them in the
state a capture expects.

> For contributors who set up or repair a capture emulator.

| Emulator | Host | System image | Emulator version tested |
| --- | --- | --- | --- |
| `phantom-pixel7` | Windows, x86_64 | `system-images;android-37.0;google_apis_playstore;x86_64` revision 6 | 36.6.11 |
| `phantom-pixel7-arm` | Apple silicon Mac | `system-images;android-37.0;google_apis_playstore;arm64-v8a` revision 6 | 37.1.11 |

Both images are Android 17 (API 37), build `CE2A.260420.019`, with 4 KB
pages like a Pixel 7. The `android-37.1` and `android-37.2` images exist only
with 16 KB pages, and `android-36` is one major version behind a current
Pixel 7. Edge for Android ships only an arm64 build, which cannot start on
the x86_64 image, so Edge runs on the Mac.

This directory holds:

- `start-capture.sh`, which starts an emulator from its `onboarded`
  snapshot;
- `phantom_pixel7/`, a Magisk module whose `system.prop` sets the build
  properties of a Pixel 7 on build `CP3A.260905.009`. The file cites its
  sources.

No binary is kept here: fetch Magisk and the system image yourself and check
them against the digests below.

## Create the AVD

Install the image and create the AVD with the `pixel_7` hardware profile:

```sh
sdkmanager "platform-tools" "emulator" \
  "system-images;android-37.0;google_apis_playstore;x86_64"
avdmanager create avd -n phantom-pixel7 -d pixel_7 \
  -k "system-images;android-37.0;google_apis_playstore;x86_64"
```

On the Mac, use the `arm64-v8a` image and the name `phantom-pixel7-arm`.
Then edit the AVD's `config.ini`:

- `avdmanager` can write placeholders: replace `avd.id=<build>`,
  `avd.name=<build>`, and `disk.dataPartition.path=<temp>` with the AVD name
  and the default data path;
- `PlayStore.enabled=yes`, `hw.keyboard=yes`, `fastboot.forceFastBoot=yes`;
- `disk.dataPartition.size=8G`;
- `hw.ramSize=8192M` on Windows and `hw.ramSize=6144M` on the Mac;
- `hw.cpu.ncore=6`, the most the emulator supports.

On Windows the guest got 4 GB despite `hw.ramSize=8192M`, so
`start-capture.sh` also passes `-memory`. With 2.5 GB of RAM the guest's
system server died during long capture sessions.

## Root with Magisk

Magisk v30.7 from its
[GitHub release](https://github.com/topjohnwu/Magisk/releases/tag/v30.7):
`Magisk-v30.7.apk`, SHA-256
`e0d32d2123532860f97123d927b1bb86c4e08e6fd8a48bfc6b5bee0afae9ebd5`.

Root goes into a patched copy of the image's ramdisk, passed with
`-ramdisk`; the SDK's `ramdisk.img` stays untouched. Keep a copy of the stock
ramdisk next to the patched one.

| Image | Stock `ramdisk.img` SHA-256 | Patched copy on the capture host |
| --- | --- | --- |
| x86_64 | `652ade17d334c4f1bda0eaa8050167df62995f8432f292acb557bae11e8f53d3` | `b2463a44f09a15b56f09bcc9b1b1f04d24784cc57c49b82a78c3d77dc99c9284` |
| arm64-v8a | `af134385a5c56ce0101c7863f1203c30a10857e7a608394c5ee81677c7fe35a5` | `62da20b17c23780ed812dc2ccc066b9924f8eaf43c8572d3c06862ec22b573eb` |

Patch it with the ramdisk steps of Magisk's own `assets/boot_patch.sh`, run by
hand in the guest with the binaries from the same APK:

1. Cold-boot the stock AVD and install the APK with `adb install`.
2. From the APK, take `lib/<abi>/libmagiskboot.so`, `libmagiskinit.so`,
   `libmagisk.so`, and `libinit-ld.so`, and `assets/stub.apk`. Push them to
   `/data/local/tmp/mg` as `magiskboot`, `magiskinit`, `magisk`, `init-ld`,
   and `stub.apk`, with the stock `ramdisk.img`.
3. In `adb shell`, run:

   ```sh
   cd /data/local/tmp/mg && chmod 755 magiskboot
   SHA1=$(./magiskboot sha1 ramdisk.img)
   ./magiskboot decompress ramdisk.img ramdisk.cpio
   cp ramdisk.cpio ramdisk.cpio.orig
   for f in magisk stub.apk init-ld; do ./magiskboot compress=xz "$f" "${f%.apk}.xz"; done
   printf 'KEEPVERITY=true\nKEEPFORCEENCRYPT=true\nRECOVERYMODE=false\nVENDORBOOT=false\nPREINITDEVICE=vdd1\nSHA1=%s\n' "$SHA1" > config
   ./magiskboot cpio ramdisk.cpio "add 0750 init magiskinit" \
     "mkdir 0750 overlay.d" "mkdir 0750 overlay.d/sbin" \
     "add 0644 overlay.d/sbin/magisk.xz magisk.xz" \
     "add 0644 overlay.d/sbin/stub.xz stub.xz" \
     "add 0644 overlay.d/sbin/init-ld.xz init-ld.xz" \
     "patch" "backup ramdisk.cpio.orig" "mkdir 000 .backup" \
     "add 000 .backup/.magisk config"
   ./magiskboot compress=lz4_legacy ramdisk.cpio ramdisk-patched.img
   sync
   ```

   Without `PREINITDEVICE=vdd1` (the `/metadata` partition) Magisk reports
   an incomplete environment and asks to be reflashed.
4. Pull `ramdisk-patched.img`. Run `adb shell sync` before `adb emu kill`:
   files written shortly before a kill can come back empty.
5. Boot with `-ramdisk <patched>`. When the Magisk app asks for additional
   setup, accept and let it reboot. It should then report Magisk 30.7 with
   Ramdisk Yes. Allow root for the shell in its Superuser list.

## Install the identity module

Copy the module into Magisk's module directory and reboot:

```sh
adb push scripts/capture/android/phantom_pixel7 /data/local/tmp/
adb shell su -c "cp -r /data/local/tmp/phantom_pixel7 /data/adb/modules/"
adb shell su -c "rm -r /data/local/tmp/phantom_pixel7"
adb reboot
```

Check the result: `getprop ro.product.model` is `Pixel 7`,
`ro.build.fingerprint` is
`google/panther/panther:17/CP3A.260905.009/16091614:user/release-keys`, and
`ro.build.version.security_patch` is `2026-09-05`. `ro.product.cpu.abilist`
and `ro.build.version.codename` keep the image's values. The stock arm64
image has no `ro.bootimage.build.fingerprint` or `ro.odm.build.id`; the module
adds them.

## Guest settings

Set these once, before the snapshot is saved:

```sh
adb shell svc data disable
adb shell svc wifi enable
adb shell settings put global window_animation_scale 0
adb shell settings put global transition_animation_scale 0
adb shell settings put global animator_duration_scale 0
adb shell settings put secure stylus_handwriting_enabled 0
adb shell su -c "setprop persist.sys.locale en-US"
```

Wi-Fi must be the only network: Chromium sends `initial_rtt_us` on a fresh
QUIC connection when a cellular network is the default. `dumpsys
connectivity` shows the default network; if Wi-Fi drops, `svc wifi disable`
and `svc wifi enable` restore it. `start-capture.sh` sets the time zone to
`America/Los_Angeles`.

Install the browsers from the Play Store with a throwaway account made for
this. Play did not sign in on the Mac, so Edge was installed there with `adb
install-multiple` from the APKs of the Windows install. Do not keep account
data in the repository.

Open each browser once and finish its first-run screens, declining data
collection. Start a browser with `adb shell am start -n
<package>/<activity>`, not `monkey`: `monkey` sends a random event, which
once accepted Chrome's usage statistics.

## The `onboarded` snapshot

A capture starts from the `onboarded` snapshot and never saves over it.
`android_device.py` refuses an emulator that did not load it, because a
cold-booted guest keeps what a run writes, such as `pm clear`, on its disk.
The check reads `debug.phantom.snapshot`: a property without the `persist.`
prefix lives only in guest memory, so a snapshot load brings it back and a
cold boot does not. Set
`PHANTOM_ANDROID_ALLOW_COLD_BOOT=1`, or pass `--allow-cold-boot` to
`android_run.py`, to run on a cold-booted emulator anyway.

To save or re-save the snapshot:

1. Start the emulator with `start-capture.sh`. It loads `onboarded` when one
   exists and cold-boots otherwise.
2. Make the changes. Force-stop the browsers, remove `adb reverse` ports, and
   empty `/data/local/tmp`.
3. Mark the guest and save:

   ```sh
   adb shell sync
   adb shell setprop debug.phantom.snapshot onboarded
   adb emu avd snapshot save onboarded
   adb emu avd snapshot delete default_boot
   adb emu kill
   ```

A snapshot loads only under the renderer it was saved with. Under another
renderer the emulator logs "different renderer configured" and cold-boots.
Save and load with the same `-gpu` value; `start-capture.sh` fixes it per
host:

- Windows: `-gpu swiftshader_indirect`. The default host renderer changes
  when `-no-window` is added, so a snapshot saved with a window would not
  load headless.
- macOS: `-gpu host`, which keeps the Metal renderer with or without a
  window.

Never pass `-wipe-data`: it signs the Play account out, removes the browsers,
and discards root and the snapshot state.

## Start a capture emulator

```sh
ANDROID_SDK_ROOT=<sdk> scripts/capture/android/start-capture.sh \
  -r <patched-ramdisk.img> -- -no-window -no-audio > emulator.log 2>&1 &
```

`-p <port>` sets the console port and so the serial `emulator-<port>`; the
default is 5556. `-a <avd>` overrides the AVD name. Arguments after `--` go
to the emulator. The script clears the proxy variables, because the emulator
otherwise sends the guest's TCP through the host's `HTTP_PROXY`.

A successful load logs `Successfully loaded snapshot 'onboarded'`, and
`sys.boot_completed` is `1` within about 12 seconds. A launch that logs
"starting from scratch" cold-booted; stop it before any capture.
