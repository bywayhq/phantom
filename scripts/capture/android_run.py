"""Open one page in an Android browser on a cleared profile, then stop it.

For capture tools that only listen, such as the `capture_client_hello` and
`capture_http2_tls` examples: start the listener, then run this with its URL.
The recorded launch arguments go to standard output for the fixture's
`launch_arguments` field.
"""

from __future__ import annotations

import argparse
import os
import time
from collections.abc import Sequence
from pathlib import Path

from .android_device import ALLOW_COLD_BOOT_VARIABLE, ANDROID_BROWSERS
from .browser_launch import BROWSERS, LaunchedBrowser, LaunchPlan


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--browser", choices=[name for name in BROWSERS if name in ANDROID_BROWSERS]
    )
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument(
        "--switch",
        action="append",
        default=[],
        help="an extra Chromium switch, in order; repeat for more",
    )
    parser.add_argument("--entry", choices=("typed", "intent"), default="typed")
    parser.add_argument("--hold", type=float, default=8.0)
    parser.add_argument("--print-arguments", action="store_true")
    parser.add_argument(
        "--allow-physical-device",
        action="store_true",
        help="run on a device that is not an emulator; its browser data is cleared",
    )
    parser.add_argument(
        "--allow-cold-boot",
        action="store_true",
        help="run on an emulator that did not load its marked snapshot",
    )
    args = parser.parse_args(argv)
    if args.browser is None:
        parser.error("--browser is required")
    plan = LaunchPlan(
        args.browser,
        args.adb,
        False,
        tuple(args.switch),
        android_entry=args.entry,
        android_allow_physical_device=args.allow_physical_device,
    )
    if args.allow_cold_boot:
        os.environ[ALLOW_COLD_BOOT_VARIABLE] = "1"
    if args.print_arguments:
        print(plan.recorded_arguments(args.url), flush=True)
        return
    with LaunchedBrowser(plan, args.url):
        time.sleep(args.hold)


if __name__ == "__main__":
    main()
