"""Launch a browser with a disposable profile and record the exact launch."""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .android_device import (
    ANDROID_BROWSERS,
    ANDROID_CHROMIUM_BROWSERS,
    ANDROID_CHROMIUM_FIRST_RUN_FLAGS,
    AdbDevice,
    AndroidLaunch,
    AndroidSession,
    android_launch_mode,
    device_arguments,
)

DESKTOP_CHROMIUM_BROWSERS = ("chrome", "edge", "brave", "opera")
# Android Chromium browsers take the same switches through a command-line file.
CHROMIUM_BROWSERS = (*DESKTOP_CHROMIUM_BROWSERS, *ANDROID_CHROMIUM_BROWSERS)
FIREFOX_BROWSERS = ("firefox", "firefox-android")
BROWSERS = (*DESKTOP_CHROMIUM_BROWSERS, "firefox", *ANDROID_BROWSERS)
PROFILE_PLACEHOLDER = "<temporary-profile>"
CLIENT_NAMES = {
    "chrome": "Google Chrome",
    "edge": "Microsoft Edge",
    "brave": "Brave",
    "opera": "Opera",
    "firefox": "Mozilla Firefox",
    **{name: browser.client_name for name, browser in ANDROID_BROWSERS.items()},
    "manual": "manual",
}

# Flags that keep a fresh Chromium profile from issuing unrelated background
# requests during a loopback capture. They are recorded verbatim in fixtures.
CHROMIUM_FLAGS = (
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--no-proxy-server",
    "--disable-client-side-phishing-detection",
    "--disable-component-extensions-with-background-pages",
    "--disable-domain-reliability",
    "--disable-sync",
    "--no-pings",
    # MediaRouter probes Cast devices on the local network.
    "--disable-features=MediaRouter,OptimizationHints",
)

# Firefox has no equivalent command-line switches; these preferences disable
# the same classes of background traffic in the disposable profile.
FIREFOX_PREFERENCES = (
    ("app.normandy.enabled", False),
    ("app.update.disabledForTesting", True),
    ("browser.aboutwelcome.enabled", False),
    ("browser.newtabpage.enabled", False),
    ("browser.region.network.url", ""),
    ("browser.region.update.enabled", False),
    ("browser.safebrowsing.malware.enabled", False),
    ("browser.safebrowsing.phishing.enabled", False),
    ("browser.shell.checkDefaultBrowser", False),
    ("browser.startup.homepage_override.mstone", "ignore"),
    ("datareporting.policy.dataSubmissionEnabled", False),
    ("doh-rollout.disable-heuristics", True),
    ("dom.push.connection.enabled", False),
    ("extensions.update.enabled", False),
    ("media.gmp-manager.updateEnabled", False),
    ("network.captive-portal-service.enabled", False),
    ("network.connectivity-service.enabled", False),
    ("network.proxy.type", 0),
    ("network.trr.mode", 5),
    # Mozilla's own test profiles point remote settings at this inert URL.
    ("services.settings.server", "data:,#remote-settings-dummy/v1"),
    ("toolkit.telemetry.enabled", False),
)


def chromium_arguments(
    profile: Path, url: str, *, headless: bool, extra: Sequence[str] = ()
) -> list[str]:
    arguments = ["--headless=new"] if headless else []
    arguments.append(f"--user-data-dir={profile}")
    arguments.extend(CHROMIUM_FLAGS)
    arguments.extend(extra)
    arguments.append(url)
    return arguments


def firefox_arguments(
    profile: Path, url: str, *, headless: bool, extra: Sequence[str] = ()
) -> list[str]:
    arguments = ["--headless"] if headless else []
    # Firefox's launcher process otherwise exits after starting the browser,
    # which would leave nothing for the harness to wait on or terminate.
    arguments.append("--wait-for-browser")
    arguments.extend(["--no-remote", "--profile", str(profile)])
    arguments.extend(extra)
    arguments.append(url)
    return arguments


def preference_value(value: bool | int | str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def firefox_user_js(extra: Sequence[tuple[str, bool | int | str]] = ()) -> str:
    """Render the baseline preferences, then `extra` in caller order."""
    lines = [
        f'user_pref("{name}", {preference_value(value)});'
        for name, value in (*FIREFOX_PREFERENCES, *extra)
    ]
    return "\n".join(lines) + "\n"


def render_preferences(preferences: Sequence[tuple[str, bool | int | str]]) -> str:
    """Render scenario-specific preferences for a fixture line."""
    return ";".join(f"{name}={preference_value(value)}" for name, value in preferences)


def android_chromium_arguments(extra: Sequence[str] = ()) -> list[str]:
    """Switches for an Android Chromium command-line file, in file order.

    Android has no headless mode or `--user-data-dir`: the launch clears the
    app's data instead. Host-resolver rules are rewritten for the emulator.
    `--no-proxy-server` would override a `--proxy-server` switch, so it is
    left out when one is present.
    """
    proxied = any(argument.startswith("--proxy-server=") for argument in extra)
    return [
        *ANDROID_CHROMIUM_FIRST_RUN_FLAGS,
        *(
            flag
            for flag in CHROMIUM_FLAGS
            if not (proxied and flag == "--no-proxy-server")
        ),
        *device_arguments(extra),
    ]


def browser_arguments(
    browser: str, profile: Path, url: str, *, headless: bool, extra: Sequence[str]
) -> list[str]:
    if browser in ANDROID_CHROMIUM_BROWSERS:
        return [*android_chromium_arguments(extra), url]
    if browser in ANDROID_BROWSERS:
        if extra:
            raise ValueError(f"{browser} cannot take command-line switches")
        return [url]
    if browser in CHROMIUM_BROWSERS:
        return chromium_arguments(profile, url, headless=headless, extra=extra)
    if browser == "firefox":
        return firefox_arguments(profile, url, headless=headless, extra=extra)
    raise ValueError(f"unsupported browser: {browser}")


def recorded_arguments(arguments: Sequence[str], profile: Path) -> str:
    """Render launch arguments for a fixture without the machine-local profile."""
    text = str(profile)
    portable = [argument.replace(text, PROFILE_PLACEHOLDER) for argument in arguments]
    return shlex.join(portable)


@dataclass(frozen=True)
class LaunchPlan:
    browser: str
    executable: Path | None
    headless: bool
    extra_arguments: tuple[str, ...] = ()
    # Appended to the baseline `user.js`; Firefox has no switches for these.
    firefox_preferences: tuple[tuple[str, bool | int | str], ...] = ()
    # (name, text) files written into the disposable profile before launch.
    profile_files: tuple[tuple[str, str], ...] = ()
    # How an Android browser reaches the page: "typed" into the address bar,
    # or "intent", which opens it without user activation.
    android_entry: str = "typed"

    @property
    def launch_mode(self) -> str:
        if self.browser == "manual":
            return "manual"
        if self.android:
            return android_launch_mode(self.android_entry)
        return "headless" if self.headless else "headful"

    @property
    def android(self) -> bool:
        return self.browser in ANDROID_BROWSERS

    @property
    def client_name(self) -> str:
        return CLIENT_NAMES[self.browser]

    def recorded_arguments(self, url: str) -> str:
        if self.browser == "manual":
            return "manual"
        profile = Path(PROFILE_PLACEHOLDER)
        return recorded_arguments(
            browser_arguments(
                self.browser,
                profile,
                url,
                headless=self.headless,
                extra=self.extra_arguments,
            ),
            profile,
        )


class LaunchedBrowser:
    """One browser process on a fresh profile, removed with its process tree.

    For an Android browser the executable is adb, and the fresh profile is the
    app's cleared data on the device.
    """

    def __init__(self, plan: LaunchPlan, url: str) -> None:
        if plan.browser == "manual":
            raise ValueError("manual launches have no browser process")
        if plan.executable is None:
            raise ValueError("a browser executable is required")
        self.plan = plan
        self.url = url
        self.profile: Path | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.session: AndroidSession | None = None

    def android_launch(self) -> AndroidLaunch:
        if self.plan.profile_files:
            raise ValueError("an Android browser profile cannot receive files")
        arguments = browser_arguments(
            self.plan.browser,
            Path(PROFILE_PLACEHOLDER),
            self.url,
            headless=False,
            extra=self.plan.extra_arguments,
        )
        preferences = self.plan.firefox_preferences
        if self.plan.browser in FIREFOX_BROWSERS:
            preferences = (*FIREFOX_PREFERENCES, *preferences)
        return AndroidLaunch(
            ANDROID_BROWSERS[self.plan.browser],
            self.url,
            tuple(arguments[:-1]),
            preferences,
            entry=self.plan.android_entry,
        )

    def __enter__(self) -> LaunchedBrowser:
        if self.plan.android:
            assert self.plan.executable is not None
            session = AndroidSession(
                AdbDevice(self.plan.executable), self.android_launch()
            )
            self.session = session.__enter__()
            return self
        self.profile = Path(tempfile.mkdtemp(prefix="phantom-capture-profile-"))
        try:
            self.process = self._start(self.profile)
        except BaseException:
            shutil.rmtree(self.profile, ignore_errors=True)
            self.profile = None
            raise
        return self

    def _start(self, profile: Path) -> subprocess.Popen[bytes]:
        if self.plan.browser == "firefox":
            (profile / "user.js").write_text(
                firefox_user_js(self.plan.firefox_preferences), encoding="utf-8"
            )
        for name, text in self.plan.profile_files:
            if Path(name).name != name:
                raise ValueError(f"profile file must be a plain name: {name}")
            (profile / name).write_text(text, encoding="utf-8", newline="")
        arguments = browser_arguments(
            self.plan.browser,
            profile,
            self.url,
            headless=self.plan.headless,
            extra=self.plan.extra_arguments,
        )
        options: dict[str, object] = {}
        if sys.platform != "win32":
            options["start_new_session"] = True
        return subprocess.Popen(
            [str(self.plan.executable), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **options,
        )

    def __exit__(self, *_: object) -> None:
        if self.session is not None:
            self.session.__exit__()
            self.session = None
            return
        try:
            if self.process is not None:
                terminate_process_tree(self.process)
            if self.profile is not None:
                terminate_profile_processes(self.profile)
        finally:
            if self.profile is not None:
                shutil.rmtree(self.profile, ignore_errors=True)


class BrowserDriver:
    """Async context owning one launched browser, or one manual-open prompt."""

    def __init__(self, plan: LaunchPlan, url: str) -> None:
        self.plan = plan
        self.url = url
        self.browser: LaunchedBrowser | None = None

    async def __aenter__(self) -> BrowserDriver:
        if self.plan.browser == "manual":
            print(f"open {self.url}", file=sys.stderr, flush=True)
        else:
            self.browser = LaunchedBrowser(self.plan, self.url).__enter__()
        return self

    async def __aexit__(self, *details: object) -> None:
        if self.browser is not None:
            self.browser.__exit__(*details)


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if sys.platform != "win32":
            os.killpg(process.pid, signal.SIGKILL)
        process.kill()
        process.wait(timeout=10)


def terminate_profile_processes(profile: Path) -> None:
    """Kill processes still using `profile` after their launcher exited.

    Browsers can re-parent their main process away from the launched process,
    so a process-tree kill alone does not prove the run's browser is gone.
    """
    if sys.platform != "win32":
        return
    # The profile path is a mkdtemp name without quotes, so it is safe to embed.
    script = (
        "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and "
        f"$_.CommandLine.Contains('{profile}') }} | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force "
        "-ErrorAction SilentlyContinue }"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=60,
    )
