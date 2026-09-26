"""Launch a browser with a disposable profile and record the exact launch."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
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
from .android_device import (
    ENTRIES as ANDROID_ENTRIES,
)

DESKTOP_CHROMIUM_BROWSERS = ("chrome", "edge", "brave", "opera")
# Android Chromium browsers take the same switches through a command-line file.
CHROMIUM_BROWSERS = (*DESKTOP_CHROMIUM_BROWSERS, *ANDROID_CHROMIUM_BROWSERS)
FIREFOX_BROWSERS = ("firefox", "firefox-android")
BROWSERS = (*DESKTOP_CHROMIUM_BROWSERS, "firefox", *ANDROID_BROWSERS)
PROFILE_PLACEHOLDER = "<temporary-profile>"
# Set by run_matrix.py when it runs tools side by side. Desktop Firefox
# processes that start at the same moment can each lose their page load, so
# launches then take turns until each has restored its first window.
LAUNCH_LOCK_DIRECTORY = "PHANTOM_CAPTURE_LOCK_DIR"
FIREFOX_STARTED_CHECKPOINT = "sessionstore-windows-restored"
FIREFOX_START_LIMIT_SECONDS = 15.0
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

# Switches a Chromium launch needs on one host OS only. On macOS a fresh
# profile otherwise reads and writes the browser's "Safe Storage" item in the
# login keychain, which belongs to the person's own browser profile.
HOST_CHROMIUM_FLAGS = {"darwin": ("--use-mock-keychain",)}


def host_chromium_flags(platform: str = sys.platform) -> tuple[str, ...]:
    return HOST_CHROMIUM_FLAGS.get(platform, ())


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
    arguments.extend(host_chromium_flags())
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


def add_browser_switch_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--browser-switch",
        action="append",
        default=[],
        metavar="SWITCH",
        help="extra Chromium switch, recorded in the launch arguments; "
        "pass as --browser-switch=--name=value and repeat for more",
    )


def check_browser_switches(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    if not args.browser_switch:
        return
    if args.browser not in CHROMIUM_BROWSERS:
        parser.error("--browser-switch applies to Chromium browsers only")
    if any(not switch.startswith("--") for switch in args.browser_switch):
        parser.error("each --browser-switch must start with --")


def add_android_entry_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--android-entry",
        choices=ANDROID_ENTRIES,
        default="typed",
        help="how an Android browser opens the page: typed into the address "
        "bar, or by a VIEW intent, which carries no user activation",
    )


def check_android_entry(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    if args.android_entry != "typed" and args.browser not in ANDROID_BROWSERS:
        parser.error("--android-entry applies to Android browsers only")


def with_android_entry(plan: LaunchPlan, entry: str) -> LaunchPlan:
    """`plan` opening its page by `entry`; a desktop plan is unchanged."""
    return replace(plan, android_entry=entry) if plan.android else plan


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
    # A run clears browser data; allow a device that is not an emulator.
    android_allow_physical_device: bool = False
    # Host TCP ports the device reaches on its own 127.0.0.1 through
    # `adb reverse`, besides those the URL and switches name.
    android_reverse_ports: tuple[int, ...] = ()

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
    def takes_turns(self) -> bool:
        """Whether a launch waits for the machine-wide Firefox launch lock."""
        return self.browser == "firefox" and bool(os.environ.get(LAUNCH_LOCK_DIRECTORY))

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
            allow_physical_device=self.plan.android_allow_physical_device,
            reverse=self.plan.android_reverse_ports,
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
            if self.plan.browser == "firefox":
                with launch_turn("firefox") as shared:
                    self.process = self._start(self.profile)
                    if shared:
                        wait_for_firefox_start(self.profile, self.process)
            else:
                self.process = self._start(self.profile)
        except BaseException:
            if self.process is not None:
                terminate_process_tree(self.process)
                self.process = None
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
            self.browser = await enter_browser(LaunchedBrowser(self.plan, self.url))
        return self

    async def __aexit__(self, *details: object) -> None:
        if self.browser is not None:
            self.browser.__exit__(*details)


async def enter_browser(browser: LaunchedBrowser) -> LaunchedBrowser:
    """Launch `browser` from a coroutine without stalling its event loop.

    A launch that takes turns can wait many seconds for the launch lock and
    for Firefox to start. That wait runs in a worker thread, so the tool's
    loopback server keeps answering, including the page Firefox requests
    before its start checkpoint is written. Other launches only spawn a
    process and stay on the loop, as before.
    """
    if not browser.plan.takes_turns:
        return browser.__enter__()
    guard = threading.Lock()
    state = {"entered": False, "abandoned": False}

    def enter() -> LaunchedBrowser:
        browser.__enter__()
        with guard:
            state["entered"] = True
            abandoned = state["abandoned"]
        if abandoned:
            browser.__exit__(None, None, None)
        return browser

    future = asyncio.get_running_loop().run_in_executor(None, enter)
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        # The launch finishes in its thread; whichever side sees it last
        # removes the browser.
        with guard:
            state["abandoned"] = True
            entered = state["entered"]
        if entered:
            browser.__exit__(None, None, None)
        raise


@contextmanager
def launch_turn(name: str) -> Iterator[bool]:
    """Hold the machine-wide `name` launch lock when a runner shares the host.

    Yields whether the lock is held; without `PHANTOM_CAPTURE_LOCK_DIR` the
    launch proceeds at once, as a tool run on its own always has.
    """
    directory = os.environ.get(LAUNCH_LOCK_DIRECTORY)
    if not directory:
        yield False
        return
    path = Path(directory) / f"{name}.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        lock_file(handle.fileno())
        try:
            yield True
        finally:
            unlock_file(handle.fileno())


def lock_file(descriptor: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        # LK_LOCK gives up after ten seconds, so poll the non-blocking form.
        # The lock covers byte 0, whatever the file's length.
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                time.sleep(0.05)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX)


def unlock_file(descriptor: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


def wait_for_firefox_start(profile: Path, process: subprocess.Popen[bytes]) -> None:
    """Wait until Firefox records that it restored its first window.

    Firefox writes the checkpoint to `sessionCheckpoints.json` in the profile
    at about the moment it requests the page. The wait ends early if the
    process exits, and after `FIREFOX_START_LIMIT_SECONDS` in any case.
    """
    checkpoints = profile / "sessionCheckpoints.json"
    deadline = time.monotonic() + FIREFOX_START_LIMIT_SECONDS
    while time.monotonic() < deadline and process.poll() is None:
        try:
            if FIREFOX_STARTED_CHECKPOINT in checkpoints.read_text(encoding="utf-8"):
                return
        except OSError:
            pass
        time.sleep(0.05)


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
        signal_process_group(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if sys.platform != "win32":
            signal_process_group(process.pid, signal.SIGKILL)
        process.kill()
        process.wait(timeout=10)


def signal_process_group(pid: int, signum: int) -> None:
    """Signal the session a launch started; it may already have exited."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signum)


def terminate_profile_processes(profile: Path) -> None:
    """Kill processes still using `profile` after their launcher exited.

    Browsers can re-parent their main process away from the launched process,
    so a process-tree kill alone does not prove the run's browser is gone.
    Only a process whose command line names this run's profile, or a path
    inside it, is killed. run_matrix.py passes a job's temporary directory,
    which holds every profile the job's tool created.
    """
    if sys.platform != "win32":
        listing = subprocess.run(
            ["ps", "-axww", "-o", "pid=,command="],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=60,
        ).stdout.decode(errors="replace")
        for pid in profile_process_ids(listing, profile, own_pid=os.getpid()):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
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


def profile_process_ids(listing: str, profile: Path, *, own_pid: int) -> list[int]:
    """Process ids in a `ps -o pid=,command=` listing that name `profile`.

    A mkdtemp profile name is unique to the run, so a match cannot be a
    browser the person started. The profile is matched as a whole path
    component, so `.../profile-x` does not match `.../profile-xy`.
    """
    text = str(profile).rstrip("/")
    ids = []
    for line in listing.splitlines():
        pid_text, _, command = line.strip().partition(" ")
        if not pid_text.isdigit() or int(pid_text) == own_pid:
            continue
        start = command.find(text)
        while start != -1:
            end = start + len(text)
            if end == len(command) or not (
                command[end].isalnum() or command[end] in "-_."
            ):
                ids.append(int(pid_text))
                break
            start = command.find(text, end)
    return ids
