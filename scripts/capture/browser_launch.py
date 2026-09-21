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

CHROMIUM_BROWSERS = ("chrome", "edge")
BROWSERS = (*CHROMIUM_BROWSERS, "firefox")
PROFILE_PLACEHOLDER = "<temporary-profile>"
CLIENT_NAMES = {
    "chrome": "Google Chrome",
    "edge": "Microsoft Edge",
    "firefox": "Mozilla Firefox",
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
)

# Firefox has no equivalent command-line switches; these preferences disable
# the same classes of background traffic in the disposable profile.
FIREFOX_PREFERENCES = (
    ("app.update.disabledForTesting", True),
    ("browser.aboutwelcome.enabled", False),
    ("browser.newtabpage.enabled", False),
    ("browser.safebrowsing.malware.enabled", False),
    ("browser.safebrowsing.phishing.enabled", False),
    ("browser.shell.checkDefaultBrowser", False),
    ("browser.startup.homepage_override.mstone", "ignore"),
    ("datareporting.policy.dataSubmissionEnabled", False),
    ("extensions.update.enabled", False),
    ("network.captive-portal-service.enabled", False),
    ("network.connectivity-service.enabled", False),
    ("network.proxy.type", 0),
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
    arguments.extend(["--no-remote", "--profile", str(profile)])
    arguments.extend(extra)
    arguments.append(url)
    return arguments


def firefox_user_js() -> str:
    lines = []
    for name, value in FIREFOX_PREFERENCES:
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, int):
            rendered = str(value)
        else:
            rendered = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        lines.append(f'user_pref("{name}", {rendered});')
    return "\n".join(lines) + "\n"


def browser_arguments(
    browser: str, profile: Path, url: str, *, headless: bool, extra: Sequence[str]
) -> list[str]:
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

    @property
    def launch_mode(self) -> str:
        if self.browser == "manual":
            return "manual"
        return "headless" if self.headless else "headful"

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
    """One browser process on a fresh profile, removed with its process tree."""

    def __init__(self, plan: LaunchPlan, url: str) -> None:
        if plan.browser == "manual":
            raise ValueError("manual launches have no browser process")
        if plan.executable is None:
            raise ValueError("a browser executable is required")
        self.plan = plan
        self.url = url
        self.profile: Path | None = None
        self.process: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> LaunchedBrowser:
        self.profile = Path(tempfile.mkdtemp(prefix="phantom-capture-profile-"))
        if self.plan.browser == "firefox":
            (self.profile / "user.js").write_text(firefox_user_js(), encoding="utf-8")
        arguments = browser_arguments(
            self.plan.browser,
            self.profile,
            self.url,
            headless=self.plan.headless,
            extra=self.plan.extra_arguments,
        )
        options: dict[str, object] = {}
        if sys.platform != "win32":
            options["start_new_session"] = True
        self.process = subprocess.Popen(
            [str(self.plan.executable), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **options,
        )
        return self

    def __exit__(self, *_: object) -> None:
        try:
            if self.process is not None:
                terminate_process_tree(self.process)
        finally:
            if self.profile is not None:
                shutil.rmtree(self.profile, ignore_errors=True)


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
