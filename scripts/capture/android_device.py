"""Launch a browser on an Android device or emulator over adb.

A run stops every browser this module knows, clears the browser's app data
(`pm clear`), which is Android's fresh profile, and writes the browser's debug
configuration file. It then opens `about:blank` with a `VIEW` intent aimed at
the browser's package, focuses the address bar with Ctrl+L, types the page
URL, and presses Enter, so the page load is a user-typed navigation. A page
opened by another app's intent carries no user activation: Chrome then omits
`Sec-Fetch-User`. `entry="intent"` opens the page URL with the intent instead.
adb picks the device from `ANDROID_SERIAL` when more than one is attached.

The emulator reaches the host's loopback interface as `10.0.2.2`, over TCP
and UDP alike. Host-resolver rules that map a test name to `127.0.0.1` are
rewritten to that address, so QUIC reaches a host listener too. A URL or flag
that names the device's own loopback (`127.0.0.1` or `localhost`) with a port
gets an `adb reverse` for that port, which forwards TCP only.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

EMULATOR_HOST_LOOPBACK = "10.0.2.2"
DEVICE_DIRECTORY = "/data/local/tmp"
ENTRIES = ("typed", "intent")


def android_launch_mode(entry: str) -> str:
    """The fixture `launch_mode` of an Android run: how the page was opened."""
    if entry not in ENTRIES:
        raise ValueError(f"unknown entry: {entry}")
    return f"android-{entry}"


@dataclass(frozen=True)
class AndroidBrowser:
    package: str
    client_name: str
    # File under /data/local/tmp that Chromium reads its switches from when the
    # package is the device's debug app. None when the browser reads none.
    command_line_file: str | None = None
    # GeckoView reads `<package>-geckoview-config.yaml` there instead.
    gecko_config: bool = False

    @property
    def configuration_path(self) -> str | None:
        if self.command_line_file is not None:
            return f"{DEVICE_DIRECTORY}/{self.command_line_file}"
        if self.gecko_config:
            return f"{DEVICE_DIRECTORY}/{self.package}-geckoview-config.yaml"
        return None


ANDROID_BROWSERS = {
    "chrome-android": AndroidBrowser(
        "com.android.chrome", "Google Chrome", command_line_file="chrome-command-line"
    ),
    "edge-android": AndroidBrowser(
        "com.microsoft.emmx", "Microsoft Edge", command_line_file="chrome-command-line"
    ),
    "brave-android": AndroidBrowser(
        "com.brave.browser", "Brave", command_line_file="chrome-command-line"
    ),
    "opera-android": AndroidBrowser("com.opera.browser", "Opera"),
    "firefox-android": AndroidBrowser(
        "org.mozilla.firefox", "Mozilla Firefox", gecko_config=True
    ),
}
ANDROID_CHROMIUM_BROWSERS = tuple(
    name
    for name, browser in ANDROID_BROWSERS.items()
    if browser.command_line_file is not None
)

# Chrome for Android skips its first-run screens with this switch. The desktop
# flags in `browser_launch.CHROMIUM_FLAGS` follow it on the command line.
ANDROID_CHROMIUM_FIRST_RUN_FLAGS = ("--disable-fre",)

_RESOLVER_RULES = "--host-resolver-rules="
# `adb shell input text` turns `%s` into a space, so a typed URL avoids `%`,
# whitespace, and quotes.
_TYPEABLE_URL = re.compile(r"[A-Za-z0-9:/.?&=_~<>+,;@!*()\[\]-]+")
KEYCODE_CTRL_LEFT = "113"
KEYCODE_L = "40"
KEYCODE_ENTER = "66"
KEYCODE_A = "29"
KEYCODE_DEL = "67"
TYPING_CHUNK = 6
WINDOW_DUMP = "/sdcard/phantom-window.xml"
_LOOPBACK_PORT = re.compile(r"(?:127\.0\.0\.1|localhost|\[::1\]):(\d{1,5})\b")


def device_arguments(arguments: Sequence[str]) -> list[str]:
    """Point host-resolver rules at the emulator's route to host loopback."""
    rewritten = []
    for argument in arguments:
        if argument.startswith(_RESOLVER_RULES):
            rules = argument[len(_RESOLVER_RULES) :]
            rules = re.sub(
                r"(\bMAP\s+\S+\s+)127\.0\.0\.1\b",
                rf"\g<1>{EMULATOR_HOST_LOOPBACK}",
                rules,
            )
            argument = _RESOLVER_RULES + rules
        rewritten.append(argument)
    return rewritten


def reverse_ports(url: str, arguments: Sequence[str]) -> list[int]:
    """Device-loopback TCP ports named by the URL or the switches, in order."""
    ports: list[int] = []
    for text in (url, *arguments):
        if text.startswith(_RESOLVER_RULES):
            continue
        for match in _LOOPBACK_PORT.finditer(text):
            port = int(match.group(1))
            if 0 < port < 65536 and port not in ports:
                ports.append(port)
    return ports


def command_line_text(arguments: Sequence[str]) -> str:
    """Render a Chromium command-line file: a program name, then the switches."""
    return shlex.join(["_", *arguments]) + "\n"


def gecko_value(value: bool | int | str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def gecko_config_text(preferences: Sequence[tuple[str, bool | int | str]]) -> str:
    """Render GeckoView's debug configuration with `preferences` in order."""
    lines = ["prefs:"]
    lines.extend(f"  {name}: {gecko_value(value)}" for name, value in preferences)
    return "\n".join(lines) + "\n"


def focused_field_text(dump: str) -> str | None:
    """Return the `text` of the focused node in a `uiautomator dump`, if any."""
    try:
        root = ElementTree.fromstring(dump)
    except ElementTree.ParseError:
        return None
    for node in root.iter("node"):
        if node.get("focused") == "true":
            return node.get("text", "")
    return None


class TypingFailed(RuntimeError):
    """The address bar never held the whole typed URL; Enter was not pressed."""


class AdbDevice:
    """Runs adb commands against the device adb selects."""

    def __init__(self, adb: Path) -> None:
        self.adb = adb

    def run(self, *arguments: str, check: bool = True) -> str:
        completed = subprocess.run(
            [str(self.adb), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=120,
        )
        output = completed.stdout.decode("utf-8", "replace")
        if check and completed.returncode != 0:
            error = completed.stderr.decode("utf-8", "replace").strip()
            raise RuntimeError(f"adb {' '.join(arguments)} failed: {error or output}")
        return output

    def shell(self, *arguments: str, check: bool = True) -> str:
        return self.run("shell", *arguments, check=check)

    def push_text(self, text: str, device_path: str) -> None:
        with tempfile.TemporaryDirectory(prefix="phantom-adb-") as directory:
            local = Path(directory) / "file"
            local.write_bytes(text.encode("utf-8"))
            self.run("push", str(local), device_path)
        self.shell("chmod", "644", device_path)

    def package_version(self, package: str) -> str:
        for line in self.shell("dumpsys", "package", package).splitlines():
            line = line.strip()
            if line.startswith("versionName="):
                return line.removeprefix("versionName=")
        raise RuntimeError(f"{package} is not installed")


@dataclass(frozen=True)
class AndroidLaunch:
    browser: AndroidBrowser
    url: str
    arguments: tuple[str, ...] = ()
    preferences: tuple[tuple[str, bool | int | str], ...] = ()
    # "typed" types the URL into the address bar; "intent" opens it directly.
    entry: str = "typed"
    # Seconds to wait after clearing app data before the intent; a cleared
    # package can drop an intent sent while its process is still dying.
    settle: float = 1.0
    # Seconds between opening `about:blank` and typing: a cleared browser's
    # cold start can outlast `am start -W`, and keys sent earlier are lost.
    typing_delay: float = 6.0
    # Seconds to wait for the address bar to hold the whole typed URL, and how
    # many cleared-profile launches to try before giving up.
    typing_timeout: float = 150.0
    typing_attempts: int = 3

    def __post_init__(self) -> None:
        if self.entry not in ENTRIES:
            raise ValueError(f"unknown entry: {self.entry}")
        if self.entry == "typed" and not _TYPEABLE_URL.fullmatch(self.url):
            raise ValueError(f"cannot type this URL with adb input: {self.url}")

    def configuration(self) -> str | None:
        if self.browser.command_line_file is not None:
            return command_line_text(self.arguments)
        if self.browser.gecko_config:
            if self.arguments:
                raise ValueError("GeckoView takes preferences, not switches")
            return gecko_config_text(self.preferences)
        if self.arguments or self.preferences:
            raise ValueError(
                f"{self.browser.package} reads no debug configuration, so it "
                "cannot apply the requested switches or preferences"
            )
        return None


class AndroidSession:
    """One browser run on a cleared profile, stopped and cleaned up on exit."""

    def __init__(self, device: AdbDevice, launch: AndroidLaunch) -> None:
        self.device = device
        self.launch = launch
        self.reversed: list[int] = []
        self.configured = False

    def __enter__(self) -> AndroidSession:
        try:
            self._start()
        except BaseException:
            self.__exit__()
            raise
        return self

    def _start(self) -> None:
        launch = self.launch
        package = launch.browser.package
        configuration = launch.configuration()
        for other in ANDROID_BROWSERS.values():
            self.device.shell("am", "force-stop", other.package)
        # Ends cached background processes, so the browser has the memory.
        self.device.shell("am", "kill-all", check=False)
        self.device.shell("pm", "clear", package)
        # Without it a cleared Chrome opens a notification prompt over the page.
        self.device.shell(
            "pm", "grant", package, "android.permission.POST_NOTIFICATIONS", check=False
        )
        path = launch.browser.configuration_path
        if configuration is not None and path is not None:
            self.device.push_text(configuration, path)
            self.configured = True
            self.device.shell("am", "set-debug-app", "--persistent", package)
        for port in reverse_ports(launch.url, launch.arguments):
            self.device.run("reverse", f"tcp:{port}", f"tcp:{port}")
            self.reversed.append(port)
        for attempt in range(launch.typing_attempts):
            try:
                self._open(package)
                return
            except TypingFailed:
                if attempt + 1 == launch.typing_attempts:
                    raise
                # Enter was never pressed. Start over from a cleared profile.
                self.device.shell("am", "force-stop", package)
                self.device.shell("pm", "clear", package)
                self.device.shell(
                    "pm",
                    "grant",
                    package,
                    "android.permission.POST_NOTIFICATIONS",
                    check=False,
                )

    def _open(self, package: str) -> None:
        launch = self.launch
        time.sleep(launch.settle)
        target = launch.url if launch.entry == "intent" else "about:blank"
        self.device.shell(
            "am",
            "start",
            "-W",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            shlex.quote(target),
            "-p",
            package,
        )
        if launch.entry == "typed":
            time.sleep(launch.typing_delay)
            self.device.shell("input", "keycombination", KEYCODE_CTRL_LEFT, KEYCODE_L)
            time.sleep(1.0)
            self.type_url()
            self.device.shell("input", "keyevent", KEYCODE_ENTER)

    def focused_text(self) -> str | None:
        """The text of the focused field on screen, from a window dump."""
        self.device.shell("uiautomator", "dump", WINDOW_DUMP, check=False)
        dumped = self.device.shell("cat", WINDOW_DUMP, check=False)
        return focused_field_text(dumped)

    def type_url(self) -> None:
        """Type the URL in short chunks until the focused field holds it exactly.

        A loaded device drops keys while the address bar redraws its
        suggestions, and Enter pressed on a partial URL would run a search. Each
        chunk is followed by a window dump. The address bar may append a
        selected inline completion to what was typed; the next key replaces
        it, and after the last chunk one Delete removes it. When the focused
        field is empty or does not start with a prefix of the URL, Ctrl+L
        focuses the address bar, Ctrl+A and Delete clear it, and typing
        starts again.
        """
        url = self.launch.url
        deadline = time.monotonic() + self.launch.typing_timeout
        typed = ""
        while True:
            pending = len(url)
            if typed != url:
                chunk = url[len(typed) : len(typed) + TYPING_CHUNK]
                self.device.shell("input", "text", shlex.quote(chunk))
                pending = len(typed) + len(chunk)
                time.sleep(0.5)
            current = self.focused_text()
            if current == url:
                return
            if time.monotonic() >= deadline:
                raise TypingFailed("the address bar never held the typed URL")
            if current and current.startswith(url[:pending]):
                typed = url[:pending]
                if typed == url:
                    # Only an inline completion follows the whole URL.
                    self.device.shell("input", "keyevent", KEYCODE_DEL)
            elif current and url.startswith(current):
                typed = current
            else:
                # The field lost focus, lost every key, or holds other text:
                # focus the address bar again, select its text, and clear it.
                self.device.shell(
                    "input", "keycombination", KEYCODE_CTRL_LEFT, KEYCODE_L
                )
                time.sleep(1.0)
                self.device.shell(
                    "input", "keycombination", KEYCODE_CTRL_LEFT, KEYCODE_A
                )
                self.device.shell("input", "keyevent", KEYCODE_DEL)
                typed = ""

    def __exit__(self, *_: object) -> None:
        package = self.launch.browser.package
        self.device.shell("am", "force-stop", package, check=False)
        for port in self.reversed:
            self.device.run("reverse", "--remove", f"tcp:{port}", check=False)
        self.reversed.clear()
        path = self.launch.browser.configuration_path
        if self.configured and path is not None:
            self.device.shell("rm", "-f", path, check=False)
            self.device.shell("am", "clear-debug-app", check=False)
            self.configured = False
