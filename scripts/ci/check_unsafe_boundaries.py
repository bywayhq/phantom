"""Inspect source lint attributes, not cfg evaluation or macro expansion."""

import re
import subprocess
import sys
from pathlib import Path

AUDITED_MODULES = {
    "crates/phantom-quic-btls/src/lib.rs": ("backend",),
    "crates/phantom-net/src/lib.rs": (
        "socket_ffi",
        "system_dns_ffi",
        "linux_dns_ffi",
        "macos_dns_ffi",
    ),
    "bindings/go/native/src/lib.rs": ("ffi",),
    "bindings/node/src/lib.rs": ("ffi",),
}
IDENTIFIER = re.compile(r"(?:r#)?(?:[^\W\d]|_)\w*")
COMMENT_MARKER = re.compile(r"/\*|\*/")
RAW_STRING = re.compile(r'(?:br|cr|r)(#*)"')
CHARACTER = re.compile(
    r"(?:b)?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[^\r\n])|[^'\\\r\n])'"
)
PAIRS = {"(": ")", "[": "]", "{": "}"}


def tokens(source: str) -> tuple[list[str], dict[int, int]]:
    """Keep delimiters/identifiers while making comments and literals opaque."""
    result: list[str] = []
    closing: dict[int, int] = {}
    groups: list[int] = []
    at = 0
    while at < len(source):
        if source[at].isspace():
            at += 1
            continue
        if source.startswith("//", at):
            end = source.find("\n", at)
            at = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", at):
            depth = 1
            at += 2
            while depth:
                next_marker = COMMENT_MARKER.search(source, at)
                if next_marker is None:
                    raise ValueError("unterminated block comment")
                at = next_marker.end()
                depth += 1 if next_marker.group() == "/*" else -1
            continue
        raw = RAW_STRING.match(source, at)
        character = CHARACTER.match(source, at)
        if raw:
            end_marker = '"' + raw[1]
            end = source.find(end_marker, raw.end())
            if end < 0:
                raise ValueError("unterminated raw string")
            at = end + len(end_marker)
            value = "<literal>"
        elif character:
            at = character.end()
            value = "<literal>"
        elif source[at] == '"' or source[at : at + 2] in ('b"', 'c"'):
            at += 1 if source[at] == '"' else 2
            while at < len(source) and source[at] != '"':
                at += 2 if source[at] == "\\" else 1
            if at >= len(source):
                raise ValueError("unterminated string")
            at += 1
            value = "<literal>"
        else:
            identifier = IDENTIFIER.match(source, at)
            if identifier:
                at = identifier.end()
                value = identifier.group().removeprefix("r#")
            else:
                value = source[at]
                at += 1
        index = len(result)
        result.append(value)
        if value in PAIRS:
            groups.append(index)
        elif value in PAIRS.values():
            if not groups or PAIRS[result[groups[-1]]] != value:
                raise ValueError("unbalanced delimiter")
            closing[groups.pop()] = index
    if groups:
        raise ValueError("unterminated delimiter")
    return result, closing


def arguments(
    source: list[str], closing: dict[int, int], start: int, end: int
) -> list[tuple[int, int]]:
    """Split a single meta-item list without interpreting nested predicates."""
    result = []
    at = start
    while at < end:
        if source[at] == ",":
            result.append((start, at))
            start = at + 1
        at = closing.get(at, at) + 1
    if start < end:
        result.append((start, end))
    return result


def allowances(source: list[str], closing: dict[int, int], start: int, end: int) -> int:
    """Inspect allow/expect, including every source branch of cfg_attr."""
    pending = [(start, end)]
    count = 0
    while pending:
        start, end = pending.pop()
        if end - start < 3 or source[start + 1] != "(":
            continue
        if closing[start + 1] != end - 1:
            continue
        name = source[start]
        items = arguments(source, closing, start + 2, end - 1)
        if name in ("allow", "expect"):
            count += sum(
                right == left + 1 and source[left] == "unsafe_code"
                for left, right in items
            )
        elif name == "cfg_attr":
            pending.extend(items[1:])
    return count


def attribute_end(source: list[str], closing: dict[int, int], at: int) -> int | None:
    if source[at] != "#":
        return None
    at += 1
    if at < len(source) and source[at] == "!":
        at += 1
    if at < len(source) and source[at] == "[":
        return closing[at]
    return None


def source_allowances(source: str) -> list[str | None]:
    """Return an allowed target only for a private, out-of-line root module."""
    lexed, closing = tokens(source)
    result: list[str | None] = []
    depth = 0
    at = 0
    while at < len(lexed):
        end = attribute_end(lexed, closing, at)
        if end is not None:
            inner = lexed[at + 1] == "!"
            count = allowances(lexed, closing, at + (3 if inner else 2), end)
            target = None
            after = end + 1
            while after < len(lexed):
                next_end = attribute_end(lexed, closing, after)
                if next_end is None:
                    break
                after = next_end + 1
            declaration = lexed[after : after + 3]
            if (
                not inner
                and depth == 0
                and len(declaration) == 3
                and declaration[0] == "mod"
                and declaration[2] == ";"
            ):
                target = declaration[1]
            result.extend([target] * count)
            at = end + 1
            continue
        value = lexed[at]
        if value in PAIRS:
            depth += 1
        elif value in PAIRS.values():
            depth -= 1
        at += 1
    return result


def check(root: Path) -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.rs", ":!vendor"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    found: dict[str, list[str | None]] = {}
    for raw_path in listed.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = raw_path.decode("utf-8")
        source = (root / path).read_text(encoding="utf-8")
        # No relevant lint can be present without this identifier, even raw.
        if "unsafe_code" in source:
            try:
                found[path] = source_allowances(source)
            except ValueError as error:
                raise ValueError(f"{path}: {error}") from error
    failures = []
    for path, modules in AUDITED_MODULES.items():
        actual = found.get(path, [])
        if len(actual) != len(modules):
            failures.append(
                f"expected {len(modules)} unsafe_code allowance(s) in {path}"
            )
        if sorted(target or "" for target in actual) != sorted(modules):
            failures.append(
                f"unsafe_code allowance moved outside audited declarations in {path}"
            )
    for path, actual in found.items():
        if actual and path not in AUDITED_MODULES:
            failures.append(
                f"unsafe_code is allowed outside the audited FFI modules: {path}"
            )
    return failures


def main() -> int:
    try:
        failures = check(Path.cwd())
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"unsafe boundary source scan failed: {error}", file=sys.stderr)
        return 2
    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
