"""Merge a crate's integration test files into a few test binaries.

Each top-level `tests/<name>.rs` becomes the module `tests/<group>/<name>.rs`
of the test binary `<group>`, as `GROUPS` assigns it, and each directory that
the file includes moves with it. `tests/support/` stays in place and becomes
one `support` module that every group loads once, instead of a copy per test
file. The script rewrites the paths, feature gates, and imports that the move
changes, regenerates each `main.rs` and `tests/support/mod.rs`, and rewrites
`crates/<crate>/tests/<name>` references in tracked text files.

A few binaries rather than one: stable rustc type-checks a crate on one
thread. With all 51 files in one binary, a one-line test edit took about 50 s
to rebuild with `-j 4`; with five groups it takes about 9 s, and a library
edit rebuilds the groups in parallel.

It is idempotent: run it again after a branch adds or changes a top-level
test file, and only the new files move. A new file needs an entry in
`GROUPS`. Uses `git mv`, so run it from a clean worktree and review the diff.

Usage: python scripts/dev/consolidate_integration_tests.py [crate-dir ...]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Test binary -> (what it covers, its modules), per crate. Keep the groups
# near equal in size: the largest one bounds a rebuild after a library edit.
GROUPS: dict[str, dict[str, tuple[str, list[str]]]] = {
    "crates/phantom": {
        "requests": (
            "one request through the public client: fields, bodies, redirects, "
            "retries, and timeouts",
            [
                "client",
                "client_hints",
                "connection_retries",
                "content_coding",
                "cookie_crumbs",
                "cookies",
                "diagnostics",
                "direct_http",
                "plaintext_templates",
                "redirects",
                "request_templates",
                "stale_connection_replay",
                "status_retry",
                "timeouts",
                "unprocessed_replay",
            ],
        ),
        "sessions": (
            "name resolution, connection reuse, pooling, and negotiation across "
            "requests",
            [
                "dns_overrides",
                "http2_connections",
                "negotiated",
                "negotiated_parallel",
                "session",
                "session_http1",
                "session_http1_parallel",
                "session_http2_authority",
                "session_http2_lifecycle",
                "session_http3",
                "session_tls_resumption",
            ],
        ),
        "http3": (
            "HTTP/3, Alt-Svc upgrades, HTTPS records, and CONNECT-UDP",
            [
                "alt_svc_frames",
                "alt_svc_persistence",
                "alt_svc_race",
                "connect_udp",
                "http3",
                "http3_early_data",
                "http3_retries",
                "http3_session_resumption",
                "http3_upgrade",
                "http3_upgrade_socks5",
                "https_record_ech",
                "https_record_ech_exact",
                "https_record_ech_http3",
                "https_records",
            ],
        ),
        "proxies": (
            "HTTP CONNECT, forwarding, and SOCKS5 proxy routes",
            [
                "forward_proxy",
                "negotiated_proxy",
                "proxy",
                "proxy_credential_cache",
                "proxy_field_order",
                "proxy_h2",
                "proxy_h2_multiplex",
                "socks5",
                "socks5_local",
            ],
        ),
        "streams": (
            "WebSocket and server-sent event streams",
            [
                "sse",
                "sse_browser_reconnect",
                "websocket",
                "websocket_http2",
                "websocket_http2_proxy",
                "websocket_profile",
                "websocket_trust",
            ],
        ),
    },
    "crates/phantom-profile": {
        "public_api": (
            "profile construction through the public API",
            ["http3_public_api", "quic_public_api"],
        ),
    },
}
TEXT_SUFFIXES = {".md", ".rs", ".txt", ".yml", ".yaml", ".sh", ".py", ".toml"}
SKIP_PREFIXES = ("vendor/", "fixtures/", "target/")
# Attribute lines followed by `mod name;`, at the start of a line.
MOD_DECL = re.compile(
    r"(?P<attrs>(?:^[ \t]*#\[[^\n]*\][ \t]*\n)+)[ \t]*mod (?P<name>\w+);[ \t]*\n",
    re.M,
)
PATH_ATTR = re.compile(r'#\[path = "(?P<path>[^"]+)"\]')
INNER_CFG = re.compile(r"^#!\[cfg\((?P<cond>.*)\)\][ \t]*\n", re.M)
OUTER_CFG = re.compile(r"^#\[cfg\((?P<cond>.*)\)\]$")
SUPPORT_USE = re.compile(
    r"(?P<attrs>(?:^[ \t]*#\[[^\n]*\][ \t]*\n)*)[ \t]*use crate::support::(?P<stem>\w+)"
    r"(?: as (?P<alias>\w+))?;",
    re.M,
)
MAIN_MOD = re.compile(r"(?:^#\[cfg\((?P<cond>.*)\)\]\n)?^mod (?P<name>\w+);", re.M)
# A `[[test]]` table: its header line and each line before the next header.
TEST_TABLE = re.compile(r"^\[\[test\]\][ \t]*\n(?:(?![ \t]*\[)[^\n]*\n)*", re.M)
TABLE_KEY = re.compile(r"^[ \t]*(?P<key>[\w-]+)[ \t]*=", re.M)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def read(path: Path) -> str:
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def write(path: Path, text: str) -> None:
    """Writes `text`, keeping CRLF if the file had it (core.autocrlf=true)."""
    crlf = path.exists() and b"\r\n" in path.read_bytes()
    newline = "\r\n" if crlf else "\n"
    path.write_bytes(text.replace("\n", newline).encode("utf-8"))


def fail(message: str) -> None:
    sys.exit(f"consolidate_integration_tests: {message}")


def owned_files(module: Path) -> dict[Path, str]:
    """Maps each file a module pulls in with `#[path]` to its module name.

    Support files are excluded.
    """
    files = {}
    for decl in MOD_DECL.finditer(read(module)):
        path = PATH_ATTR.search(decl["attrs"])
        if path and not path["path"].startswith("support/"):
            files[(module.parent / path["path"]).resolve()] = decl["name"]
    return files


def shared_children(modules: list[Path]) -> dict[Path, tuple[str, str]]:
    """Maps each file that several modules include to its owner and name.

    The first module in name order owns the file; the others import it, since
    a file loaded as two modules compiles twice (`clippy::duplicate_mod`).
    """
    users: dict[Path, list[tuple[str, str]]] = {}
    for module in sorted(modules):
        for child, decl_name in owned_files(module).items():
            users.setdefault(child, []).append((module.stem, decl_name))
    return {child: found[0] for child, found in users.items() if len(found) > 1}


def without_attrs(attrs: list[str]) -> str:
    """Keeps the attributes of a `mod` item that still apply to a `use`."""
    return "".join(
        a
        for a in attrs
        if not PATH_ATTR.search(a) and a.strip() != "#[allow(dead_code)]"
    )


USE_ITEM = re.compile(r"^[ \t]*(?:pub(?:\([a-z]+\))? )?use [^;]*;", re.M | re.S)


def module_path_used(text: str, siblings: str, name: str) -> bool:
    """Reports whether `name` is used as a module path in a test module.

    Paths inside other `use` trees name some other crate's module, such as
    `phantom_testkit::{tls::...}`, so only a `use` that starts with `name::`
    counts. Child files reach the module through `super::`.
    """
    outside_use = USE_ITEM.sub("", text)
    return bool(
        re.search(rf"(?<![\w:.]){name}::", outside_use)
        or re.search(rf"^[ \t]*use {name}::", text, re.M)
        or re.search(rf"\b{name}\b", siblings)
    )


def rewrite_module(
    module: Path, name: str, shared: dict[Path, tuple[str, str]]
) -> str | None:
    """Rewrites a moved test file and returns its feature gate."""
    text = read(module)
    cond = None
    gate = INNER_CFG.search(text)
    if gate:
        cond = gate["cond"]
        text = text[: gate.start()] + text[gate.end() :]

    # `crate::` meant this file's root; it is now the module `crate::<name>`.
    children = owned_files(module)
    root_ref = re.compile(r"(?<![$\w])crate::(?!support::)")
    text = root_ref.sub(f"crate::{name}::", text)
    for child in sorted(children):
        body = read(child)
        if child in shared and root_ref.search(body):
            fail(f"{child} uses `crate::`, and more than one test file includes it")
        if shared.get(child, (name,))[0] == name:
            write(child, root_ref.sub(f"crate::{name}::", body))

    def replace(decl: re.Match[str]) -> str:
        attrs = decl["attrs"].splitlines(keepends=True)
        path = next((m for a in attrs if (m := PATH_ATTR.search(a))), None)
        if not path:
            return decl.group(0)
        local = decl["name"]
        if path["path"].startswith("support/"):
            stem = Path(path["path"]).stem
            target = stem if local == stem else f"{stem} as {local}"
            return without_attrs(attrs) + f"use crate::support::{target};\n"
        owner = shared.get((module.parent / path["path"]).resolve())
        if owner is None:
            return decl.group(0)
        owner_module, owner_name = owner
        if owner_module == name:
            return decl.group(0).replace(f"mod {local};", f"pub(crate) mod {local};")
        target = owner_name if local == owner_name else f"{owner_name} as {local}"
        return without_attrs(attrs) + f"use crate::{owner_module}::{target};\n"

    text = MOD_DECL.sub(replace, text)

    # Drop imports that only existed so an included support file could reach a
    # sibling through `crate::` or `super::`; the shared module does not need
    # them. Renames such as `use tls_support as tls;` go first, since they are
    # what keeps the support import in use.
    siblings = "".join(read(p) for p in children)
    local_support = {u["alias"] or u["stem"] for u in SUPPORT_USE.finditer(text)}
    renames = re.compile(r"^use (?P<src>\w+) as (?P<alias>\w+);\n", re.M)
    for pattern, local_of in (
        (renames, lambda m: m["alias"] if m["src"] in local_support else None),
        (SUPPORT_USE, lambda m: m["alias"] or m["stem"]),
    ):
        original = text
        for use in pattern.finditer(original):
            local = local_of(use)
            if local is not None and not module_path_used(
                original[: use.start()] + original[use.end() :], siblings, local
            ):
                text = text.replace(use.group(0).rstrip("\n") + "\n", "", 1)
    write(module, text)
    return cond


def rewrite_support(path: Path, aliases: dict[str, str]) -> None:
    text = read(path)
    for alias, stem in aliases.items():
        text = re.sub(rf"\bcrate::{alias}\b", f"crate::support::{stem}", text)
        text = re.sub(rf"\bsuper::{alias}\b", f"super::{stem}", text)
    # `super` was the including test file; it is now the `support` module.
    text = text.replace("pub(super)", "pub(crate)")
    stray = re.search(r"(?<![$\w])crate::(?!support::)\w+", text)
    if stray:
        fail(f"{path}: `{stray.group(0)}` names an item of the including test file")
    write(path, text)


def collect_aliases(files: list[Path]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for path in files:
        text = read(path)
        found = []
        for decl in MOD_DECL.finditer(text):
            attr = PATH_ATTR.search(decl["attrs"])
            if attr and attr["path"].startswith("support/"):
                found.append((decl["name"], Path(attr["path"]).stem))
        for use in SUPPORT_USE.finditer(text):
            found.append((use["alias"] or use["stem"], use["stem"]))
        for alias, stem in found:
            if aliases.setdefault(alias, stem) != stem:
                fail(
                    f"{path}: `{alias}` names both support/{aliases[alias]}.rs and {stem}.rs"
                )
    return aliases


def cfg_expr(conds: list[str | None]) -> str | None:
    if not conds or any(c is None for c in conds):
        return None
    unique = sorted(set(conds))  # type: ignore[arg-type]
    return unique[0] if len(unique) == 1 else f"any({', '.join(unique)})"


def and_cfg(a: str | None, b: str | None) -> str | None:
    if a is None or b is None:
        return a or b
    return a if a == b else f"all({a}, {b})"


def target_gates(manifest: Path, stems: set[str]) -> dict[str, str]:
    """Turns the `[[test]]` tables of moving files into `cfg` gates.

    A moved file is a module, not a target, so its table goes. Its
    `required-features` becomes the module's `cfg`, so a build without them
    still skips its tests. No other setting has a module equivalent.
    """
    text = read(manifest)
    if re.search(r"^[ \t]*autotests[ \t]*=[ \t]*false", text, re.M):
        fail(f"{manifest} sets autotests = false; add the group targets by hand")
    gates: dict[str, str] = {}
    moving = []
    for table in TEST_TABLE.finditer(text):
        body = table.group(0)
        name = re.search(r'^[ \t]*name[ \t]*=[ \t]*"(?P<name>[^"]+)"', body, re.M)
        if name is None or name["name"] not in stems:
            continue
        stem = name["name"]
        for key in TABLE_KEY.finditer(body):
            if key["key"] not in {"name", "path", "required-features"}:
                fail(f"{manifest}: test `{stem}` sets `{key['key']}`; move it by hand")
        path = re.search(r'^[ \t]*path[ \t]*=[ \t]*"(?P<path>[^"]+)"', body, re.M)
        if path and path["path"] != f"tests/{stem}.rs":
            fail(f"{manifest}: test `{stem}` has path {path['path']}; move it by hand")
        features = re.search(
            r"^[ \t]*required-features[ \t]*=[ \t]*\[(?P<list>[^\]]*)\]", body, re.M
        )
        conds = (
            [f'feature = "{f}"' for f in re.findall(r'"([^"]+)"', features["list"])]
            if features
            else []
        )
        if conds:
            gates[stem] = conds[0] if len(conds) == 1 else f"all({', '.join(conds)})"
        moving.append(table)
    for table in reversed(moving):
        text = text[: table.start()] + text[table.end() :]
    if moving:
        write(manifest, re.sub(r"\n{3,}", "\n\n", text))
    return gates


def support_gates(
    support: Path, modules: dict[Path, str | None]
) -> dict[str, str | None]:
    """Gates each support file on the features of every module that uses it."""
    stems = sorted(p.stem for p in support.glob("*.rs") if p.name != "mod.rs")
    direct: dict[str, list[str | None]] = {stem: [] for stem in stems}
    users: dict[str, set[str]] = {stem: set() for stem in stems}
    for module, cond in modules.items():
        for path in [module, *owned_files(module)]:
            for use in SUPPORT_USE.finditer(read(path)):
                attr_cfg = None
                for line in use["attrs"].splitlines():
                    gate = OUTER_CFG.match(line.strip())
                    if gate:
                        attr_cfg = gate["cond"]
                direct[use["stem"]].append(and_cfg(cond, attr_cfg))
    for stem in stems:
        for ref in re.finditer(
            r"\b(?:crate::support|super)::(\w+)", read(support / f"{stem}.rs")
        ):
            if ref[1] in users and ref[1] != stem:
                users[ref[1]].add(stem)

    resolved: dict[str, str | None] = {}

    def resolve(stem: str, seen: frozenset[str]) -> str | None:
        if stem not in resolved:
            conds = list(direct[stem])
            conds += [resolve(user, seen | {stem}) for user in users[stem] - seen]
            resolved[stem] = cfg_expr(conds)
        return resolved[stem]

    return {stem: resolve(stem, frozenset()) for stem in stems}


def write_main(
    group_dir: Path, crate: str, about: str, module_cfg: dict[str, str | None]
) -> None:
    lines = [
        f"//! `{crate}` integration tests: {about}.",
        "//!",
        "//! Each module covers one area of the public API.",
    ]
    if (group_dir.parent / "support").is_dir():
        lines[-1] += " `support` holds the loopback"
        lines.append("//! servers and helpers that the crate's test binaries share.")
        lines += ["", '#[path = "../support/mod.rs"]', "mod support;"]
    lines.append("")
    for name in sorted(module_cfg):
        if module_cfg[name]:
            lines.append(f"#[cfg({module_cfg[name]})]")
        lines.append(f"mod {name};")
    write(group_dir / "main.rs", "\n".join(lines) + "\n")


def write_support_mod(support: Path, gates: dict[str, str | None]) -> None:
    lines = [
        "//! Loopback servers, fixtures, and helpers shared by the test binaries.",
        "",
        "// Each helper serves some of the modules, so each binary and each build",
        "// without every feature leaves some of them unused.",
        "#![allow(dead_code)]",
        "",
    ]
    for stem in sorted(gates):
        if gates[stem]:
            lines.append(f"#[cfg({gates[stem]})]")
        lines.append(f"pub(crate) mod {stem};")
    write(support / "mod.rs", "\n".join(lines) + "\n")


def rewrite_references(crate_dir: str, placed: dict[str, str]) -> None:
    """Rewrites `crates/<crate>/tests/<name>` paths to the name's group."""
    if not placed:
        return
    names = "|".join(sorted(placed, key=len, reverse=True))
    qualified = re.compile(rf"\b{re.escape(crate_dir)}/tests/(?=({names})(?:\.rs\b|/))")
    local = re.compile(rf"(?<![\w/])tests/(?=({names})(?:\.rs\b|/))")
    for rel in git("ls-files").splitlines():
        path = Path(rel)
        if path.suffix not in TEXT_SUFFIXES or rel.startswith(SKIP_PREFIXES):
            continue
        if not path.is_file():
            continue
        text = read(path)
        new = qualified.sub(lambda m: f"{crate_dir}/tests/{placed[m[1]]}/", text)
        if rel.startswith(crate_dir + "/"):
            new = local.sub(lambda m: f"tests/{placed[m[1]]}/", new)
        if new != text:
            write(path, new)
        for use in re.finditer(rf"--test[ =]({names})\b", new):
            print(f"{rel}: update `{use[0]}` to `--test {placed[use[1]]} {use[1]}::`")


def consolidate(crate_dir: str) -> None:
    tests = Path(crate_dir) / "tests"
    support = tests / "support"
    crate = re.search(r'^name = "([^"]+)"', read(Path(crate_dir) / "Cargo.toml"), re.M)
    if crate is None:
        fail(f"{crate_dir}/Cargo.toml has no package name")
    groups = GROUPS[crate_dir]
    group_for = {m: g for g, (_, members) in groups.items() for m in members}
    tops = sorted(tests.glob("*.rs"))
    manifest = Path(crate_dir) / "Cargo.toml"
    unplaced = [p.stem for p in tops if p.stem not in group_for]
    if unplaced:
        fail(f"add {', '.join(unplaced)} to a group of {crate_dir} in GROUPS")
    if not tops:
        print(f"{crate_dir}: nothing to move")
        return
    required = target_gates(manifest, {p.stem for p in tops})

    # Modules already in place keep the gates their `main.rs` gives them.
    module_cfg: dict[str, str | None] = {}
    for group in groups:
        main = tests / group / "main.rs"
        if main.exists():
            for decl in MAIN_MOD.finditer(read(main)):
                if decl["name"] != "support":
                    module_cfg[decl["name"]] = decl["cond"]

    # Each directory that a moving file includes moves into that file's group.
    placed_dirs: dict[str, str] = {}
    for top in tops:
        for child in owned_files(top):
            rel = child.relative_to(tests.resolve())
            if rel.parts[0] == "support" or len(rel.parts) < 2:
                continue
            group = group_for[top.stem]
            if placed_dirs.setdefault(rel.parts[0], group) != group:
                fail(f"tests/{rel.parts[0]}/ is used by more than one test binary")
    for name, group in sorted(placed_dirs.items()):
        src = tests / name
        if not src.is_dir():
            continue
        # Move through a temporary name: a group can share a directory's name.
        staging = tests / f"{name}.moving"
        git("mv", str(src), str(staging))
        (tests / group).mkdir(exist_ok=True)
        git("mv", str(staging), str(tests / group / name))

    moved: list[Path] = []
    for src in tops:
        dst = tests / group_for[src.stem] / src.name
        if dst.exists():
            fail(f"{dst} already exists; merge {src} by hand")
        dst.parent.mkdir(exist_ok=True)
        git("mv", str(src), str(dst))
        moved.append(dst)

    # Support files are rewritten once, when they first become a module.
    listed: set[str] = set()
    if (support / "mod.rs").exists():
        listed = set(re.findall(r"mod (\w+);", read(support / "mod.rs")))
    existing = [tests / group_for[m] / f"{m}.rs" for m in module_cfg]
    aliases = collect_aliases([*moved, *existing])
    for path in sorted(support.glob("*.rs")):
        if path.name != "mod.rs" and path.stem not in listed:
            rewrite_support(path, aliases)

    shared = shared_children(moved)
    for module in moved:
        cond = rewrite_module(module, module.stem, shared)
        module_cfg[module.stem] = and_cfg(cond, required.get(module.stem))
    for child, (owner, _) in shared.items():
        for module in moved:
            if f"crate::{owner}::" not in read(module):
                continue
            if group_for[module.stem] != group_for[owner]:
                fail(f"{module.stem} and {owner} share {child} across test binaries")
            if module_cfg[module.stem] != module_cfg[owner]:
                fail(f"{module.stem} imports {child} from {owner} under another gate")

    for group, (about, members) in groups.items():
        gates = {m: module_cfg[m] for m in members if m in module_cfg}
        if gates:
            write_main(tests / group, crate[1], about, gates)
    if support.is_dir():
        paths = {tests / group_for[m] / f"{m}.rs": c for m, c in module_cfg.items()}
        write_support_mod(support, support_gates(support, paths))

    rewrite_references(
        crate_dir, {p.stem: group_for[p.stem] for p in moved} | placed_dirs
    )
    for group in groups:
        main = tests / group / "main.rs"
        if main.exists():
            subprocess.run(["rustfmt", "--edition", "2024", str(main)], check=True)
            git("add", "--", str(tests / group))
    if support.is_dir():
        git("add", "--", str(support))
    git("add", "--", str(manifest))
    print(
        f"{crate_dir}: moved {len(moved)} test files and {len(placed_dirs)} directories"
    )


def main() -> None:
    root = Path(git("rev-parse", "--show-toplevel").strip())
    if Path.cwd().resolve() != root.resolve():
        fail(f"run from the repository root, {root}")
    for crate_dir in sys.argv[1:] or GROUPS:
        consolidate(crate_dir.rstrip("/"))


if __name__ == "__main__":
    main()
