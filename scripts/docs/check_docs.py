"""Check Phantom's Markdown against the documentation contract.

The rules come from docs/internals/documentation.md: relative links and
anchors resolve, pages under docs/ open and close in the standard shape, and
prose avoids the words and marks that page bans. Each finding prints as
`path:line: rule: message`; any error exits with status 1.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parents[2]

# The "Do not write these" list in docs/internals/documentation.md, less the
# words it bans only in some senses ("navigate", "ecosystem"). A single word
# also matches its inflections ("leverages", "robustly", not "robustness"); a
# phrase matches as written, across a line break.
BANNED_TERMS = (
    "delve",
    "robust",
    "seamless",
    "leverage",
    "powerful",
    "comprehensive",
    "crucial",
    "cutting-edge",
    "effortless",
    "unlock",
    "elevate",
    "streamline",
    "landscape",
    "journey",
    "simply",
    "just",
    "easily",
    "in summary",
    "that's it",
    "let's",
    "in today's world",
    "whether you're",
    "it's not just",
    "not just",
)

# Link text that says nothing about the destination.
VAGUE_LINK_TEXT = frozenset({"click here", "here", "link", "this"})

# The `> For ...` reader line must come before the first section heading and
# within this many lines: a title, a blank line, and a two-sentence opening.
BANNER_WINDOW = 12
GUIDE_LINE_LIMIT = 200

GROUPS = ("links", "shape", "prose")

LINKS_ONLY = frozenset({"llms.txt"})
NO_PROSE = frozenset({"docs/roadmap.md"})
NO_SHAPE = frozenset({"docs/roadmap.md", "docs/README.md"})

# Placeholder for masked characters: not a word character, not punctuation
# that any rule looks for.
MASK = "\x1a"

FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
HEADING = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$")
REFERENCE_DEFINITION = re.compile(r"^ {0,3}\[([^\]^][^\]]*)\]:[ \t]*(<[^>\n]*>|\S+)")
DIRECTIVE = re.compile(r"<!--\s*docs-check:\s*(allow-begin|allow-end|allow)\b(.*?)-->")
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
HREF = re.compile(r"""<a\s[^>]*?\bhref\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
HTML_ID = re.compile(r"""<[A-Za-z][^>]*?\s(?:id|name)\s*=\s*["']([^"']+)["']""")
ESCAPE = re.compile(r"\\[!-/:-@\[-`{-~]")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
AUTOLINK = re.compile(r"<[A-Za-z][A-Za-z0-9+.-]*:[^>\s]*>")
BARE_URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://\S+")
HTML_TAG = re.compile(r"</?[A-Za-z][^>]*>")
EXCLAMATION = re.compile(r"!(?!=)")


def _term_pattern(term: str) -> str:
    words = [re.escape(word).replace("'", "['\u2019]") for word in term.split()]
    if len(words) == 1 and "'" not in term and not term.endswith("y"):
        if term.endswith("e"):
            words[0] = re.escape(term[:-1]) + "(?:e|es|ed|ing|ely)"
        else:
            words[0] += "(?:s|ed|ing|ly)?"
    return r"\b" + r"\s+".join(words) + r"\b"


# Longest terms first, so "it's not just" is reported once, not also as
# "not just".
_ORDERED_TERMS = sorted(BANNED_TERMS, key=len, reverse=True)
BANNED = re.compile(
    "|".join(f"(?P<t{i}>{_term_pattern(t)})" for i, t in enumerate(_ORDERED_TERMS)),
    re.IGNORECASE,
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str
    message: str
    key: str = field(default="", compare=False)

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.message}"


@dataclass(frozen=True)
class Link:
    text: str
    dest: str | None
    offset: int
    image: bool


@dataclass
class Page:
    """One Markdown file split into what each rule reads."""

    lines: list[str]
    code: list[bool]
    headings: list[tuple[int, int, str]]
    # (line index, text) blocks with code spans, escapes, and comments masked.
    blocks: list[tuple[int, str]]
    references: list[tuple[int, str]]
    allowed: list[set[str]]
    errors: list[tuple[int, str]]


def is_emoji(char: str) -> bool:
    point = ord(char)
    return (
        0x1F000 <= point <= 0x1FAFF
        or 0x2600 <= point <= 0x27BF
        or point in (0x231A, 0x231B, 0x2B1B, 0x2B1C, 0x2B50, 0x2B55, 0xFE0F)
        or 0x23E9 <= point <= 0x23FA
    )


def code_mask(lines: Sequence[str]) -> list[bool]:
    """Marks the lines that belong to fenced code blocks, fences included."""
    mask = []
    fence: str | None = None
    for line in lines:
        match = FENCE.match(line)
        if fence is None:
            if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
                fence = match.group(1)
                mask.append(True)
            else:
                mask.append(False)
        else:
            mask.append(True)
            if (
                match
                and match.group(1)[0] == fence[0]
                and len(match.group(1)) >= len(fence)
                and not match.group(2).strip()
            ):
                fence = None
    return mask


def mask_code_spans(text: str) -> str:
    """Replaces inline code spans, backticks included, with MASK."""
    out = []
    i = 0
    while i < len(text):
        if text[i] != "`":
            out.append(text[i])
            i += 1
            continue
        run = len(text[i:]) - len(text[i:].lstrip("`"))
        start = i
        i += run
        closer = re.compile(rf"(?<!`)`{{{run}}}(?!`)")
        match = closer.search(text, i)
        if match is None:
            out.append(text[start:i])
            continue
        out.append(_mask(text[start : match.end()]))
        i = match.end()
    return "".join(out)


def _mask(text: str) -> str:
    return "".join(c if c == "\n" else MASK for c in text)


def _match_bracket(text: str, start: int) -> int | None:
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                return i
    return None


def _parse_destination(text: str, i: int) -> tuple[str, int] | None:
    """Parses `dest "title")` from just after `(`; returns dest and the end."""
    n = len(text)
    while i < n and text[i] in " \t\n":
        i += 1
    if i < n and text[i] == "<":
        close = text.find(">", i)
        if close == -1 or "\n" in text[i:close] or "<" in text[i + 1 : close]:
            return None
        dest = text[i + 1 : close]
        i = close + 1
    else:
        depth = 0
        start = i
        while i < n and text[i] not in " \t\n":
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                if depth == 0:
                    break
                depth -= 1
            i += 1
        dest = text[start:i]
    while i < n and text[i] in " \t\n":
        i += 1
    if i < n and text[i] in "\"'(":
        closer = ")" if text[i] == "(" else text[i]
        close = text.find(closer, i + 1)
        if close == -1:
            return None
        i = close + 1
        while i < n and text[i] in " \t\n":
            i += 1
    if i < n and text[i] == ")":
        return dest, i + 1
    return None


def scan_links(text: str) -> list[tuple[int, int, Link]]:
    """Finds the outermost links in a masked block as (start, end, link)."""
    found = []
    i = 0
    while i < len(text):
        if text[i] != "[":
            i += 1
            continue
        close = _match_bracket(text, i)
        if close is None:
            i += 1
            continue
        image = i > 0 and text[i - 1] == "!"
        start = i - 1 if image else i
        label = text[i + 1 : close]
        after = close + 1
        if after < len(text) and text[after] == "(":
            parsed = _parse_destination(text, after + 1)
            if parsed is not None:
                dest, end = parsed
                found.append((start, end, Link(label, dest, i, image)))
                i = end
                continue
        elif after < len(text) and text[after] == "[":
            label_close = text.find("]", after + 1)
            if label_close != -1 and "[" not in text[after + 1 : label_close]:
                end = label_close + 1
                found.append((start, end, Link(label, None, i, image)))
                i = end
                continue
        i += 1
    return found


def all_links(text: str, base: int = 0) -> Iterable[Link]:
    """Yields every link in a masked block, nested ones included."""
    for _, _, link in scan_links(text):
        yield Link(link.text, link.dest, base + link.offset, link.image)
        yield from all_links(link.text, base + link.offset + 1)


def render(text: str) -> str:
    """Replaces links with their text, keeping the number of lines."""
    out = []
    last = 0
    for start, end, link in scan_links(text):
        out.append(text[last:start])
        inner = render(link.text)
        out.append(inner + "\n" * (text.count("\n", start, end) - inner.count("\n")))
        last = end
    out.append(text[last:])
    rendered = "".join(out)
    for pattern in (AUTOLINK, BARE_URL, HTML_TAG):
        rendered = pattern.sub(lambda m: _mask(m.group(0)), rendered)
    return rendered


def heading_slug(text: str) -> str:
    """GitHub's anchor for a heading: rendered text, lowercased, punctuation
    dropped, each space a hyphen."""
    text = re.sub(r"`+", "", text)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = HTML_TAG.sub("", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def parse(text: str) -> Page:
    lines = text.splitlines()
    code = code_mask(lines)
    headings = []
    references = []
    visible = []
    for index, line in enumerate(lines):
        if code[index]:
            visible.append("")
            continue
        heading = HEADING.match(line)
        if heading:
            headings.append((index, len(heading.group(1)), heading.group(2) or ""))
        reference = REFERENCE_DEFINITION.match(line)
        if reference:
            references.append((index, reference.group(2).strip("<>")))
            visible.append("")
            continue
        visible.append(line)

    # Blocks are runs of non-blank lines; a heading is a block of its own.
    heading_lines = {index for index, _, _ in headings}
    blocks = []
    current: list[str] = []
    start = 0
    for index, line in enumerate([*visible, ""]):
        if not line.strip() or index in heading_lines:
            if current:
                blocks.append((start, "\n".join(current)))
                current = []
            if line.strip():
                blocks.append((index, line))
            continue
        if not current:
            start = index
        current.append(line)

    allowed: list[set[str]] = [set() for _ in lines]
    errors = []
    masked_blocks = []
    region: tuple[int, set[str]] | None = None
    for start, block in blocks:
        block = mask_code_spans(ESCAPE.sub(lambda m: MASK * 2, block))
        for match in DIRECTIVE.finditer(block):
            line = start + block.count("\n", 0, match.start())
            kind = match.group(1)
            items = {i.strip().lower() for i in match.group(2).split(",") if i.strip()}
            if kind == "allow-end":
                if region is None:
                    errors.append((line, "allow-end without allow-begin"))
                    continue
                for target in range(region[0], line + 1):
                    allowed[target] |= region[1]
                region = None
            elif not items:
                errors.append((line, f"{kind} names nothing to allow"))
            elif kind == "allow-begin":
                if region is not None:
                    errors.append((line, "allow-begin inside another allow-begin"))
                region = (line, items)
            else:
                for target in (line, line + 1):
                    if target < len(allowed):
                        allowed[target] |= items
        masked_blocks.append((start, COMMENT.sub(lambda m: _mask(m.group(0)), block)))
    if region is not None:
        errors.append((region[0], "allow-begin without allow-end"))
    return Page(lines, code, headings, masked_blocks, references, allowed, errors)


Report = Callable[..., None]


class Checker:
    def __init__(self, root: Path, groups: Iterable[str] = GROUPS) -> None:
        self.root = root.resolve()
        self.groups = frozenset(groups)
        self._pages: dict[Path, Page] = {}
        self._anchors: dict[Path, set[str]] = {}

    def page(self, path: Path) -> Page:
        if path not in self._pages:
            self._pages[path] = parse(path.read_text(encoding="utf-8"))
        return self._pages[path]

    def anchors(self, path: Path) -> set[str]:
        if path not in self._anchors:
            page = self.page(path)
            found = set()
            counts: dict[str, int] = {}
            for _, _, text in page.headings:
                slug = heading_slug(text)
                count = counts.get(slug, 0)
                counts[slug] = count + 1
                found.add(slug if count == 0 else f"{slug}-{count}")
            for line, is_code in zip(page.lines, page.code, strict=True):
                if not is_code:
                    found.update(HTML_ID.findall(line))
            self._anchors[path] = found
        return self._anchors[path]

    def check(self, rel: str) -> tuple[list[Finding], list[Finding]]:
        page = self.page(self.root / rel)
        errors: list[Finding] = []
        warnings: list[Finding] = []

        def report(index: int, rule: str, message: str, key: str = "") -> None:
            allowed = page.allowed[index] if index < len(page.allowed) else set()
            if rule in allowed or (key and key in allowed):
                return
            errors.append(Finding(rel, index + 1, rule, message, key))

        for index, message in page.errors:
            errors.append(Finding(rel, index + 1, "directive", message))

        links = [
            (start + block.count("\n", 0, link.offset), link)
            for start, block in page.blocks
            for link in all_links(block)
        ]
        if "links" in self.groups:
            targets = [(i, link.dest) for i, link in links if link.dest is not None]
            targets += page.references
            targets += [
                (start + block.count("\n", 0, m.start()), m.group(1))
                for start, block in page.blocks
                for m in HREF.finditer(block)
            ]
            for index, dest in sorted(targets):
                problem = self.resolve(rel, dest)
                if problem:
                    report(index, *problem)

        prose = rel not in LINKS_ONLY and rel not in NO_PROSE
        if "prose" in self.groups and prose:
            for index, link in links:
                words = " ".join(re.sub(r"[\W_]+", " ", link.text).split()).lower()
                if (
                    not link.image
                    and MASK not in link.text
                    and words in VAGUE_LINK_TEXT
                ):
                    report(
                        index,
                        "link-text",
                        f"link text {link.text!r} does not name the target",
                    )
            heading_lines = {index for index, _, _ in page.headings}
            for start, block in page.blocks:
                text = render(block)
                _check_prose(start, text, report)
                if start in heading_lines and text.rstrip(" #").endswith("?"):
                    report(start, "heading-question", "heading is a question")

        shape = rel.startswith("docs/") and rel not in NO_SHAPE
        if "shape" in self.groups and shape:
            _check_shape(page, report)
            if rel.startswith("docs/guides/") and len(page.lines) > GUIDE_LINE_LIMIT:
                message = f"warning: {len(page.lines)} lines; aim for at most {GUIDE_LINE_LIMIT}"
                warnings.append(
                    Finding(rel, GUIDE_LINE_LIMIT + 1, "guide-length", message)
                )
        return errors, warnings

    def resolve(self, rel: str, dest: str) -> tuple[str, str] | None:
        """Returns (rule, message) when a link destination does not resolve."""
        dest = dest.strip()
        if not dest:
            return "link", "empty link destination"
        if SCHEME.match(dest) or dest.startswith("//"):
            return None
        path_part, _, fragment = dest.partition("#")
        path_part = unquote(path_part.partition("?")[0])
        source = self.root / rel
        if not path_part:
            target = source
        elif path_part.startswith("/"):
            target = self.root / path_part.lstrip("/")
        else:
            target = source.parent / path_part
        target = Path(os.path.normpath(target))
        try:
            relative = target.relative_to(self.root)
        except ValueError:
            return "link", f"{dest} leaves the repository"
        if not _exists_exact_case(self.root, relative.parts):
            return "link", f"{dest} does not exist"
        if (
            fragment
            and target.suffix == ".md"
            and target.is_file()
            and unquote(fragment) not in self.anchors(target)
        ):
            return "anchor", f"{dest} has no anchor #{fragment}"
        return None


def _check_prose(start: int, text: str, report: Report) -> None:
    def line(offset: int) -> int:
        return start + text.count("\n", 0, offset)

    for match in BANNED.finditer(text):
        term = _ORDERED_TERMS[int(match.lastgroup[1:])]
        report(line(match.start()), "word", f"banned term {match.group(0)!r}", term)
    for offset, char in enumerate(text):
        if char == "—":
            report(
                line(offset),
                "em-dash",
                "em-dash; use a colon, parentheses, or a new sentence",
            )
        elif is_emoji(char):
            report(line(offset), "emoji", f"emoji U+{ord(char):04X}")
    for match in EXCLAMATION.finditer(text):
        report(line(match.start()), "exclamation", "exclamation mark in prose")


def _check_shape(page: Page, report: Report) -> None:
    if not page.headings:
        report(0, "h1", "page has no H1")
        return
    first = page.headings[0]
    if first[1] != 1:
        report(first[0], "h1", f"first heading is H{first[1]}, expected H1")
    previous = first[1]
    for index, level, _ in page.headings[1:]:
        if level == 1:
            report(index, "h1", "second H1; a page has exactly one")
        elif level > previous + 1:
            report(index, "heading-level", f"H{level} follows H{previous}")
        previous = level
    opening = page.headings[1][0] if len(page.headings) > 1 else len(page.lines)
    if not any(
        not page.code[i] and re.match(r">\s*For\s", line)
        for i, line in enumerate(page.lines[: min(opening, BANNER_WINDOW)])
    ):
        report(0, "banner", "no '> For ...' reader line before the first section")
    last = page.headings[-1]
    if last[1] != 2 or last[2].strip() != "Next":
        report(last[0], "next", "the last section must be '## Next'")


def _exists_exact_case(root: Path, parts: Sequence[str]) -> bool:
    """Path existence with case-sensitive names, as on the Linux CI runner."""
    current = root
    for part in parts:
        try:
            if part not in os.listdir(current):
                return False
        except (NotADirectoryError, FileNotFoundError):
            return False
        current = current / part
    return True


def default_files(root: Path) -> list[str]:
    """The documentation set: top-level pages, docs/, and script READMEs."""
    files = [
        name
        for name in ("README.md", "CONTRIBUTING.md", "llms.txt")
        if (root / name).is_file()
    ]
    files += sorted(
        p.relative_to(root).as_posix() for p in (root / "docs").rglob("*.md")
    )
    files += sorted(
        p.relative_to(root).as_posix() for p in root.glob("scripts/*/README.md")
    )
    return files


def check(
    root: Path, files: Sequence[str] | None = None, groups: Iterable[str] = GROUPS
) -> tuple[list[Finding], list[Finding]]:
    """Checks the files (default: the documentation set); returns errors and warnings."""
    checker = Checker(root, groups)
    errors: list[Finding] = []
    warnings: list[Finding] = []
    for rel in files if files is not None else default_files(checker.root):
        file_errors, file_warnings = checker.check(rel)
        errors += file_errors
        warnings += file_warnings
    return sorted(errors), sorted(warnings)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "paths", nargs="*", help="files to check (default: the documentation set)"
    )
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    parser.add_argument(
        "--only",
        action="append",
        choices=GROUPS,
        help="run only this group of rules; repeat for more",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    files = None
    if args.paths:
        files = []
        for name in args.paths:
            try:
                files.append(Path(name).resolve().relative_to(root).as_posix())
            except ValueError:
                parser.error(f"{name} is outside {root}")
    errors, warnings = check(root, files, args.only or GROUPS)
    for finding in [*errors, *warnings]:
        print(finding)
    print(f"{len(errors)} error(s), {len(warnings)} warning(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
