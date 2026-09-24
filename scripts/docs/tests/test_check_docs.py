import contextlib
import io
import tempfile
import textwrap
import unittest
from pathlib import Path

from scripts.docs.check_docs import GUIDE_LINE_LIMIT, check, heading_slug, main

GOOD_PAGE = """\
# Title

What the reader can do here.

> For builders who have read [the start](a.md).

## Do a task

Text.

## Next

- [Start](a.md): where to begin.
"""


class RepoTestCase(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.write("README.md", "# Project\n\nText.\n")

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")

    def findings(self, rel: str, groups=("links", "shape", "prose")) -> list[str]:
        errors, _ = check(self.root, [rel], groups)
        return [f"{f.line}: {f.rule}" for f in errors]


class LinkTests(RepoTestCase):
    def test_accepts_existing_files_anchors_and_external_links(self) -> None:
        self.write(
            "docs/a.md",
            """\
            # A

            ## Set up `Client::new` (fast)

            <a id="custom"></a>

            [up](../README.md) [self](#set-up-clientnew-fast) [id](#custom)
            [web](https://example.com/missing.md) [mail](mailto:x@example.com)
            [dir](../docs/) [space](<b file.md>) [encoded](b%20file.md#b)
            """,
        )
        self.write("docs/b file.md", "# B\n")
        self.assertEqual(self.findings("docs/a.md", ["links"]), [])

    def test_reports_a_missing_file(self) -> None:
        self.write("docs/a.md", "# A\n\nSee [the guide](guide.md).\n")
        self.assertEqual(self.findings("docs/a.md", ["links"]), ["3: link"])

    def test_reports_a_missing_anchor(self) -> None:
        self.write("docs/a.md", "# A\n\n[x](../README.md#install)\n")
        self.assertEqual(self.findings("docs/a.md", ["links"]), ["3: anchor"])

    def test_numbers_duplicate_headings(self) -> None:
        self.write(
            "docs/a.md",
            "# A\n\n## Limits\n\n## Limits\n\n[a](#limits-1) [b](#limits-2)\n",
        )
        self.assertEqual(self.findings("docs/a.md", ["links"]), ["7: anchor"])

    def test_ignores_headings_and_links_in_fenced_code(self) -> None:
        self.write(
            "docs/a.md",
            """\
            # A

            ```markdown
            ## Hidden
            [broken](nowhere.md)
            ```

            [x](#hidden)
            """,
        )
        self.assertEqual(self.findings("docs/a.md", ["links"]), ["8: anchor"])

    def test_ignores_brackets_inside_code_spans(self) -> None:
        self.write(
            "docs/a.md",
            "# A\n\nUse `map[key](value)` and [`Vec<[u8]>`](../README.md).\n",
        )
        self.assertEqual(self.findings("docs/a.md", ["links"]), [])

    def test_checks_reference_definitions_and_link_text_across_lines(self) -> None:
        self.write(
            "docs/a.md",
            """\
            # A

            A [link that
            wraps](missing.md) and a [reference][ref].

            [ref]: ../README.md#nothing
            """,
        )
        self.assertEqual(
            self.findings("docs/a.md", ["links"]), ["3: link", "6: anchor"]
        )

    def test_checks_html_links_and_images(self) -> None:
        self.write(
            "docs/a.md",
            '# A\n\n<a href="gone.md">x</a> ![diagram](diagram.svg)\n',
        )
        self.assertEqual(self.findings("docs/a.md", ["links"]), ["3: link", "3: link"])

    def test_reports_links_that_leave_the_repository(self) -> None:
        self.write("docs/a.md", "# A\n\n[x](../../outside.md)\n")
        self.assertEqual(self.findings("docs/a.md", ["links"]), ["3: link"])

    def test_file_names_are_case_sensitive(self) -> None:
        self.write("docs/a.md", "# A\n\n[x](../readme.md)\n")
        self.assertEqual(self.findings("docs/a.md", ["links"]), ["3: link"])

    def test_llms_txt_gets_only_link_checks(self) -> None:
        self.write("llms.txt", "# P\n\nSimply read [here](missing.md)!\n")
        self.assertEqual(self.findings("llms.txt"), ["3: link"])

    def test_slug_follows_github_rules(self) -> None:
        self.assertEqual(
            heading_slug("HTTP/2 & `h2c`: [Setup](x.md)"), "http2--h2c-setup"
        )


class ShapeTests(RepoTestCase):
    def test_accepts_the_standard_page(self) -> None:
        self.write("docs/guides/a.md", GOOD_PAGE)
        self.assertEqual(self.findings("docs/guides/a.md"), [])

    def test_requires_one_leading_h1(self) -> None:
        self.write(
            "docs/a.md",
            GOOD_PAGE.replace("# Title", "## Title").replace("Text.", "# Two"),
        )
        self.assertEqual(self.findings("docs/a.md", ["shape"]), ["1: h1", "9: h1"])

    def test_reports_skipped_heading_levels(self) -> None:
        self.write("docs/a.md", GOOD_PAGE.replace("Text.", "#### Deep"))
        self.assertEqual(self.findings("docs/a.md", ["shape"]), ["9: heading-level"])

    def test_requires_a_reader_line_in_the_opening(self) -> None:
        self.write("docs/a.md", GOOD_PAGE.replace("> For", "For"))
        self.assertEqual(self.findings("docs/a.md", ["shape"]), ["1: banner"])

    def test_requires_a_final_next_section(self) -> None:
        self.write("docs/a.md", GOOD_PAGE + "\n## Limits\n\n- One.\n")
        self.assertEqual(self.findings("docs/a.md", ["shape"]), ["15: next"])

    def test_exempts_the_roadmap_index_and_top_level_pages(self) -> None:
        for rel in ("docs/roadmap.md", "docs/README.md", "CONTRIBUTING.md"):
            self.write(rel, "## No title\n\n#### Deep\n")
            self.assertEqual(self.findings(rel, ["shape"]), [], rel)

    def test_warns_about_long_guides_without_failing(self) -> None:
        self.write("docs/guides/a.md", GOOD_PAGE + "\ntext\n" * GUIDE_LINE_LIMIT)
        errors, warnings = check(self.root, ["docs/guides/a.md"])
        self.assertEqual(errors, [])
        self.assertEqual([w.rule for w in warnings], ["guide-length"])


class ProseTests(RepoTestCase):
    def test_reports_banned_words_and_their_inflections(self) -> None:
        self.write(
            "CONTRIBUTING.md",
            "# C\n\nA Robust client that leverages\nTLS and works seamlessly.\n",
        )
        self.assertEqual(
            self.findings("CONTRIBUTING.md"), ["3: word", "3: word", "4: word"]
        )

    def test_matches_whole_words_only(self) -> None:
        self.write(
            "CONTRIBUTING.md", "# C\n\nJustify the robustness of unlockable parts.\n"
        )
        self.assertEqual(self.findings("CONTRIBUTING.md"), [])

    def test_matches_phrases_across_line_breaks_once(self) -> None:
        self.write("CONTRIBUTING.md", "# C\n\nIt’s not\njust a client. Let's go.\n")
        self.assertEqual(self.findings("CONTRIBUTING.md"), ["3: word", "4: word"])

    def test_ignores_code_link_targets_and_urls(self) -> None:
        self.write(
            "CONTRIBUTING.md",
            """\
            # C

            Call `simply!()` and see [the page](robust.md) at
            https://example.com/seamless or <https://example.com/unlock>.

            ```rust
            // A robust example!
            ```
            """,
        )
        self.write("robust.md", "# R\n")
        self.assertEqual(self.findings("CONTRIBUTING.md"), [])

    def test_reports_em_dash_emoji_and_exclamation(self) -> None:
        self.write(
            "CONTRIBUTING.md",
            "# C\n\nFast — and done.\nShip it \U0001f680\nDone! But a != b.\n",
        )
        self.assertEqual(
            self.findings("CONTRIBUTING.md"),
            ["3: em-dash", "4: emoji", "5: exclamation"],
        )

    def test_reports_question_headings(self) -> None:
        self.write(
            "CONTRIBUTING.md", "# C\n\n## Why use it?\n\n## `Option<T>?` is fine\n"
        )
        self.assertEqual(self.findings("CONTRIBUTING.md"), ["3: heading-question"])

    def test_reports_vague_link_text(self) -> None:
        self.write(
            "CONTRIBUTING.md",
            "# C\n\n[here](README.md), [Click here](README.md), [link](README.md),\n"
            "[this](README.md), [the README](README.md), [`here`](README.md)\n",
        )
        self.assertEqual(
            self.findings("CONTRIBUTING.md"),
            ["3: link-text", "3: link-text", "3: link-text", "4: link-text"],
        )

    def test_roadmap_gets_no_prose_rules(self) -> None:
        self.write("docs/roadmap.md", "# R\n\nA robust plan!\n")
        self.assertEqual(self.findings("docs/roadmap.md"), [])


class AllowTests(RepoTestCase):
    def test_allow_comment_covers_the_next_line_only(self) -> None:
        self.write(
            "CONTRIBUTING.md",
            """\
            # C

            <!-- docs-check: allow robust, em-dash -->
            | "robust — quoted" | robust! |
            | robust |
            """,
        )
        self.assertEqual(
            self.findings("CONTRIBUTING.md"), ["4: exclamation", "5: word"]
        )

    def test_allow_region_covers_every_line_until_its_end(self) -> None:
        self.write(
            "CONTRIBUTING.md",
            """\
            # C

            <!-- docs-check: allow-begin word -->

            - Stock words: delve, robust,
              seamless, leverage.

            <!-- docs-check: allow-end -->

            Robust.
            """,
        )
        self.assertEqual(self.findings("CONTRIBUTING.md"), ["10: word"])

    def test_reports_malformed_directives(self) -> None:
        self.write(
            "CONTRIBUTING.md",
            "# C\n\n<!-- docs-check: allow -->\n\n<!-- docs-check: allow-begin word -->\n",
        )
        self.assertEqual(
            self.findings("CONTRIBUTING.md"), ["3: directive", "5: directive"]
        )

    def test_directive_inside_code_span_is_text(self) -> None:
        self.write(
            "CONTRIBUTING.md",
            "# C\n\nWrite `<!-- docs-check: allow word -->`\nrobust\n",
        )
        self.assertEqual(self.findings("CONTRIBUTING.md"), ["4: word"])


class CommandLineTests(RepoTestCase):
    def run_main(self, *args: str) -> tuple[int, str]:
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            status = main(["--root", str(self.root), *args])
        return status, output.getvalue()

    def test_prints_findings_and_fails(self) -> None:
        self.write("docs/a.md", "# A\n\nA robust [page](gone.md).\n")
        status, output = self.run_main()
        self.assertEqual(status, 1)
        self.assertIn("docs/a.md:3: link: gone.md does not exist\n", output)
        self.assertIn("docs/a.md:3: word: banned term 'robust'\n", output)

    def test_only_runs_the_selected_group(self) -> None:
        self.write("docs/a.md", GOOD_PAGE.replace("Text.", "A robust [page](gone.md)."))
        status, output = self.run_main("--only", "prose", str(self.root / "docs/a.md"))
        self.assertEqual(status, 1)
        self.assertEqual(output, "docs/a.md:9: word: banned term 'robust'\n")

    def test_passes_a_clean_tree(self) -> None:
        self.write("docs/guides/a.md", GOOD_PAGE)
        self.write(
            "scripts/tool/README.md",
            "# Tool\n\nSee [a](../../docs/guides/a.md#next).\n",
        )
        self.assertEqual(self.run_main(), (0, ""))


if __name__ == "__main__":
    unittest.main()
