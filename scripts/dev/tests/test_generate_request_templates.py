"""Ordered immutable templates and their exact catalog binding boundaries."""

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from unittest import mock

from scripts.dev.profile_catalog import cli, declarations
from scripts.dev.profile_catalog import request_template as domain


def literal(name="accept", value="*/*"):
    return {"variant": "Literal", "name": name, "value": value}


def empty_values():
    return {
        "http1_fields": [],
        "http2_fields": [],
        "http3_fields": None,
        "http2_priority": None,
        "requested_client_hint_placement": False,
        "restarts_for_connection_accept_ch": False,
    }


def document(value=None):
    return {
        "schema": 1,
        "templates": [
            {
                "id": "test",
                "base": None,
                "values": empty_values() if value is None else value,
            }
        ],
    }


class TemplateDeclarationTests(unittest.TestCase):
    def setUp(self):
        self.actual = declarations.read_document(cli.REQUEST_TEMPLATE_RECORDS)

    def reject(self, value):
        with self.assertRaises(declarations.DeclarationError):
            domain.validate_templates(value)

    def reject_fields(self, fields, protocol=1):
        value = empty_values()
        value[f"http{protocol}_fields"] = fields
        self.reject(document(value))

    def test_current_bindings_retain_all_ordered_field_records(self):
        templates = domain.validate_templates(self.actual)
        profiles = cli.load()
        domain.validate_template_bindings(profiles, templates)
        self.assertEqual(len(templates), 40)
        self.assertEqual(sum(len(row["templates"]) for row in profiles), 56)
        for target in ("FirefoxWindows157R2", "FirefoxWindows157"):
            firefox = next(row for row in profiles if row["target"] == target)
            self.assertEqual(
                firefox["templates"],
                {
                    "Fetch": "firefox_windows157_fetch",
                    "FetchNoStore": "firefox_windows157_fetch_no_store",
                    "FetchUpload": "firefox_windows157_fetch_upload",
                    "Navigation": "firefox_windows157_navigation",
                },
            )
        chrome156 = next(row for row in profiles if row["target"] == "ChromeWindows156")
        self.assertEqual(
            chrome156["templates"],
            {
                "Navigation": "chrome_windows156_navigation",
                "Script": "chrome_windows156_script",
                "Stylesheet": "chrome_windows156_stylesheet",
                "Image": "chrome_windows156_image",
                "Font": "chrome_windows156_font",
            },
        )
        navigation = templates["chrome_windows156_navigation"]
        self.assertEqual(
            [
                len(navigation[name])
                for name in ("http1_fields", "http2_fields", "http3_fields")
            ],
            [14, 13, 12],
        )
        for protocol in ("http1_fields", "http2_fields", "http3_fields"):
            fields = {
                field["name"].lower(): field["value"]
                for field in navigation[protocol]
                if field["variant"] == "Literal"
            }
            self.assertEqual(
                fields["user-agent"],
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
            )
            self.assertEqual(
                fields["accept"],
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7",
            )
        original = [
            row
            for row in profiles
            if row["target"]
            not in (
                "EdgeWindows153",
                "ChromeMacos154",
                "ChromeLinux156",
                "ChromeMacos156",
                "ChromeMacos156Intel",
            )
            and row["metadata"]["identity"]["kind"] == "Observed"
        ]
        count = sum(
            len(templates[identifier][name] or [])
            for profile in original
            for identifier in profile["templates"].values()
            for name in ("http1_fields", "http2_fields", "http3_fields")
        )
        self.assertEqual(count, 1187)
        self.assertEqual(
            domain.generate_templates(templates),
            cli.REQUEST_TEMPLATE_OUTPUT.read_text(encoding="utf-8"),
        )

    def test_alt_used_is_a_single_http3_unit_slot(self):
        slot = {"variant": "AltUsed"}
        value = empty_values()
        value["http3_fields"] = [slot]
        domain.validate_templates(document(value))
        for fields, protocol in (
            ([slot], 1),
            ([slot], 2),
            ([slot, slot], 3),
            ([{**slot, "name": "alt-used"}], 3),
            ([literal("alt-used", "spoofed")], 3),
        ):
            with self.subTest(fields=fields, protocol=protocol):
                self.reject_fields(fields, protocol)

    def test_alt_used_is_not_a_cross_protocol_hint_anchor(self):
        fields = [
            {"variant": "ClientHints"},
            {"variant": "RestartClientHints"},
            literal("x-end"),
        ]
        h3 = copy.deepcopy(fields)
        h3.insert(2, {"variant": "AltUsed"})
        value = empty_values()
        value.update(http1_fields=fields, http2_fields=fields, http3_fields=h3)
        domain.validate_templates(document(value))
        self.assertEqual(domain.hint_signature(fields), domain.hint_signature(h3))
        self.assertEqual(domain.restart_signature(fields), domain.restart_signature(h3))

    def test_generation_is_independent_of_declaration_and_object_order(self):
        expected = domain.generate_templates(domain.validate_templates(self.actual))
        reordered = copy.deepcopy(self.actual)
        reordered["templates"].reverse()
        for entry in reordered["templates"]:
            value = entry["values"]
            entry["values"] = dict(reversed(list(value.items())))
            if value.get("http2_priority") is not None:
                entry["values"]["http2_priority"] = dict(
                    reversed(list(value["http2_priority"].items()))
                )
        self.assertEqual(
            domain.generate_templates(domain.validate_templates(reordered)), expected
        )

    def test_field_arrays_are_not_sorted(self):
        value = empty_values()
        value["http1_fields"] = [literal("z"), literal("a")]
        value["http2_fields"] = [literal("a"), literal("z")]
        resolved = domain.validate_templates(document(value))["test"]
        self.assertEqual(resolved["http1_fields"], value["http1_fields"])
        self.assertEqual(resolved["http2_fields"], value["http2_fields"])
        output = domain.generate_templates({"test": resolved})
        self.assertLess(output.index('name: "z"'), output.index('name: "a"'))

    def test_unknown_and_missing_schema_keys_are_rejected(self):
        for path in ((), ("templates", 0), ("templates", 0, "values")):
            for change in ("add", "remove"):
                value = document()
                selected = value
                for key in path:
                    selected = selected[key]
                if change == "add":
                    selected["unexpected"] = True
                else:
                    selected.pop(next(iter(selected)))
                with self.subTest(path=path, change=change):
                    self.reject(value)

    def test_wrong_schema_types_ids_and_duplicate_ids_are_rejected(self):
        for schema in (True, 0, 2, None, "1"):
            value = document()
            value["schema"] = schema
            self.reject(value)
        for identifier in ("", "self", "bad-name", "Bad", None, 1, "x" * 65):
            value = document()
            value["templates"][0]["id"] = identifier
            self.reject(value)
        value = document()
        value["templates"] *= 2
        self.reject(value)

    def test_unknown_variants_and_variant_keys_are_rejected(self):
        for entry in (
            {"variant": "Automatic"},
            {"variant": "ClientHints", "name": "x"},
            {"variant": "Caller", "name": "x"},
            {"variant": "Literal", "name": "x", "value": "ok", "required": False},
            None,
            "literal",
        ):
            self.reject_fields([entry])

    def test_field_names_require_bounded_ascii_tokens(self):
        for name in (
            None,
            0,
            "",
            "x y",
            "x:y",
            "x\n",
            "é",
            "x" * (declarations.MAX_STRING + 1),
        ):
            self.reject_fields([literal(name)])
        self.reject_fields([{"variant": "Caller", "name": None, "required": False}])
        self.reject_fields([{"variant": "ClientHint", "name": None}])
        value = empty_values()
        value["http1_fields"] = [literal("X-Token_!#$%&'*+-.^`|~")]
        domain.validate_templates(document(value))

    def test_values_preserve_empty_tabs_and_escaping(self):
        for content in ("", "\t", 'a"b\\c'):
            value = empty_values()
            value["http1_fields"] = [literal(value=content)]
            resolved = domain.validate_templates(document(value))
            self.assertEqual(resolved["test"]["http1_fields"][0]["value"], content)
            self.assertIn(json.dumps(content), domain.generate_templates(resolved))
        for content in (
            None,
            1,
            "\n",
            "\r",
            "\x7f",
            "é",
            "\ud800",
            "x" * (declarations.MAX_STRING + 1),
        ):
            self.reject_fields([literal(value=content)])

    def test_absent_and_empty_http3_remain_distinct_without_added_flag_rules(self):
        for fields in (None, []):
            value = empty_values()
            value["http3_fields"] = fields
            value["requested_client_hint_placement"] = True
            value["restarts_for_connection_accept_ch"] = True
            resolved = domain.validate_templates(document(value))
            self.assertEqual(resolved["test"]["http3_fields"], fields)
            self.assertIn(
                "http3_fields: " + ("None" if fields is None else "Some(&[])"),
                domain.generate_templates(resolved),
            )

    def test_boolean_fields_reject_integer_or_string_substitutes(self):
        for name in domain.TEMPLATE_FIELDS[-2:]:
            for item in (0, 1, "true", None):
                value = empty_values()
                value[name] = item
                self.reject(document(value))
        self.reject_fields([{"variant": "Caller", "name": "x", "required": 1}])

    def test_priority_matches_native_dependency_weight_and_boolean_bounds(self):
        for weight in (1, 256):
            value = empty_values()
            value["http2_priority"] = {
                "variant": "Fixed",
                "dependency_stream_id": 0,
                "weight": weight,
                "exclusive": False,
            }
            domain.validate_templates(document(value))
        for name, item in (
            ("dependency_stream_id", 1),
            ("dependency_stream_id", False),
            ("weight", 0),
            ("weight", 257),
            ("weight", True),
            ("exclusive", 1),
        ):
            value = empty_values()
            value["http2_priority"] = {
                "variant": "Fixed",
                "dependency_stream_id": 0,
                "weight": 1,
                "exclusive": False,
            }
            value["http2_priority"][name] = item
            self.reject(document(value))

    def test_weight_bands_have_explicit_bounded_and_exclusive_fields(self):
        for weight in (1, 256):
            value = empty_values()
            value["http2_priority"] = {
                "variant": "WeightBand",
                "weight": weight,
                "exclusive": True,
            }
            domain.validate_templates(document(value))

        for priority in (
            False,
            [],
            "WeightBand",
            {"variant": "Unknown", "weight": 1, "exclusive": True},
            {"variant": "WeightBand", "weight": 0, "exclusive": True},
            {"variant": "WeightBand", "weight": 257, "exclusive": True},
            {"variant": "WeightBand", "weight": True, "exclusive": True},
            {"variant": "WeightBand", "weight": 1, "exclusive": 1},
            {
                "variant": "WeightBand",
                "weight": 1,
                "exclusive": True,
                "dependency_stream_id": 0,
            },
        ):
            value = empty_values()
            value["http2_priority"] = priority
            self.reject(document(value))

    def test_conditional_values_require_one_branch_and_preserve_empty(self):
        for variant, left, right in (
            ("ByTrust", "trustworthy", "untrustworthy"),
            ("ByForwarding", "unforwarded", "forwarded"),
        ):
            entry = {"variant": variant, "name": "x", left: None, right: None}
            self.reject_fields([entry])
            entry[left] = ""
            value = empty_values()
            value["http1_fields"] = [entry]
            domain.validate_templates(document(value))
            entry[right] = "\n"
            self.reject_fields([entry])

    def test_duplicate_ordinary_names_are_case_insensitive(self):
        self.reject_fields([literal("X"), literal("x")])
        self.reject_fields(
            [literal("x"), {"variant": "Caller", "name": "x", "required": False}]
        )

    def test_disjoint_proxy_attempts_share_one_name_in_order(self):
        for protocol in (1, 2):
            fields = [
                {
                    "variant": "ProxyAuthorization",
                    "name": "proxy-authorization",
                    "attempt": attempt,
                }
                for attempt in ("Replay", "Preemptive")
            ]
            value = empty_values()
            value[f"http{protocol}_fields"] = fields
            self.assertEqual(
                domain.validate_templates(document(value))["test"][
                    f"http{protocol}_fields"
                ],
                fields,
            )

    def test_overlapping_unknown_misnamed_and_http3_proxy_slots_are_rejected(self):
        for pair in (
            ("Every", "Every"),
            ("Every", "Preemptive"),
            ("Replay", "Every"),
            ("Replay", "Replay"),
        ):
            self.reject_fields(
                [
                    {
                        "variant": "ProxyAuthorization",
                        "name": "Proxy-Authorization",
                        "attempt": attempt,
                    }
                    for attempt in pair
                ]
            )
        for name, attempt in (
            ("authorization", "Every"),
            ("proxy-authorization", "Automatic"),
        ):
            self.reject_fields(
                [{"variant": "ProxyAuthorization", "name": name, "attempt": attempt}]
            )
        self.reject_fields(
            [
                {
                    "variant": "ProxyAuthorization",
                    "name": "proxy-authorization",
                    "attempt": "Every",
                }
            ],
            3,
        )

    def test_generated_fields_allow_only_caller_content_length(self):
        for name in domain.GENERATED_FIELDS:
            self.reject_fields([literal(name)])
        for required in (False, True):
            value = empty_values()
            value["http2_fields"] = [
                {"variant": "Caller", "name": "content-length", "required": required}
            ]
            domain.validate_templates(document(value))

    def test_h2_h3_case_and_connection_fields_match_native_rules(self):
        for protocol in (2, 3):
            self.reject_fields([literal("Accept")], protocol)
            for name in domain.CONNECTION_FIELDS:
                self.reject_fields([literal(name)], protocol)
            self.reject_fields([literal("te", "gzip")], protocol)
            value = empty_values()
            value[f"http{protocol}_fields"] = [literal("te", "trailers")]
            domain.validate_templates(document(value))

    def test_hint_slots_require_a_block_lowercase_name_and_later_literal(self):
        for fields in (
            [{"variant": "ClientHints"}],
            [{"variant": "ClientHint", "name": "sec-ch-ua"}, literal()],
            [{"variant": "ClientHints"}, {"variant": "ClientHints"}, literal()],
            [
                {"variant": "ClientHint", "name": "Sec-CH-UA"},
                {"variant": "ClientHints"},
                literal(),
            ],
        ):
            self.reject_fields(fields)

    def test_hint_signatures_compare_following_names_on_every_protocol(self):
        value = empty_values()
        value["http1_fields"] = [{"variant": "ClientHints"}, literal("Accept")]
        value["http2_fields"] = [{"variant": "ClientHints"}, literal()]
        domain.validate_templates(document(value))
        value["http3_fields"] = [{"variant": "ClientHints"}, literal("other")]
        self.reject(document(value))
        value["http3_fields"] = None
        value["http1_fields"].insert(
            1, {"variant": "Caller", "name": "User-Agent", "required": False}
        )
        self.reject(document(value))

    def test_restart_signatures_allow_the_native_shorter_matching_prefix(self):
        value = empty_values()
        value["http1_fields"] = [{"variant": "RestartClientHints"}, literal("X")]
        value["http2_fields"] = [
            {"variant": "RestartClientHints"},
            {"variant": "Caller", "name": "x", "required": False},
            literal("y"),
        ]
        domain.validate_templates(document(value))
        value["http2_fields"][1]["name"] = "z"
        self.reject(document(value))

    def test_restart_absence_empty_suffix_and_duplicates_are_distinct(self):
        value = empty_values()
        value["http1_fields"] = [{"variant": "RestartClientHints"}]
        self.reject(document(value))
        value["http2_fields"] = [{"variant": "RestartClientHints"}]
        domain.validate_templates(document(value))
        value["http2_fields"].append(literal())
        self.reject(document(value))
        self.reject_fields(
            [{"variant": "RestartClientHints"}, {"variant": "RestartClientHints"}]
        )

    def test_inheritance_replaces_whole_ordered_lists(self):
        value = document()
        value["templates"][0]["values"]["http1_fields"] = [literal("a"), literal("b")]
        value["templates"].append(
            {"id": "child", "base": "test", "values": {"http1_fields": [literal("z")]}}
        )
        self.assertEqual(
            domain.validate_templates(value)["child"]["http1_fields"], [literal("z")]
        )
        value["templates"][-1]["values"]["http1_fields"] = []
        self.assertEqual(domain.validate_templates(value)["child"]["http1_fields"], [])

    def test_bad_references_cycles_and_missing_inherited_values_are_rejected(self):
        value = document()
        value["templates"][0]["base"] = "missing"
        self.reject(value)
        value["templates"][0]["base"] = "test"
        self.reject(value)
        value = document()
        value["templates"][0]["values"].pop("http3_fields")
        self.reject(value)
        value = document()
        value["templates"][0]["base"] = "child"
        value["templates"].append({"id": "child", "base": "test", "values": {}})
        self.reject(value)

    def test_inheritance_limit_is_independent_of_sorted_cached_parent_order(self):
        for prefix in ("a", "z"):
            value = document()
            value["templates"][0]["id"] = prefix + "_root"
            previous = prefix + "_root"
            for index in range(3):
                identifier = "middle_" + str(index)
                value["templates"].append(
                    {"id": identifier, "base": previous, "values": {}}
                )
                previous = identifier
            with mock.patch.object(domain, "MAX_COMPONENT_CHAIN", 3):
                self.reject(value)
            with mock.patch.object(domain, "MAX_COMPONENT_CHAIN", 4):
                domain.validate_templates(value)

    def test_field_declaration_byte_and_depth_resource_bounds_are_rejected(self):
        value = empty_values()
        value["http1_fields"] = [
            literal(str(index)) for index in range(domain.MAX_FIELDS + 1)
        ]
        self.reject(document(value))
        with mock.patch.object(domain, "MAX_COMPONENTS", 0):
            self.reject(document())
        nested = []
        for _ in range(declarations.MAX_DEPTH + 1):
            nested = [nested]
        self.reject(nested)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.json"
            path.write_bytes(b" " * 65)
            with (
                mock.patch.object(declarations, "MAX_BYTES", 64),
                self.assertRaises(declarations.DeclarationError),
            ):
                cli.load_request_templates(path)

    def test_duplicate_json_keys_and_unknown_binding_references_are_rejected(self):
        with self.assertRaises(declarations.DeclarationError):
            json.loads(
                '{"schema":1,"schema":1,"templates":[]}',
                object_pairs_hook=declarations.object_pairs,
            )
        profiles = cli.load()
        profiles[0]["templates"]["Navigation"] = "unknown"
        with self.assertRaises(declarations.DeclarationError):
            domain.validate_template_bindings(
                profiles, domain.validate_templates(self.actual)
            )


OUTPUT_NAMES = (
    "OUTPUT",
    "COMPONENT_OUTPUT",
    "HTTP2_COMPONENT_OUTPUT",
    "TLS_COMPONENT_OUTPUT",
    "QUIC_COMPONENT_OUTPUT",
    "HTTP1_COMPONENT_OUTPUT",
    "DNS_COMPONENT_OUTPUT",
    "UDP_COMPONENT_OUTPUT",
    "TCP_COMPONENT_OUTPUT",
    "COOKIE_COMPONENT_OUTPUT",
    "PROXY_CONNECT_COMPONENT_OUTPUT",
    "CLIENT_HINTS_COMPONENT_OUTPUT",
    "WEBSOCKET_COMPONENT_OUTPUT",
    "REQUEST_TEMPLATE_OUTPUT",
    "COMPOSITION_OUTPUT",
    "CONSTRUCTOR_OUTPUT",
)


class TemplateCliBoundaryTests(unittest.TestCase):
    def test_fixture_redirects_every_generator_output(self):
        outputs = {
            name
            for name, value in vars(cli).items()
            if isinstance(value, Path)
            and (name == "OUTPUT" or name.endswith("_OUTPUT"))
        }
        self.assertEqual(set(OUTPUT_NAMES), outputs)

    def output_context(self, directory, stack):
        paths = []
        for name in OUTPUT_NAMES:
            path = Path(directory) / (name.lower() + ".rs")
            path.write_bytes(b"preserve original output\n")
            stack.enter_context(mock.patch.object(cli, name, path))
            paths.append(path)
        stack.enter_context(mock.patch("sys.argv", ["generate_profiles.py"]))
        stack.enter_context(redirect_stderr(io.StringIO()))
        return paths

    def test_invalid_template_input_preserves_all_outputs(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            paths = self.output_context(directory, stack)
            stack.enter_context(
                mock.patch.object(
                    cli,
                    "load_request_templates",
                    side_effect=declarations.DeclarationError("invalid template"),
                )
            )
            self.assertEqual(cli.main(), 1)
            self.assertTrue(
                all(
                    path.read_bytes() == b"preserve original output\n" for path in paths
                )
            )

    def test_unknown_template_binding_preserves_all_outputs(self):
        profiles = cli.load()
        profiles[0]["templates"]["Navigation"] = "unknown"
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            paths = self.output_context(directory, stack)
            stack.enter_context(mock.patch.object(cli, "load", return_value=profiles))
            self.assertEqual(cli.main(), 1)
            self.assertTrue(
                all(
                    path.read_bytes() == b"preserve original output\n" for path in paths
                )
            )

    def test_check_reports_stale_templates_and_registry_without_modifying_outputs(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            paths = self.output_context(directory, stack)
            self.assertEqual(cli.main(), 0)
            for name in ("OUTPUT", "REQUEST_TEMPLATE_OUTPUT"):
                path = getattr(cli, name)
                expected = path.read_bytes()
                path.write_bytes(b"stale\n")
                all_before = [output.read_bytes() for output in paths]
                with mock.patch("sys.argv", ["generate_profiles.py", "--check"]):
                    self.assertEqual(cli.main(), 1)
                self.assertEqual([output.read_bytes() for output in paths], all_before)
                path.write_bytes(expected)

    def test_absolute_cli_checks_all_outputs_from_an_arbitrary_cwd(self):
        paths = [getattr(cli, name) for name in OUTPUT_NAMES]
        before = [path.read_bytes() for path in paths]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli.REPO / "scripts/dev/generate_profiles.py"),
                    "--check",
                ],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual([path.read_bytes() for path in paths], before)


if __name__ == "__main__":
    unittest.main()
