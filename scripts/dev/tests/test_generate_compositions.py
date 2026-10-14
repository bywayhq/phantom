"""Typed component references, immutable profile assembly and output boundaries."""

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

from scripts.dev.profile_catalog import cli, composition, declarations

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
)


def components():
    return [
        component
        for group in (
            cli.load_components(),
            cli.load_http2_components(),
            cli.load_tls_components(),
            cli.load_quic_components(),
            cli.load_http1_components(),
            cli.load_dns_components(),
            cli.load_udp_components(),
            cli.load_tcp_components(),
            cli.load_cookie_components(),
            cli.load_proxy_connect_components(),
            cli.load_client_hints_components(),
            cli.load_websocket_components(),
        )
        for component in group
    ]


class CompositionDeclarationTests(unittest.TestCase):
    def setUp(self):
        self.document = declarations.read_document(cli.RECORDS)
        self.components = components()

    def reject(self, document):
        with self.assertRaises(declarations.DeclarationError):
            profiles = cli.validate(document)
            composition.validate_composition_bindings(profiles, self.components)

    def test_current_ten_compositions_retain_explicit_configured_and_absent_layers(
        self,
    ):
        profiles = cli.validate(self.document)
        composition.validate_composition_bindings(profiles, self.components)
        self.assertEqual(len(profiles), 10)
        pairs = [value for entry in profiles for value in entry["composition"].values()]
        self.assertEqual(len(pairs), 140)
        self.assertEqual(sum(value is not None for value in pairs), 94)
        self.assertEqual(sum(value is None for value in pairs), 46)
        self.assertEqual(
            cli.COMPOSITION_OUTPUT.read_text(encoding="utf-8"),
            composition.generate_compositions(profiles),
        )

    def test_generation_ignores_record_reference_object_and_component_input_order(self):
        expected = composition.generate_compositions(cli.validate(self.document))
        self.document["profiles"].reverse()
        for entry in self.document["profiles"]:
            entry["composition"] = dict(reversed(list(entry["composition"].items())))
        profiles = cli.validate(self.document)
        self.components.reverse()
        composition.validate_composition_bindings(profiles, self.components)
        self.assertEqual(composition.generate_compositions(profiles), expected)

    def test_composition_requires_exact_keys_and_no_implicit_defaults(self):
        for value in (None, [], {}, {"Automatic": None}):
            document = copy.deepcopy(self.document)
            document["profiles"][0]["composition"] = value
            self.reject(document)
        for name in composition.LAYER_KINDS:
            document = copy.deepcopy(self.document)
            del document["profiles"][0]["composition"][name]
            self.reject(document)
        document = copy.deepcopy(self.document)
        document["profiles"][0]["composition"]["Default"] = None
        self.reject(document)

    def test_references_require_bounded_closed_identifiers(self):
        for value in (False, 1, [], {}, "", "std::process::exit", "../tls", "x" * 65):
            document = copy.deepcopy(self.document)
            document["profiles"][0]["composition"]["TcpTls"] = value
            self.reject(document)

    def test_all_configured_references_reject_unknown_and_incompatible_components(self):
        for index, entry in enumerate(self.document["profiles"]):
            for layer, identifier in entry["composition"].items():
                if identifier is None:
                    continue
                with self.subTest(target=entry["target"], layer=layer):
                    document = copy.deepcopy(self.document)
                    document["profiles"][index]["composition"][layer] = (
                        "unknown_component"
                    )
                    self.reject(document)
                    wrong = next(
                        component["id"]
                        for component in self.components
                        if component["kind"] != composition.LAYER_KINDS[layer]
                    )
                    document["profiles"][index]["composition"][layer] = wrong
                    self.reject(document)

    def test_component_presence_cannot_contradict_configured_or_absent_evidence(self):
        for index, entry in enumerate(self.document["profiles"]):
            for layer, identifier in entry["composition"].items():
                document = copy.deepcopy(self.document)
                document["profiles"][index]["composition"][layer] = (
                    None
                    if identifier is not None
                    else next(
                        item["id"]
                        for item in self.components
                        if item["kind"] == composition.LAYER_KINDS[layer]
                    )
                )
                with self.subTest(target=entry["target"], layer=layer):
                    self.reject(document)

    def test_http3_requires_all_four_typed_layers_even_without_evidence_checks(self):
        entry = copy.deepcopy(self.document["profiles"][0])
        entry["layers"] = []
        for mask in range(1, 15):
            value = copy.deepcopy(entry)
            for index, layer in enumerate(composition.HTTP3_LAYERS):
                if mask & (1 << index):
                    value["composition"][layer] = None
            with (
                self.subTest(mask=mask),
                self.assertRaises(declarations.DeclarationError),
            ):
                composition.validate_composition(value)
        for layer in composition.HTTP3_LAYERS:
            entry["composition"][layer] = None
        composition.validate_composition(entry)

    def test_tcp_tls_cannot_be_absent_even_without_evidence_checks(self):
        entry = copy.deepcopy(self.document["profiles"][0])
        entry["layers"] = []
        entry["composition"]["TcpTls"] = None
        with self.assertRaises(declarations.DeclarationError):
            composition.validate_composition(entry)

    def test_cross_domain_duplicate_identifiers_are_ambiguous(self):
        self.components.append(copy.deepcopy(self.components[0]))
        with self.assertRaises(declarations.DeclarationError):
            composition.validate_composition_bindings(
                cli.validate(self.document), self.components
            )

    def test_duplicate_composition_json_keys_are_rejected(self):
        with self.assertRaises(declarations.DeclarationError):
            json.loads(
                '{"TcpTls":"a","TcpTls":"b"}',
                object_pairs_hook=declarations.object_pairs,
            )

    def test_generated_composition_uses_typed_values_without_complete_factory_dispatch(
        self,
    ):
        generated = composition.generate_compositions(cli.validate(self.document))
        self.assertIn("ConnectionProfileDefinition", generated)
        self.assertNotIn("browser::", generated)
        self.assertNotIn("RecipeBinding", generated)
        self.assertNotIn("fn()", generated)
        self.assertNotIn("random", generated)
        self.assertEqual(generated.count("static "), 10)


class CompositionCliBoundaryTests(unittest.TestCase):
    def outputs(self, directory, stack):
        paths = {}
        for name in OUTPUT_NAMES:
            path = Path(directory) / (name.lower() + ".rs")
            path.write_bytes(b"preserve\r\n")
            paths[name] = path
        stack.enter_context(mock.patch.multiple(cli, **paths))
        stack.enter_context(mock.patch.object(sys, "argv", ["generate_profiles.py"]))
        stack.enter_context(redirect_stderr(io.StringIO()))
        return paths

    def test_bad_cross_reference_preserves_all_fifteen_outputs_and_missing_directory(
        self,
    ):
        profiles = cli.load()
        profiles[0]["composition"]["TcpTls"] = "unknown_component"
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            paths = self.outputs(directory, stack)
            missing = Path(directory) / "missing"
            stack.enter_context(
                mock.patch.object(cli, "COMPOSITION_OUTPUT", missing / "new.rs")
            )
            stack.enter_context(mock.patch.object(cli, "load", return_value=profiles))
            self.assertEqual(cli.main(), 1)
            self.assertFalse(missing.exists())
            self.assertTrue(
                all(path.read_bytes() == b"preserve\r\n" for path in paths.values())
            )

    def test_failure_emitting_last_output_cannot_write_any_earlier_output(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            paths = self.outputs(directory, stack)
            stack.enter_context(
                mock.patch.object(
                    cli,
                    "generate_compositions",
                    side_effect=declarations.DeclarationError("invalid composition"),
                )
            )
            self.assertEqual(cli.main(), 1)
            self.assertTrue(
                all(path.read_bytes() == b"preserve\r\n" for path in paths.values())
            )

    def test_check_rejects_each_stale_output_and_never_writes(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            paths = self.outputs(directory, stack)
            self.assertEqual(cli.main(), 0)
            expected = {name: path.read_bytes() for name, path in paths.items()}
            stack.enter_context(
                mock.patch.object(sys, "argv", ["generate_profiles.py", "--check"])
            )
            for stale in OUTPUT_NAMES:
                for name, path in paths.items():
                    path.write_bytes(b"stale" if name == stale else expected[name])
                before = {name: path.read_bytes() for name, path in paths.items()}
                with self.subTest(stale=stale):
                    self.assertEqual(cli.main(), 1)
                    self.assertEqual(
                        {name: path.read_bytes() for name, path in paths.items()},
                        before,
                    )

    def test_absolute_command_from_arbitrary_cwd_preserves_all_fifteen_outputs(self):
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
