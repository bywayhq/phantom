import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "binding_h3_peer", Path(__file__).resolve().parents[1] / "binding_h3_peer.py"
)
peer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(peer)
ROOT = Path(__file__).resolve().parents[3]


class H3PeerEnvironmentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.python = self.directory / "peer-python"
        self.python.write_bytes(b"interpreter fixture")

    def identity(self, version=(3, 12, 10), aioquic="1.3.0"):
        return json.dumps({"python": version, "aioquic": aioquic}).encode()

    def test_binding_peers_are_staged_with_an_independent_runtime(self):
        environment = {
            "PHANTOM_H3_PEER_PYTHON": str(self.python),
            "PHANTOM_H3_PEER_SCRIPT": "stale-script",
            "PHANTOM_HEADER_H3_PEER_SCRIPT": "stale-header-script",
            "PHANTOM_WEBSOCKET_H3_PEER_SCRIPT": "stale-websocket-script",
            "PHANTOM_EVENTS_H3_PEER_SCRIPT": "stale-events-script",
            "PHANTOM_GO_LIBRARY": "retained-library",
        }
        with patch.object(
            peer.subprocess, "check_output", return_value=self.identity()
        ) as probe:
            result = peer.peer_environment(ROOT, self.directory, environment)
        self.assertEqual(result["PHANTOM_H3_PEER_PYTHON"], str(self.python))
        self.assertEqual(probe.call_args.args[0][0], str(self.python))
        self.assertEqual(result["PHANTOM_GO_LIBRARY"], "retained-library")
        staging = self.directory / "h3-peer"
        self.assertEqual(
            {path.name for path in staging.iterdir()}, set(peer.PEER_FILES)
        )
        for name in peer.PEER_FILES:
            self.assertEqual(
                (staging / name).read_bytes(),
                (ROOT / "scripts/conformance" / name).read_bytes(),
            )
        self.assertEqual(
            result["PHANTOM_H3_PEER_SCRIPT"], str(staging / "binding_upload_h3.py")
        )
        self.assertEqual(environment["PHANTOM_H3_PEER_SCRIPT"], "stale-script")
        self.assertEqual(
            result["PHANTOM_HEADER_H3_PEER_SCRIPT"],
            str(staging / "binding_headers_h3.py"),
        )
        self.assertEqual(
            environment["PHANTOM_HEADER_H3_PEER_SCRIPT"], "stale-header-script"
        )
        self.assertEqual(
            result["PHANTOM_WEBSOCKET_H3_PEER_SCRIPT"],
            str(staging / "binding_websocket_h3.py"),
        )
        self.assertEqual(
            environment["PHANTOM_WEBSOCKET_H3_PEER_SCRIPT"], "stale-websocket-script"
        )
        self.assertEqual(
            result["PHANTOM_EVENTS_H3_PEER_SCRIPT"],
            str(staging / "binding_events_h3.py"),
        )
        self.assertEqual(
            environment["PHANTOM_EVENTS_H3_PEER_SCRIPT"], "stale-events-script"
        )

    def test_unsupported_runtime_fails_before_exposing_peer_files(self):
        for version, aioquic in (((3, 12, 2), "1.3.0"), ((3, 12, 10), "1.2.0")):
            with (
                self.subTest(version=version, aioquic=aioquic),
                patch.object(
                    peer.subprocess,
                    "check_output",
                    return_value=self.identity(version, aioquic),
                ),
                self.assertRaisesRegex(ValueError, "requires Python"),
            ):
                peer.peer_environment(
                    ROOT, self.directory, {"PHANTOM_H3_PEER_PYTHON": str(self.python)}
                )
            self.assertFalse((self.directory / "h3-peer").exists())

    def test_local_fallback_creates_a_stable_owned_venv_not_a_uv_run_path(self):
        commands = []

        def run(command, **options):
            commands.append(command)
            self.assertTrue(options["check"])
            if command[1] == "venv":
                runtime = Path(command[-1])
                python = runtime / (
                    "Scripts/python.exe" if os.name == "nt" else "bin/python"
                )
                python.parent.mkdir(parents=True)
                python.write_bytes(b"interpreter")

        with (
            patch.object(peer.subprocess, "run", side_effect=run),
            patch.object(peer.subprocess, "check_output", return_value=self.identity()),
        ):
            result = peer.peer_environment(ROOT, self.directory, {})
        self.assertEqual(commands[0][:4], ["uv", "venv", "--python", "3.12.10"])
        self.assertEqual(commands[1][-1], "aioquic==1.3.0")
        self.assertTrue(Path(result["PHANTOM_H3_PEER_PYTHON"]).is_file())
        self.assertNotIn("run", commands[0])

    def test_missing_selected_interpreter_is_not_replaced_with_a_fallback(self):
        with self.assertRaisesRegex(ValueError, "interpreter is missing"):
            peer.peer_environment(
                ROOT,
                self.directory,
                {"PHANTOM_H3_PEER_PYTHON": str(self.directory / "absent")},
            )

    def test_command_failure_preserves_error_and_cleans_owned_staging(self):
        seen = []
        failure = subprocess.CalledProcessError(73, ["node", "test"])

        def environment(_root, directory):
            seen.append(directory)
            self.assertTrue(directory.is_dir())
            return {"peer": "owned"}

        with (
            patch.object(sys, "argv", ["binding_h3_peer.py", "--", "node", "test"]),
            patch.object(peer, "peer_environment", side_effect=environment),
            patch.object(peer.subprocess, "run", side_effect=failure) as run,
            self.assertRaises(subprocess.CalledProcessError) as caught,
        ):
            peer.main()
        self.assertIs(caught.exception, failure)
        run.assert_called_once_with(["node", "test"], check=True, env={"peer": "owned"})
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists())
