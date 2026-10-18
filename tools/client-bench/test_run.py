"""Controls that prevent incorrect work from becoming an accepted baseline."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from run import accepted, accepted_recovery, one, quantile, sha


class ExternalClientTests(unittest.TestCase):
    def test_separate_client_keeps_phase_controls_and_retains_literal_arguments(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory).resolve()
            script = folder / "controlled processes.py"
            script.write_text(
                """import json, sys
from pathlib import Path
def signal(event):
    print(json.dumps({"event": event}), flush=True)
role, *args = sys.argv[1:]
if role == "client":
    marker, mode, config, ready, result = args
    assert marker == "literal;$(unused)" and mode == "run"
    assert all(Path(path).is_absolute() for path in (config, ready, result))
    signal("ready")
    assert input() == "go"
    signal("phase_end")
    assert input() == "save"
    Path(result).write_text(json.dumps({
        "elapsed_ns": 1000000, "heap_instrumented": False,
        "config": json.loads(Path(config).read_text()),
        "observer_storage_bytes": 0, "samples": [{
            "id": 0, "scheduled_ns": 0, "started_ns": 0,
            "error": None, "bytes": 0, "head_ns": 1,
            "first_byte_ns": None, "complete_ns": 1,
            "build_ns": 0, "application_wait_ns": 0
        }]
    }))
    signal("saved")
else:
    assert role == "serve"
    config, ready, result = map(Path, args)
    ready.write_text("{}")
    signal("ready")
    assert input() == "snapshot"
    phase = {"requests": 1, "failures": 0, "proxy_connections": 0}
    result.with_name("peer-phase.json").write_text(json.dumps(phase))
    signal("snapshotted")
    assert input() == "stop"
    result.write_text(json.dumps(phase))
    signal("stopped")
""",
                encoding="utf-8",
            )
            real_popen = subprocess.Popen
            observed = []

            def spawn(argv, **kwargs):
                observed.append(argv)
                if argv[1] == "serve":
                    argv = [argv[0], str(script), *argv[1:]]
                return real_popen(argv, **kwargs)

            client = [sys.executable, str(script), "client", "literal;$(unused)"]
            with patch("run.subprocess.Popen", side_effect=spawn):
                summary = one(
                    Path(sys.executable),
                    {"requests": 1, "warmup": 0, "protocol": "h2", "bytes": 0},
                    folder / "trial",
                    10,
                    client_command=client,
                )
            self.assertTrue(summary["accepted"])
            self.assertEqual(observed[0][1], "serve")
            self.assertEqual(observed[1][: len(client)], client)
            retained = json.loads((folder / "trial/run.command.json").read_text())
            self.assertEqual(retained, observed[1])
            self.assertTrue((folder / "trial/process.json").is_file())


class AcceptanceTests(unittest.TestCase):
    def test_binary_identity_hashes_the_file_bytes(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(b"abc")
            self.assertEqual(
                sha(path),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_incomplete_or_duplicate_peer_requests_are_rejected(self):
        config = {"protocol": "h2", "requests": 10, "warmup": 2}
        for observed in (11, 13):
            self.assertFalse(
                accepted(
                    {"failures": 0},
                    config,
                    {"requests": observed, "failures": 0, "proxy_connections": 0},
                )
            )

    def test_client_and_peer_failures_are_rejected(self):
        config = {"protocol": "h2", "requests": 10, "warmup": 2}
        self.assertFalse(
            accepted(
                {"failures": 1},
                config,
                {"requests": 12, "failures": 0, "proxy_connections": 0},
            )
        )
        self.assertFalse(
            accepted(
                {"failures": 0},
                config,
                {"requests": 12, "failures": 1, "proxy_connections": 0},
            )
        )

    def test_upload_totals_include_warmup_and_must_match_every_attempt(self):
        config = {"protocol": "h2", "requests": 10, "warmup": 2, "upload_bytes": 65536}
        phase = {"requests": 12, "failures": 0, "proxy_connections": 0}
        for observed in (None, 0, 11 * 65536, 13 * 65536):
            with self.subTest(observed=observed):
                if observed is not None:
                    phase["uploaded_bytes"] = observed
                self.assertFalse(accepted({"failures": 0}, config, phase))
        phase["uploaded_bytes"] = 12 * 65536
        self.assertTrue(accepted({"failures": 0}, config, phase))

    def test_proxy_route_must_actually_open_a_proxy_connection(self):
        phase = {"requests": 12, "failures": 0, "proxy_connections": 0}
        config = {"protocol": "h2", "requests": 10, "warmup": 2, "route": "connect"}
        self.assertFalse(accepted({"failures": 0}, config, phase))
        phase["proxy_connections"] = 1
        self.assertTrue(accepted({"failures": 0}, config, phase))
        config["route"] = "direct"
        self.assertFalse(accepted({"failures": 0}, config, phase))

    def test_small_tail_uses_observed_maximum_without_interpolation(self):
        self.assertEqual(quantile([10, 20, 30, 40], 0.99), 40)
        self.assertIsNone(quantile([], 0.99))

    def test_idle_peer_failures_and_mixed_allocation_intervals_are_rejected(self):
        config = {"protocol": "h2", "requests": 10, "warmup": 2}
        phase = {"requests": 12, "failures": 0, "proxy_connections": 0}
        self.assertTrue(accepted_recovery({"heap_instrumented": False}, config, phase))
        self.assertFalse(accepted_recovery({"heap_instrumented": True}, config, phase))
        phase["failures"] = 1
        self.assertFalse(accepted_recovery({"heap_instrumented": False}, config, phase))


if __name__ == "__main__":
    unittest.main()
