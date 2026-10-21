"""Zero-window upload cancellation is an explicit, event-triggered scenario."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from client_result import validate_result
from run import accepted, one
from workload_config import effective_config, validate_cancellation


def config():
    return effective_config(
        {
            "cancel_stage": "upload",
            "method": "POST",
            "upload_bytes": 65536,
            "requests": 2,
            "warmup": 1,
            "concurrency": 2,
            "workers": 1,
            "bytes": 2,
        }
    )


def raw(c):
    sample = {
        "id": 0,
        "scheduled_ns": 0,
        "started_ns": 0,
        "application_wait_ns": 0,
        "build_ns": 0,
        "head_ns": None,
        "first_byte_ns": None,
        "complete_ns": 3,
        "bytes": 0,
        "cancelled": True,
        "error": None,
    }
    sibling = sample | {
        "id": 1,
        "bytes": 2,
        "head_ns": 1,
        "first_byte_ns": 2,
        "cancelled": False,
    }
    return {
        "config": c,
        "samples": [sample, sibling],
        "elapsed_ns": 10,
        "heap_instrumented": False,
        "observer_storage_bytes": 0,
    }


def phase():
    return {
        "connections": 1,
        "requests": 2,
        "cancelled_streams": 1,
        "cancelled_uploads": 1,
        "cancelled_while_multiplexed": 1,
        "upload_headers": 1,
        "uploaded_bytes": 0,
        "failures": 0,
        "proxy_connections": 0,
    }


class ContractTests(unittest.TestCase):
    def test_strict_stage_and_two_operation_configuration(self):
        c = config()
        validate_cancellation(c)
        for change in (
            {"cancel_stage": "setup"},
            {"protocol": "h3"},
            {"requests": 4},
            {"warmup": 0},
            {"method": "GET"},
            {"upload_bytes": 0},
            {"cancel_after_bytes": 1},
            {"cold": True},
            {"consume": "collect"},
            {"route": "connect"},
            {"template": True},
            {"diagnostic_events": 1},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_cancellation(c | change)

    def test_result_requires_zero_response_bytes_no_head_and_one_complete_get(self):
        c = config()
        validate_result(raw(c), c)
        for change in (
            {"cancelled": False},
            {"bytes": 1},
            {"head_ns": 0},
            {"first_byte_ns": 0},
            {"error": "cancel failed"},
        ):
            value = raw(c)
            value["samples"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_result(value, c)
        value = raw(c)
        value["samples"][1]["bytes"] = 0
        with self.assertRaises(ValueError):
            validate_result(value, c)

    def test_peer_requires_zero_data_cancel_and_the_original_connection(self):
        c, p = config(), phase()
        summary = {"failures": 0, "cancelled": 1}
        self.assertTrue(accepted(summary, c, p))
        for change in (
            {"connections": 2},
            {"requests": 3},
            {"cancelled_streams": 0},
            {"upload_headers": 0},
            {"cancelled_uploads": 0},
            {"cancelled_while_multiplexed": 0},
            {"cancelled_while_multiplexed": 2},
            {"uploaded_bytes": 1},
            {"failures": 1},
        ):
            with self.subTest(change=change):
                self.assertFalse(accepted(summary, c, p | change))

    def test_controller_relays_only_the_peer_header_event_and_retains_the_receipt(self):
        with TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            script = directory / "fixture.py"
            script.write_text(
                """import json, os, sys
from pathlib import Path
def signal(value):
    message = {"event": value}
    if value == "ready":
        message["pid"] = os.getpid()
    print(json.dumps(message), flush=True)
role, config, ready, result = sys.argv[1:]
config, ready, result = map(Path, (config, ready, result))
c = json.loads(config.read_text())
if role == "serve":
    ready.write_text("{}")
    signal("ready")
    signal("upload_headers")
    assert input() == "snapshot"
    p = {"connections":1,"requests":2,"cancelled_streams":1,"cancelled_uploads":1,"cancelled_while_multiplexed":1,"upload_headers":1,"uploaded_bytes":0,"failures":0,"proxy_connections":0}
    result.with_name("peer-phase.json").write_text(json.dumps(p))
    signal("snapshotted")
    assert input() == "stop"
    result.write_text(json.dumps(p)); signal("stopped")
else:
    signal("ready")
    assert input() == "go"
    assert input() == "cancel-upload"
    signal("phase_end")
    assert input() == "save"
    base = {"id":0,"scheduled_ns":0,"started_ns":0,"application_wait_ns":0,"build_ns":0,"head_ns":None,"first_byte_ns":None,"complete_ns":3,"bytes":0,"cancelled":True,"error":None}
    sibling = base | {"id":1,"cancelled":False,"bytes":2,"head_ns":1,"first_byte_ns":2}
    result.write_text(json.dumps({"config":c,"samples":[base,sibling],"elapsed_ns":10,"heap_instrumented":False,"observer_storage_bytes":0}))
    signal("saved")
""",
                encoding="utf-8",
            )
            real = subprocess.Popen

            def spawn(argv, **kwargs):
                if argv[1] == "serve":
                    argv = [argv[0], str(script), *argv[1:]]
                return real(argv, **kwargs)

            with patch("run.subprocess.Popen", side_effect=spawn):
                result = one(
                    Path(sys.executable),
                    config(),
                    directory / "trial",
                    10,
                    client_command=[sys.executable, str(script)],
                )
            self.assertTrue(result["accepted"])
            receipt = json.loads(
                (directory / "trial/upload-cancellation.json").read_text()
            )
            self.assertEqual(receipt["peer_event"], "upload_headers")
            self.assertEqual(receipt["client_command"], "cancel-upload")


if __name__ == "__main__":
    unittest.main()
