import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.dev.tests.test_wsl_cargo import BASH, GATE

WSL_PREFIX = (
    "wsl: Failed to create virtual network; assigned a new address\r\n".encode(
        "utf-16-le"
    )
    + b"\n"
)
NATIVE_PROGRESS = (
    b"warning: phantom-btls-sys@0.5.6-phantom.2: "
    b"applying 0001-boringssl-ffdhe.patch to boringssl\n"
)


@unittest.skipIf(BASH is None, "needs a POSIX bash")
class GateDiagnosticsTests(unittest.TestCase):
    def run_step(self, payload: bytes, status: int = 0) -> tuple[bytes, int]:
        source = GATE.read_text(encoding="utf-8")
        start = source.index("\nfailure_pattern=") + 1
        end = source.index("\n# feature_rows", start)
        scanner = source[start:end]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output.bin"
            output.write_bytes(payload)
            result = subprocess.run(
                [
                    BASH,
                    "-c",
                    scanner + '\nlogs=$1; shift\nrun_step sample - "$@"\n',
                    "gate-diagnostics-test",
                    str(root),
                    BASH,
                    "-c",
                    'cat "$1"; exit "$2"',
                    "byte-output",
                    str(output),
                    str(status),
                ],
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            recorded_status, seconds = (root / "sample.status").read_text().split()
            self.assertGreaterEqual(int(seconds), 0)
            self.assertTrue((root / "sample.log").read_bytes().endswith(payload))
            return (root / "sample.flags").read_bytes(), int(recorded_status)

    def test_mixed_wsl_output_keeps_raw_bytes_without_flagging_native_progress(
        self,
    ) -> None:
        flags, status = self.run_step(WSL_PREFIX + NATIVE_PROGRESS)
        self.assertEqual(flags, b"")
        self.assertEqual(status, 0)

    def test_mixed_output_retains_the_first_five_actual_diagnostics(self) -> None:
        diagnostics = [
            b"warning: actual warning with an embedded \0 byte",
            b"error[E0001]: actual compiler error",
            b"warning: phantom-btls-sys@0.5.6-phantom.2: unknown native notice",
            b"FAILED actual test",
            b"error: fifth diagnostic",
            b"warning: sixth diagnostic",
        ]
        flags, status = self.run_step(
            WSL_PREFIX + NATIVE_PROGRESS + b"\n".join(diagnostics) + b"\n"
        )
        self.assertEqual(flags, b"\n".join(diagnostics[:5]) + b"\n")
        self.assertEqual(status, 0)

    def test_mixed_output_preserves_a_failing_commands_status(self) -> None:
        flags, status = self.run_step(WSL_PREFIX + NATIVE_PROGRESS, 37)
        self.assertEqual(flags, b"")
        self.assertEqual(status, 37)


if __name__ == "__main__":
    unittest.main()
