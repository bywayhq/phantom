import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
BASH = shutil.which("bash")
if BASH is not None and "system32" in BASH.lower():
    BASH = None

OFFLINE_UPSTREAM = """\
curl() {
  local url=${!#}
  case "$url" in
    https://index.crates.io/ht/tp/http2|https://index.crates.io/wr/eq/wreq-proto)
      printf '%s\\n' '{"vers":"1.2.3","cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","yanked":false,"rust_version":"1.85"}' ;;
    https://codeload.github.com/hyperium/h3/tar.gz/*) printf 'archive fixture' ;;
    https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json)
      printf '%s\\n' '{"channels":{"Stable":{"version":"154.0.8037.58","revision":"42"}}}' ;;
    *) echo "unexpected offline URL: $url" >&2; return 64 ;;
  esac
}
git() {
  if [[ $1 == ls-remote ]]; then
    case "$2" in
      https://github.com/0x676e67/btls.git|https://github.com/hyperium/h3.git)
        printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\tHEAD\\n'; return ;;
      *) echo 'unexpected offline git remote' >&2; return 64 ;;
    esac
  fi
  command git "$@"
}
export -f curl git
exec bash "$1" target/report
"""


@unittest.skipIf(BASH is None or shutil.which("jq") is None, "needs POSIX bash and jq")
class UpstreamReportTests(unittest.TestCase):
    def test_full_offline_report_writes_validated_fixtures_and_workflow_outputs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = [
                "scripts/ci/report-upstream-freshness.sh",
                "crates/phantom-profile/src/browser/chrome.rs",
                "vendor/wreq-proto/Cargo.toml",
                "vendor/http2/Cargo.toml",
                "vendor/btls/PHANTOM.md",
                "vendor/h3/PHANTOM.md",
                "fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt",
                "fixtures/http2/chrome/154.0.8037.58/windows-11-26200/client-startup.txt",
            ]
            for name in names:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPO / name, destination)
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            outputs = root / "outputs.txt"
            result = subprocess.run(
                [BASH, "-c", OFFLINE_UPSTREAM, "report-test", str(root / names[0])],
                cwd=root,
                env={**os.environ, "GITHUB_OUTPUT": str(outputs)},
                capture_output=True,
                text=True,
                timeout=45,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((root / "target/report/report.json").read_text())
            chrome = report["browser_fixtures"]["chrome"]
            self.assertEqual(chrome["recipe_version"], "154.0.8037.58")
            self.assertEqual(chrome["platform"], "windows-11-26200")
            self.assertEqual(chrome["tls_fixture"], names[-2])
            self.assertEqual(chrome["http2_fixture"], names[-1])
            self.assertTrue(chrome["fixture_metadata_matches_recipe"])
            self.assertFalse(chrome["drift"])
            self.assertEqual(chrome["official_revision"], "42")
            self.assertTrue(report["drift"])
            self.assertIn("Checked at", (root / "target/report/summary.md").read_text())
            workflow_outputs = dict(
                line.split("=", 1) for line in outputs.read_text().splitlines()
            )
            expected_keys = {
                "wreq_latest",
                "wreq_checksum",
                "wreq_drift",
                "http2_latest",
                "http2_checksum",
                "http2_drift",
                "btls_latest",
                "btls_drift",
                "btls_probe_supported",
                "h3_latest",
                "h3_checksum",
                "h3_drift",
                "chrome_drift",
                "any_drift",
            }
            self.assertEqual(set(workflow_outputs), expected_keys)
            self.assertTrue(all(workflow_outputs.values()))
            self.assertEqual(workflow_outputs["chrome_drift"], "false")
            self.assertEqual(workflow_outputs["any_drift"], "true")
            for dependency in ("wreq", "http2"):
                self.assertEqual(workflow_outputs[f"{dependency}_latest"], "1.2.3")
                self.assertEqual(workflow_outputs[f"{dependency}_checksum"], "a" * 64)
                self.assertEqual(workflow_outputs[f"{dependency}_drift"], "true")
            for dependency in ("btls", "h3"):
                self.assertEqual(workflow_outputs[f"{dependency}_latest"], "a" * 40)
                self.assertEqual(workflow_outputs[f"{dependency}_drift"], "true")
            self.assertEqual(workflow_outputs["btls_probe_supported"], "true")
            self.assertEqual(
                workflow_outputs["h3_checksum"],
                hashlib.sha256(b"archive fixture").hexdigest(),
            )
            for dependency in ("wreq-proto", "http2", "btls", "h3"):
                self.assertTrue(report["dependencies"][dependency]["drift"])
                self.assertTrue(report["dependencies"][dependency]["current"])
                self.assertTrue(report["dependencies"][dependency]["source"])
            self.assertRegex(report["checked_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")


if __name__ == "__main__":
    unittest.main()
