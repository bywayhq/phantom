"""A stand-in capture tool for the runner tests; it never starts a browser.

It takes the arguments the runner passes to a scenario tool and writes one
`resumption-<scenario>.txt` fixture. Scenario names select the behavior:

- `fail-once` fails its first attempt, tracked by a file in the output
  directory;
- `fail` always exits 1;
- `hang` starts a sleeping child, writes the child's process id to
  `grandchild.pid` in the output directory, and sleeps past any test timeout;
- `timed-out` writes a fixture with a timed-out run;
- anything else succeeds.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCENARIOS = {
    name: name for name in ("ok", "slow", "fail-once", "fail", "hang", "timed-out")
}


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in (
        "--browser",
        "--browser-path",
        "--client-version",
        "--operating-system",
        "--scenario",
    ):
        parser.add_argument(name, required=True)
    parser.add_argument("--repeat", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--sleep", type=float, default=0.0)
    args = parser.parse_args()
    # The runner gives each attempt its own TEMP; report it for the tests.
    print(f"temp={tempfile.gettempdir()}", flush=True)
    print(f"lock_dir={os.environ.get('PHANTOM_CAPTURE_LOCK_DIR', '')}", flush=True)
    time.sleep(args.sleep)
    if args.scenario == "hang":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        # Renamed into place, so a reader never sees the file empty.
        partial = args.output_dir / "grandchild.pid.partial"
        partial.write_text(str(child.pid))
        os.replace(partial, args.output_dir / "grandchild.pid")
        time.sleep(600)
    if args.scenario == "fail":
        return 1
    if args.scenario == "fail-once":
        marker = args.output_dir / "fail-once.marker"
        if not marker.exists():
            marker.write_text("failed\n")
            return 1
    timed_out = "true" if args.scenario == "timed-out" else "false"
    fixture = "".join(
        (
            "format=fake\n",
            f"client_version={args.client_version}\n",
            f"operating_system={args.operating_system}\n",
            *(f"run_{run}_timed_out={timed_out}\n" for run in range(args.repeat)),
        )
    )
    path = args.output_dir / f"resumption-{args.scenario}.txt"
    path.write_bytes(fixture.encode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
