"""Run isolated client/peer pairs and retain raw samples and process counters."""

import argparse
import hashlib
import json
import platform
import queue
import random
import re
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def output_reader(process):
    messages = queue.Queue()

    def read():
        for line in process.stdout:
            messages.put(line)
        messages.put(None)

    threading.Thread(target=read, daemon=True).start()
    return messages


def event(messages, expected, timeout=60):
    line = messages.get(timeout=timeout)
    if line is None or json.loads(line).get("event") != expected:
        raise RuntimeError(f"expected {expected}, received {line!r}")


def command(process, text):
    process.stdin.write(text + "\n")
    process.stdin.flush()


def snapshot(process):
    with process.oneshot():
        cpu = process.cpu_times()
        memory = process.memory_info()
        return {
            "cpu_user_s": cpu.user,
            "cpu_system_s": cpu.system,
            "rss_bytes": memory.rss,
            "private_bytes": getattr(memory, "private", None),
            "lifetime_peak_rss_bytes": getattr(memory, "peak_wset", None),
            "threads": process.num_threads(),
        }


def quantile(values, q):
    """Nearest-rank percentiles: retain raw observations for other estimators."""
    import math

    values = sorted(values)
    return values[max(0, math.ceil(len(values) * q) - 1)] if values else None


def summarize(raw, measurements):
    good = [sample for sample in raw["samples"] if sample["error"] is None]
    failed = [sample for sample in raw["samples"] if sample["error"] is not None]
    seconds = raw["elapsed_ns"] / 1e9
    cpu = sum(
        measurements["end"]["client"][key] - measurements["start"]["client"][key]
        for key in ("cpu_user_s", "cpu_system_s")
    )
    timing = {}
    for field in (
        "head_ns",
        "first_byte_ns",
        "complete_ns",
        "build_ns",
        "application_wait_ns",
    ):
        values = [sample[field] for sample in good if sample[field] is not None]
        timing[field] = {
            "p50": quantile(values, 0.5),
            "p95": quantile(values, 0.95),
            "p99": quantile(values, 0.99),
            "mean": statistics.mean(values) if values else None,
        }
    values = [sample["application_wait_ns"] + sample["complete_ns"] for sample in good]
    timing["scheduled_to_complete_ns"] = {
        "p50": quantile(values, 0.5),
        "p95": quantile(values, 0.95),
        "p99": quantile(values, 0.99),
    }
    return {
        "successes": len(good),
        "failures": len(failed),
        "elapsed_s": seconds,
        "expected_observations_beyond_p99": len(good) * 0.01,
        "heap_instrumented": raw["heap_instrumented"],
        "observer_storage_bytes": raw["observer_storage_bytes"],
        "completed_requests_s": len(good) / seconds,
        "completed_mib_s": sum(sample["bytes"] for sample in good) / seconds / 2**20,
        "client_cpu_s": cpu,
        "client_cpu_us_per_success": cpu * 1e6 / len(good) if good else None,
        "client_cpu_cores": cpu / seconds,
        "sampled_peak_rss_bytes": max(
            row["client"]["rss_bytes"] for row in measurements["samples"]
        ),
        "start_rss_bytes": measurements["start"]["client"]["rss_bytes"],
        "end_rss_bytes": measurements["end"]["client"]["rss_bytes"],
        "sampled_peak_private_bytes": max(
            (row["client"]["private_bytes"] or 0) for row in measurements["samples"]
        ),
        "peer_cpu_s": sum(
            measurements["end"]["peer"][key] - measurements["start"]["peer"][key]
            for key in ("cpu_user_s", "cpu_system_s")
        ),
        "timing": timing,
    }


def accepted(summary, config, phase):
    expected = (
        0
        if config.get("protocol") == "construct"
        else config.get("requests", 2000) + config.get("warmup", 100)
    )
    return (
        summary["failures"] == 0
        and phase["requests"] == expected
        and phase["failures"] == 0
        and (
            phase["proxy_connections"] == 0
            if config.get("route", "direct") == "direct"
            else phase["proxy_connections"] > 0
        )
    )


def one(binary, config, folder, timeout):
    folder.mkdir()
    save(folder / "config.json", config)
    handles = []
    processes = []
    try:

        def spawn(mode, result):
            log = (folder / f"{mode}.stderr.log").open("x", encoding="utf-8")
            handles.append(log)
            process = subprocess.Popen(
                [
                    str(binary),
                    mode,
                    str(folder / "config.json"),
                    str(folder / "ready.json"),
                    str(folder / result),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=log,
                text=True,
                encoding="utf-8",
                cwd=folder,
            )
            processes.append(process)
            return process, output_reader(process)

        peer, peer_messages = spawn("serve", "peer.json")
        event(peer_messages, "ready")
        client, client_messages = spawn("run", "client.json")
        event(client_messages, "ready", timeout=timeout)
        client_ps = psutil.Process(client.pid)
        peer_ps = psutil.Process(peer.pid)
        before = {
            "client": snapshot(client_ps),
            "peer": snapshot(peer_ps),
            "system_cpu": psutil.cpu_times()._asdict(),
        }
        start = time.perf_counter()
        rows = [{"t_s": 0.0, **before}]
        command(client, "go")
        while True:
            try:
                event(client_messages, "phase_end", timeout=0.01)
                break
            except queue.Empty:
                rows.append(
                    {
                        "t_s": time.perf_counter() - start,
                        "client": snapshot(client_ps),
                        "peer": snapshot(peer_ps),
                        "system_cpu": psutil.cpu_times()._asdict(),
                    }
                )
                if rows[-1]["t_s"] > timeout:
                    raise TimeoutError("benchmark phase exceeded its bound") from None
        after = {
            "client": snapshot(client_ps),
            "peer": snapshot(peer_ps),
            "system_cpu": psutil.cpu_times()._asdict(),
        }
        rows.append({"t_s": time.perf_counter() - start, **after})
        measurements = {
            "start": before,
            "end": after,
            "samples": rows,
            "sampling_target_s": 0.01,
        }
        save(folder / "process.json", measurements)
        command(peer, "snapshot")
        event(peer_messages, "snapshotted")
        command(client, "save")
        event(client_messages, "saved", timeout=timeout)
        if client.wait(timeout=timeout) != 0:
            raise RuntimeError("client failed")
        command(peer, "stop")
        event(peer_messages, "stopped")
        if peer.wait(timeout=15) != 0:
            raise RuntimeError("peer failed")
        raw = json.loads((folder / "client.json").read_text())
        if len(raw["samples"]) != config.get("requests", 2000):
            raise RuntimeError("wrong number of measured operations")
        summary = summarize(raw, measurements)
        summary["peer"] = json.loads((folder / "peer.json").read_text())
        summary["peer_phase"] = phase = json.loads(
            (folder / "peer-phase.json").read_text()
        )
        summary["accepted"] = accepted(summary, config, phase)
        save(folder / "summary.json", summary)
        if not summary["accepted"]:
            raise RuntimeError("failed requests or peer controls: see retained summary")
        return summary
    finally:
        # Only terminate the exact subprocesses this controller created.
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        for handle in handles:
            handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument(
        "--measurement-kind",
        choices=("diagnostic", "timing", "profile"),
        default="diagnostic",
    )
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument("--external-profiler", action="store_true")
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="retain failed cases and finish the bounded matrix, returning nonzero",
    )
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    matrix = json.loads(args.matrix.read_text())
    receipt = json.loads(args.build_receipt.read_text()) if args.build_receipt else None
    if args.measurement_kind == "timing" and (
        args.external_profiler
        or not receipt
        or not receipt.get("native_optimization_verified")
        or receipt.get("binary_sha256") != sha(binary)
    ):
        raise ValueError(
            "timing needs a matching verified native build and no external profiler"
        )
    if not 1 <= matrix.get("repeats", 3) <= 30:
        raise ValueError("repetitions must be between 1 and 30")
    if any(
        not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", case.get("name", ""))
        for case in matrix["cases"]
    ):
        raise ValueError(
            "case names must be short filenames using letters, numbers, dash or underscore"
        )
    if len({case["name"] for case in matrix["cases"]}) != len(matrix["cases"]):
        raise ValueError("case names must be unique within a matrix")
    root = Path(__file__).resolve().parents[2]

    def git(*command):
        return subprocess.check_output(["git", *command], cwd=root, text=True).strip()

    sources = {
        path: sha(root / path)
        for path in git("ls-files").splitlines()
        if (root / path).is_file()
    }
    for path in Path(__file__).parent.rglob("*"):
        if path.is_file() and path.suffix in (
            ".rs",
            ".py",
            ".toml",
            ".lock",
            ".json",
            ".cmake",
        ):
            sources[str(path.relative_to(root))] = sha(path)
    save(
        output / "identity.json",
        {
            "head": git("rev-parse", "HEAD"),
            "dirty": git("status", "--porcelain"),
            "source_sha256": sources,
            "binary": str(binary),
            "binary_sha256": sha(binary),
            "measurement_kind": args.measurement_kind,
            "external_profiler": args.external_profiler,
            "build_receipt": receipt,
            "build_receipt_sha256": sha(args.build_receipt)
            if args.build_receipt
            else None,
            "matrix": matrix,
            "matrix_sha256": sha(args.matrix),
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "os": platform.platform(),
            "python": sys.version,
            "psutil": psutil.__version__,
            "cpu_logical": psutil.cpu_count(),
            "cpu_physical": psutil.cpu_count(logical=False),
            "memory": psutil.virtual_memory()._asdict(),
            "cpu_times": psutil.cpu_times()._asdict(),
            "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
        },
    )
    randomizer = random.Random(matrix.get("seed", 20261016))
    order = []
    for repetition in range(matrix.get("repeats", 3)):
        cases = list(matrix["cases"])
        randomizer.shuffle(cases)
        for case in cases:
            order.append((repetition, {**matrix.get("base", {}), **case}))
    save(output / "order.json", order)
    results = []
    failures = []
    for index, (repetition, config) in enumerate(order):
        name = config["name"]
        folder = output / f"{index:03d}-{name}-r{repetition}"
        try:
            summary = one(binary, config, folder, args.timeout)
            results.append(
                {
                    "name": name,
                    "repetition": repetition,
                    "folder": folder.name,
                    "summary": summary,
                }
            )
            print(
                json.dumps(
                    {
                        "name": name,
                        "repetition": repetition,
                        "successes": summary["successes"],
                        "failures": summary["failures"],
                        "rps": round(summary["completed_requests_s"], 1),
                    }
                ),
                flush=True,
            )
        except Exception as error:
            failure = {
                "name": name,
                "repetition": repetition,
                "folder": folder.name,
                "error": repr(error),
            }
            save(folder / "failure.json", failure)
            failures.append(failure)
            print(json.dumps(failure), flush=True)
            if not args.keep_going:
                save(output / "failure.json", {**failure, "completed": results})
                raise
    save(output / "results.json", results)
    save(output / "failures.json", failures)
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
