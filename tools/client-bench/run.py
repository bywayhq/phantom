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
from client_command import load_client, verified_client_build
from client_result import validate_result
from workload_config import effective_config


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    message = None if line is None else json.loads(line)
    if message is None or message.get("event") != expected:
        raise RuntimeError(f"expected {expected}, received {line!r}")
    return message


def command(process, text):
    process.stdin.write(text + "\n")
    process.stdin.flush()


def snapshot(process):
    with process.oneshot():
        cpu = process.cpu_times()
        memory = process.memory_info()
        return {
            "pid": process.pid,
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
    good = [
        sample
        for sample in raw["samples"]
        if sample["error"] is None and not sample.get("cancelled", False)
    ]
    cancelled = [sample for sample in raw["samples"] if sample.get("cancelled", False)]
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
        "cancelled": len(cancelled),
        "cancellation_end_ns": {
            "p50": quantile([sample["complete_ns"] for sample in cancelled], 0.5),
            "p99": quantile([sample["complete_ns"] for sample in cancelled], 0.99),
        },
        "failures": len(failed),
        "elapsed_s": seconds,
        "expected_observations_beyond_p99": len(good) * 0.01,
        "heap_instrumented": raw["heap_instrumented"],
        "observer_storage_bytes": raw["observer_storage_bytes"],
        "unavailable_timings": raw.get("unavailable_timings", {}),
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
    logical = (
        0
        if config.get("protocol") == "construct"
        else config.get("requests", 2000) + config.get("warmup", 100)
    )
    upload_cancel = config.get("cancel_stage", "body") == "upload"
    cancellations = (
        1
        if upload_cancel
        else (
            config.get("requests", 2000) // 2
            if config.get("cancel_after_bytes", 0)
            else 0
        )
    )
    expected = logical * (config.get("redirects", 0) + 1) - cancellations
    return (
        summary["failures"] == 0
        and summary.get("cancelled", 0) == cancellations
        and phase.get("cancelled_streams", 0) == cancellations
        and (
            not cancellations
            or (
                (
                    config.get("protocol") == "h1"
                    and phase["connections"] >= 2
                    and phase.get("cancelled_http1_connections", 0) == cancellations
                )
                or (
                    config.get("protocol") in ("h2", "h3")
                    and phase["connections"] == 1
                    and phase.get("cancelled_while_multiplexed", 0) > 0
                    and (
                        config.get("protocol") == "h2"
                        or phase.get("cancelled_http3_streams", 0) == cancellations
                    )
                )
            )
        )
        and phase["requests"] == expected
        and phase["failures"] == 0
        and phase.get("uploaded_bytes", 0)
        == (0 if upload_cancel else expected * config.get("upload_bytes", 0))
        and (
            not upload_cancel
            or (
                phase.get("upload_headers", 0) == 1
                and phase.get("cancelled_uploads", 0) == 1
                and phase.get("cancelled_while_multiplexed", 0) == 1
            )
        )
        and phase.get("redirect_responses", 0) == logical * config.get("redirects", 0)
        and (
            phase.get("proxy_authenticated_connections", 0) > 0
            and phase["proxy_authenticated_connections"]
            == phase.get("proxy_tunnels", 0)
            and phase["proxy_connections"]
            == phase["proxy_authenticated_connections"]
            + phase.get("proxy_auth_challenges", 0)
            if config.get("proxy_auth", False)
            else phase.get("proxy_authenticated_connections", 0) == 0
        )
        and (
            phase["proxy_connections"] == 0 and phase.get("proxy_tunnels", 0) == 0
            if config.get("route", "direct") == "direct"
            else phase["proxy_connections"] > 0
            and phase.get("proxy_tunnels", 0) > 0
            and phase["connections"] == phase["proxy_tunnels"]
        )
    )


def accepted_recovery(raw, config, phase):
    # DHAT currently stops at "save", so it includes the idle interval.
    # Never attribute that allocation count to measured requests alone.
    outcomes = {
        "failures": 0,
        "cancelled": sum(
            sample.get("cancelled", False) for sample in raw.get("samples", [])
        ),
    }
    return not raw["heap_instrumented"] and accepted(outcomes, config, phase)


def one(binary, config, folder, timeout, recovery_seconds=0, client_command=None):
    config = effective_config(config)
    folder.mkdir()
    save(folder / "config.json", config)
    handles = []
    processes = []
    try:

        def spawn(mode, result):
            log = (folder / f"{mode}.stderr.log").open("x", encoding="utf-8")
            handles.append(log)
            argv = [
                *(
                    client_command
                    if mode == "run" and client_command
                    else [str(binary)]
                ),
                mode,
                str(folder / "config.json"),
                str(folder / "ready.json"),
                str(folder / result),
            ]
            save(folder / f"{mode}.command.json", argv)
            process = subprocess.Popen(
                argv,
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
        ready = event(client_messages, "ready", timeout=timeout)
        if type(ready.get("pid")) is not int or ready["pid"] <= 0:
            raise RuntimeError("client ready message requires a positive process id")
        if ready["pid"] != client.pid:
            raise RuntimeError(
                f"client ready PID {ready['pid']} differs from launched process {client.pid}"
            )
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
        upload_relayed = False
        while True:
            if config["cancel_stage"] == "upload" and not upload_relayed:
                try:
                    event(peer_messages, "upload_headers", timeout=0)
                except queue.Empty:
                    pass
                else:
                    command(client, "cancel-upload")
                    upload_relayed = True
                    save(
                        folder / "upload-cancellation.json",
                        {
                            "peer_event": "upload_headers",
                            "client_command": "cancel-upload",
                            "t_s": time.perf_counter() - start,
                        },
                    )
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
        if config["cancel_stage"] == "upload" and not upload_relayed:
            raise RuntimeError("client ended before peer-confirmed upload cancellation")
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
            "phase_start_monotonic_s": start,
            "phase_end_monotonic_s": time.perf_counter(),
        }
        save(folder / "process.json", measurements)
        command(peer, "snapshot")
        event(peer_messages, "snapshotted")
        if recovery_seconds:
            # The client and its pool stay alive, waiting for "save". Keep
            # this interval outside request CPU, latency and throughput.
            recovery_start = time.perf_counter()
            recovery = []
            while True:
                elapsed = time.perf_counter() - recovery_start
                recovery.append(
                    {
                        "t_s": elapsed,
                        "client": snapshot(client_ps),
                        "peer": snapshot(peer_ps),
                    }
                )
                if elapsed >= recovery_seconds:
                    break
                time.sleep(min(0.25, recovery_seconds - elapsed))
            command(peer, "recovery-snapshot")
            event(peer_messages, "recovery-snapshotted")
            save(
                folder / "recovery.json",
                {"requested_seconds": recovery_seconds, "samples": recovery},
            )
        command(client, "save")
        event(client_messages, "saved", timeout=timeout)
        if client.wait(timeout=timeout) != 0:
            raise RuntimeError("client failed")
        command(peer, "stop")
        event(peer_messages, "stopped")
        if peer.wait(timeout=15) != 0:
            raise RuntimeError("peer failed")
        raw = json.loads((folder / "client.json").read_text())
        validate_result(raw, config)
        summary = summarize(raw, measurements)
        summary["peer"] = json.loads((folder / "peer.json").read_text())
        summary["peer_phase"] = phase = json.loads(
            (folder / "peer-phase.json").read_text()
        )
        summary["accepted"] = accepted(summary, config, phase)
        if recovery_seconds:
            summary["peer_recovery"] = recovery_phase = json.loads(
                (folder / "peer-recovery.json").read_text()
            )
            summary["recovery_accepted"] = accepted_recovery(
                raw, config, recovery_phase
            )
            summary["accepted"] = summary["accepted"] and summary["recovery_accepted"]
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
            for pipe in (process.stdin, process.stdout):
                if pipe is not None:
                    pipe.close()
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
    parser.add_argument(
        "--client",
        type=Path,
        help="external client descriptor; --binary remains the independent peer",
    )
    parser.add_argument("--client-build-receipt", type=Path)
    parser.add_argument("--external-profiler", action="store_true")
    parser.add_argument(
        "--recovery-seconds",
        type=int,
        default=0,
        choices=range(301),
        metavar="0..300",
        help="sample idle memory after requests, with the client and pools alive",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="retain failed cases and finish the bounded matrix, returning nonzero",
    )
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    client = load_client(args.client.resolve(strict=True), sha) if args.client else None
    if args.client_build_receipt and not client:
        raise ValueError("--client-build-receipt requires --client")
    client_receipt = (
        json.loads(args.client_build_receipt.read_text(encoding="utf-8"))
        if args.client_build_receipt
        else None
    )
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    matrix = json.loads(args.matrix.read_text())
    receipt = json.loads(args.build_receipt.read_text()) if args.build_receipt else None
    if args.measurement_kind == "timing" and (
        args.external_profiler
        or not receipt
        or not receipt.get("native_optimization_verified")
        or receipt.get("binary_sha256") != sha(binary)
        or (client and not verified_client_build(client, client_receipt))
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
            "client": client,
            "client_build_receipt": client_receipt,
            "client_build_receipt_sha256": sha(args.client_build_receipt)
            if args.client_build_receipt
            else None,
            "measurement_kind": args.measurement_kind,
            "external_profiler": args.external_profiler,
            "recovery_seconds": args.recovery_seconds,
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
            summary = one(
                binary,
                config,
                folder,
                args.timeout,
                args.recovery_seconds,
                client["command"] if client else None,
            )
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
