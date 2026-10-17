"""Summarize independent repetitions without pooling their latency samples."""

import argparse
import csv
import hashlib
import json
import statistics
from pathlib import Path


def aggregate(folder):
    identity_path = folder / "identity.json"
    identity = json.loads(identity_path.read_text()) if identity_path.exists() else {}
    if (
        identity.get("external_profiler")
        or identity.get("measurement_kind") == "profile"
    ):
        raise ValueError("profiler timings are not a speed baseline")
    results = json.loads((folder / "results.json").read_text())
    failures = json.loads((folder / "failures.json").read_text())
    if any(row["summary"]["heap_instrumented"] for row in results):
        raise ValueError("allocation-profiler timings are not a speed baseline")
    names = sorted({row["name"] for row in results} | {row["name"] for row in failures})
    rows = []
    for name in names:
        runs = [row["summary"] for row in results if row["name"] == name]
        rejected = [row for row in failures if row["name"] == name]
        row = {
            "name": name,
            "accepted_trials": len(runs),
            "failed_trials": len(rejected),
        }
        if runs:
            metrics = {
                "rps": lambda run: run["completed_requests_s"],
                "mib_s": lambda run: run["completed_mib_s"],
                "cpu_us": lambda run: run["client_cpu_us_per_success"],
                "p50_ms": lambda run: run["timing"]["complete_ns"]["p50"] / 1e6,
                "p99_ms": lambda run: run["timing"]["complete_ns"]["p99"] / 1e6,
                "scheduled_p99_ms": lambda run: (
                    run["timing"]["scheduled_to_complete_ns"]["p99"] / 1e6
                ),
                "rss_mib": lambda run: run["sampled_peak_rss_bytes"] / 2**20,
                "private_mib": lambda run: run["sampled_peak_private_bytes"] / 2**20,
                "rss_growth_mib": lambda run: (
                    (run["sampled_peak_rss_bytes"] - run["start_rss_bytes"]) / 2**20
                ),
                "connections": lambda run: run["peer_phase"]["connections"],
            }
            for key, value in metrics.items():
                values = [value(run) for run in runs]
                row[key] = {
                    "median": statistics.median(values),
                    "min": min(values),
                    "max": max(values),
                }
            row["measured_operations"] = sum(run["successes"] for run in runs)
            row["heap_instrumented"] = any(run["heap_instrumented"] for run in runs)
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    rows = aggregate(args.folder)
    identity = json.loads((args.folder / "identity.json").read_text())
    kind = identity.get("measurement_kind", "diagnostic")
    (args.output / "summary.json").write_text(json.dumps(rows, indent=2) + "\n")
    with (args.output / "summary.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        flattened = []
        for row in rows:
            flat = {}
            for key, value in row.items():
                if isinstance(value, dict):
                    flat.update(
                        {
                            f"{key}_{statistic}": number
                            for statistic, number in value.items()
                        }
                    )
                else:
                    flat[key] = value
            flattened.append(flat)
        fields = sorted({key for row in flattened for key in row})
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        writer.writerows(flattened)
    lines = [
        f"# Public-client {kind} measurements",
        "",
        "Medians across accepted trials; ranges show the observed minimum and maximum.",
        "Latencies are per-trial distributions, never pooled across repetitions.",
        "",
        "| Case | Accepted / failed | Operations/s (range) | p50 / p99 ms | CPU µs/op | Sampled RSS / private MiB |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        if not row["accepted_trials"]:
            lines.append(
                f"| {row['name']} | 0 / {row['failed_trials']} | unavailable | unavailable | unavailable | unavailable |"
            )
            continue

        def number(key, selected=row):
            return selected[key]["median"]

        lines.append(
            f"| {row['name']} | {row['accepted_trials']} / {row['failed_trials']} | "
            f"{number('rps'):.0f} ({row['rps']['min']:.0f}–{row['rps']['max']:.0f}) | "
            f"{number('p50_ms'):.3f} / {number('p99_ms'):.3f} | {number('cpu_us'):.1f} | "
            f"{number('rss_mib'):.1f} / {number('private_mib'):.1f} |"
        )
    lines += [
        "",
        "Shared Windows host; loopback and application payload validation are included.",
        "Allocation-profiler runs, declared external-profiler runs and failed trials are excluded.",
        "Cold cases have limited tail observations. See raw samples and phase boundaries.",
        "",
    ]
    (args.output / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    receipts = {}
    for name in ("identity.json", "results.json", "failures.json"):
        receipts[name] = hashlib.sha256((args.folder / name).read_bytes()).hexdigest()
    (args.output / "inputs.json").write_text(json.dumps(receipts, indent=2) + "\n")
    print(
        json.dumps(
            {
                "cases": len(rows),
                "accepted_trials": sum(row["accepted_trials"] for row in rows),
                "failed_trials": sum(row["failed_trials"] for row in rows),
            }
        )
    )


if __name__ == "__main__":
    main()
