"""Public Python binding adapter for the existing controlled-peer harness."""

import asyncio
import importlib.metadata
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from workload_config import DEFAULTS, effective_config


def configuration(supplied):
    config = effective_config(supplied)
    for key, default in DEFAULTS.items():
        if key != "peer_workers" and type(config[key]) is not type(default):
            raise ValueError(f"invalid configuration type: {key}")
    bounds = {
        "concurrency": (1, 256),
        "requests": (1, 1_000_000),
        "warmup": (0, 100_000),
        "bytes": (0, 16 * 1024 * 1024),
        "origins": (1, 128),
        "chunk_bytes": (1, 65536),
        "server_delay_ms": (0, 1000),
        "chunk_delay_ms": (0, 1000),
        "arrival_interval_us": (0, 1_000_000),
    }
    variable = {*bounds, "name", "protocol", "consume", "cold", "peer_workers"}
    for key, default in DEFAULTS.items():
        if key not in variable and config[key] != default:
            raise ValueError(f"adapter requires {key}={default!r}")
    for key, (lower, upper) in bounds.items():
        if not lower <= config[key] <= upper:
            raise ValueError(f"unbounded benchmark configuration: {key}")
    if config["protocol"] not in ("h1", "h2", "h3"):
        raise ValueError("adapter requires an exact HTTP protocol")
    if config["consume"] not in ("collect", "stream"):
        raise ValueError("adapter requires collect or stream consumption")
    workers = config["peer_workers"]
    if workers is not None and (type(workers) is not int or not 1 <= workers <= 16):
        raise ValueError("invalid peer_workers")
    return config


def peer_urls(ready, count):
    urls = ready["urls"]
    if not isinstance(urls, list) or len(urls) != count:
        raise ValueError("peer origin count differs from configuration")
    for url in urls:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("adapter requires HTTPS peers on IPv4 loopback")
    return urls


def sample(identifier):
    return {
        "id": identifier,
        "scheduled_ns": 0,
        "started_ns": 0,
        "application_wait_ns": 0,
        "build_ns": 0,
        "head_ns": None,
        "first_byte_ns": None,
        "complete_ns": 0,
        "bytes": 0,
        "cancelled": False,
        "error": None,
    }


def storage_size(records):
    seen = set()
    total = sys.getsizeof(records)
    for record in records:
        total += sys.getsizeof(record)
        for value in (*record.keys(), *record.values()):
            if id(value) not in seen:
                seen.add(id(value))
                total += sys.getsizeof(value)
    return total


async def execute(config, urls, shared, create, record):
    start = time.perf_counter_ns()
    selected, response, owned = shared, None, None
    try:
        if config["cold"]:
            owned = selected = create()
            record["build_ns"] = time.perf_counter_ns() - start
        response = await selected.request("GET", urls[record["id"] % len(urls)])
        record["head_ns"] = time.perf_counter_ns() - start
        if (
            response.status != 200
            or response.protocol != config["protocol"]
            or response.connection_setup_retries != 0
            or response.redirects_followed != 0
        ):
            raise ValueError("unexpected status, protocol or replay")
        if config["consume"] == "collect":
            data = await response.read(max_bytes=config["bytes"])
            record["bytes"] = len(data)
            if data.count(b"Z") != len(data):
                raise ValueError("incorrect response content")
        else:
            async for data in response.iter_bytes(65536):
                if data and record["first_byte_ns"] is None:
                    record["first_byte_ns"] = time.perf_counter_ns() - start
                record["bytes"] += len(data)
                if record["bytes"] > config["bytes"] or data.count(b"Z") != len(data):
                    raise ValueError("incorrect response content or length")
        if record["bytes"] != config["bytes"]:
            raise ValueError("incorrect response length")
    except Exception as error:
        record["error"] = f"{type(error).__name__}: {error}"
    finally:
        record["complete_ns"] = time.perf_counter_ns() - start
        try:
            if response is not None:
                response.close()
        finally:
            if owned is not None:
                await owned.close()


async def run_workers(config, urls, shared, create, records, start=None):
    async def worker(index):
        for identifier in range(index, len(records), config["concurrency"]):
            record = records[identifier]
            if start is not None:
                planned = identifier * config["arrival_interval_us"] * 1000
                if config["arrival_interval_us"]:
                    await asyncio.sleep(
                        max(0, (start + planned - time.perf_counter_ns()) / 1e9)
                    )
                now = time.perf_counter_ns() - start
                record["scheduled_ns"] = (
                    planned if config["arrival_interval_us"] else now
                )
                record["started_ns"] = now
                record["application_wait_ns"] = max(0, now - record["scheduled_ns"])
            await execute(config, urls, shared, create, record)

    tasks = [asyncio.create_task(worker(i)) for i in range(config["concurrency"])]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def signal(event):
    print(json.dumps({"event": event}), flush=True)


async def control(expected):
    if (await asyncio.to_thread(sys.stdin.readline)).strip() != expected:
        raise ValueError("controller disconnected or sent an invalid command")


async def run(supplied, ready, output):
    from phantom_http import AsyncClient, Timeouts, Trust

    config = configuration(supplied)
    urls = peer_urls(ready, config["origins"])
    identifier = "chrome/154.0.8037.97/windows-11-26200/r1"
    trust = Trust(roots=(bytes(ready["root_der"]),))

    def create():
        return AsyncClient(
            profile=identifier,
            protocol=config["protocol"],
            context="raw",
            cookies=False,
            trust=trust,
            timeouts=Timeouts(connect=5, total=15),
        )

    shared = create()
    try:
        warmup = [sample(i) for i in range(config["warmup"])]
        await run_workers(config, urls, shared, create, warmup)
        if any(record["error"] is not None for record in warmup):
            raise ValueError("warmup failed; no measurement accepted")
        del warmup
        records = [sample(i) for i in range(config["requests"])]
        observer_bytes = storage_size(records)
        await asyncio.to_thread(lambda: None)
        signal("ready")
        await control("go")
        start = time.perf_counter_ns()
        await run_workers(config, urls, shared, create, records, start)
        elapsed = time.perf_counter_ns() - start
        signal("phase_end")
        await control("save")
        result = {
            "config": config,
            "samples": records,
            "elapsed_ns": elapsed,
            "heap_instrumented": False,
            "observer_storage_bytes": observer_bytes,
            "observer_storage_kind": "unique shallow Python object sizes before measurement",
            "adapter_settings": {
                "library": "phantom-http=="
                + importlib.metadata.version("phantom-http"),
                "runtime": sys.version,
                "recipe": identifier,
                "native_workers": 2,
                "stream_chunk_bytes": 65536,
                "cookies": False,
                "connect_timeout_s": 5,
                "total_timeout_s": 15,
                "route": "direct",
            },
        }
        with output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream)
            stream.write("\n")
        signal("saved")
    finally:
        await shared.close()


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "run":
        raise ValueError("usage: phantom_python_client.py run CONFIG READY RESULT")
    config_file, ready_file, output_file = map(Path, sys.argv[2:])
    asyncio.run(
        run(
            json.loads(config_file.read_text(encoding="utf-8")),
            json.loads(ready_file.read_text(encoding="utf-8")),
            output_file,
        )
    )
