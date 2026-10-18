"""Pinned curl_cffi public-API adapter for controlled shared-peer workloads."""

import asyncio
import json
import ssl
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from workload_config import DEFAULTS

VERSION = "0.16.3"
HEAD_UNAVAILABLE = (
    "AsyncSession streaming readiness follows body delivery, not head arrival."
)


def configuration(supplied):
    if not isinstance(supplied, dict) or supplied.keys() - DEFAULTS.keys():
        raise ValueError("unknown benchmark configuration fields")
    config = DEFAULTS | supplied
    for key, default in DEFAULTS.items():
        if key != "peer_workers" and type(config[key]) is not type(default):
            raise ValueError(f"invalid configuration type: {key}")
    bounds = {
        "concurrency": (1, 256),
        "requests": (1, 1_000_000),
        "warmup": (0, 100_000),
        "bytes": (0, 16 * 1024 * 1024),
        "upload_bytes": (0, 16 * 1024 * 1024),
        "redirects": (0, 3),
        "origins": (1, 128),
        "chunk_bytes": (1, 65536),
        "server_delay_ms": (0, 1000),
        "chunk_delay_ms": (0, 1000),
        "arrival_interval_us": (0, 1_000_000),
    }
    for key, (lower, upper) in bounds.items():
        if not lower <= config[key] <= upper:
            raise ValueError(f"unbounded benchmark configuration: {key}")
    peer_workers = config["peer_workers"]
    if peer_workers is not None and (
        type(peer_workers) is not int or not 1 <= peer_workers <= 16
    ):
        raise ValueError("invalid peer_workers")
    if config["protocol"] not in ("h1", "h2", "h3"):
        raise ValueError("adapter supports only h1, h2 and h3 requests")
    if config["consume"] not in ("stream", "collect"):
        raise ValueError("adapter supports stream or collect consumption")
    if config["method"] not in ("GET", "POST") or (
        config["method"] == "GET" and config["upload_bytes"] != 0
    ):
        raise ValueError("uploads require a POST request workload")
    if config["redirects"] and (
        config["method"] != "GET" or config["consume"] != "collect"
    ):
        raise ValueError("redirect workloads require collected GET requests")
    if (
        config["route"] not in ("direct", "connect")
        or (config["protocol"] == "h3" and config["route"] != "direct")
        or (config["proxy_auth"] and config["route"] != "connect")
    ):
        raise ValueError("adapter requires direct or TCP CONNECT routing")
    required = {
        "profile": "chrome",
        "workers": 1,
        "gzip": False,
        "template": False,
        "speculative_tls": False,
        "proxy_delay_ms": 0,
        "diagnostic_events": 0,
    }
    for key, expected in required.items():
        if config[key] != expected:
            raise ValueError(f"adapter requires {key}={expected!r}")
    return config


def peer_urls(ready, count):
    urls = ready.get("urls")
    if not isinstance(urls, list) or len(urls) != count:
        raise ValueError("peer origin count differs from configuration")
    for url in urls:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "127.0.0.1"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is None
            or parsed.fragment
        ):
            raise ValueError("adapter requires HTTPS peers on IPv4 loopback")
    return urls


def proxy_url(config, ready):
    if config["route"] != "connect":
        return ""
    address = ready.get("proxy")
    if not isinstance(address, str):
        raise ValueError("missing proxy address")
    parsed = urlsplit("http://" + address)
    if (
        parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or not 1 <= parsed.port <= 65535
        or parsed.username is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("proxy must use IPv4 loopback and a bound port")
    auth = "bench:bench@" if config["proxy_auth"] else ""
    return "http://" + auth + address


def session_factory(config, certificate, proxy=""):
    import curl_cffi
    from curl_cffi import CurlHttpVersion, CurlOpt
    from curl_cffi.requests import AsyncSession

    if curl_cffi.__version__ != VERSION:
        raise ValueError(f"adapter requires curl_cffi=={VERSION}")
    requested, actual = {
        "h1": (CurlHttpVersion.V1_1, CurlHttpVersion.V1_1),
        "h2": (CurlHttpVersion.V2_PRIOR_KNOWLEDGE, CurlHttpVersion.V2_0),
        "h3": (CurlHttpVersion.V3ONLY, CurlHttpVersion.V3),
    }[config["protocol"]]

    def create():
        return AsyncSession(
            max_clients=config["concurrency"],
            impersonate="chrome150",
            default_headers=False,
            trust_env=False,
            discard_cookies=True,
            retry=0,
            allow_redirects=config["redirects"] != 0,
            max_redirects=config["redirects"],
            verify=str(certificate),
            http_version=requested,
            interface="127.0.0.1",
            curl_options={
                CurlOpt.CONNECTTIMEOUT_MS: 5000,
                CurlOpt.TIMEOUT_MS: 15000,
                CurlOpt.PROXY: proxy,
                CurlOpt.NOPROXY: "" if proxy else "*",
            },
        )

    return create, actual


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
        "error": None,
    }


def cleanup_error(record, stage, error):
    detail = f"{stage}: {type(error).__name__}: {error}"
    previous = record["error"]
    record["error"] = f"{previous}; {detail}" if previous else detail


async def execute(config, urls, shared, create, expected_protocol, record):
    start = time.perf_counter_ns()
    selected, response, owned = shared, None, None
    try:
        if config["cold"]:
            owned = selected = create()
            record["build_ns"] = time.perf_counter_ns() - start
        # The application deadline includes body consumption and validation.
        async with asyncio.timeout(15):
            response = await selected.request(
                config["method"],
                urls[record["id"] % len(urls)],
                **(
                    {"data": b"U" * config["upload_bytes"]}
                    if config["method"] == "POST"
                    else {}
                ),
                stream=config["consume"] == "stream",
                accept_encoding=None,
            )
            if (
                response.status_code != 200
                or response.http_version != expected_protocol
            ):
                raise ValueError("unexpected response status or protocol")
            if config["consume"] == "collect":
                chunks = [response.content]
                for chunk in chunks:
                    record["bytes"] += len(chunk)
                    if chunk.count(b"Z") != len(chunk):
                        raise ValueError("incorrect response content")
            else:
                async for chunk in response.aiter_content():
                    if not chunk:
                        continue
                    if record["first_byte_ns"] is None:
                        record["first_byte_ns"] = time.perf_counter_ns() - start
                    record["bytes"] += len(chunk)
                    if chunk.count(b"Z") != len(chunk):
                        raise ValueError("incorrect response content")
            if record["bytes"] != config["bytes"]:
                raise ValueError("incorrect response length")
    except Exception as error:
        record["error"] = f"{type(error).__name__}: {error}"
    finally:
        record["complete_ns"] = time.perf_counter_ns() - start
        # Teardown remains in phase CPU/elapsed time, outside request completion.
        try:
            try:
                if response is not None:
                    await response.aclose()
            except Exception as error:
                cleanup_error(record, "response cleanup", error)
        finally:
            try:
                if owned is not None:
                    await owned.close()
            except Exception as error:
                cleanup_error(record, "session cleanup", error)


async def run_workers(config, urls, shared, create, protocol, records, start=None):
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
            await execute(config, urls, shared, create, protocol, record)

    async with asyncio.TaskGroup() as group:
        for index in range(config["concurrency"]):
            group.create_task(worker(index))


def storage_size(records):
    """Unique shallow Python sizes at preallocation; excludes allocator slack."""
    seen = set()
    total = sys.getsizeof(records)
    for record in records:
        total += sys.getsizeof(record)
        for value in (*record.keys(), *record.values()):
            if id(value) not in seen:
                seen.add(id(value))
                total += sys.getsizeof(value)
    return total


def signal(event):
    print(json.dumps({"event": event}), flush=True)


async def control(expected):
    if (await asyncio.to_thread(sys.stdin.readline)).strip() != expected:
        raise ValueError("controller disconnected or sent an invalid command")


async def run(supplied, ready, output):
    config = configuration(supplied)
    urls = peer_urls(ready, config["origins"])
    with tempfile.TemporaryDirectory(prefix="phantom-curl-peer-") as directory:
        certificate = Path(directory) / "root.pem"
        certificate.write_text(
            ssl.DER_cert_to_PEM_cert(bytes(ready["root_der"])), encoding="ascii"
        )
        create, protocol = session_factory(
            config, certificate, proxy_url(config, ready)
        )
        shared = create()
        try:
            warmup = [sample(index) for index in range(config["warmup"])]
            await run_workers(config, urls, shared, create, protocol, warmup)
            for record in warmup:
                if record["error"] is not None:
                    raise ValueError(f"warmup failed: {record['error']}")
            del warmup
            records = [sample(index) for index in range(config["requests"])]
            observer_bytes = storage_size(records)
            # Start the stdin worker before process-counter snapshots.
            await asyncio.to_thread(lambda: None)
            signal("ready")
            await control("go")
            start = time.perf_counter_ns()
            await run_workers(config, urls, shared, create, protocol, records, start)
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
                "unavailable_timings": {"head_ns": HEAD_UNAVAILABLE},
                "adapter_settings": {
                    "library": f"curl_cffi=={VERSION}",
                    "recipe": "chrome150",
                    "runtime": sys.version,
                    "connect_timeout_ms": 5000,
                    "transfer_timeout_ms": 15000,
                    "application_timeout_s": 15,
                    "max_clients": config["concurrency"],
                    "retry": 0,
                    "redirects": config["redirects"],
                    "environment_proxy": False,
                    "route": config["route"],
                    "proxy_auth": config["proxy_auth"],
                    "stream_buffer": "library-default unbounded queue",
                    "pool_limits": "library defaults; max_clients caps easy handles",
                },
            }
            with output.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
            signal("saved")
        finally:
            await shared.close()


def main():
    if len(sys.argv) != 5 or sys.argv[1] != "run":
        raise ValueError("usage: curl_cffi_client.py run CONFIG READY RESULT")
    config, ready, output = map(Path, sys.argv[2:])
    asyncio.run(
        run(
            json.loads(config.read_text(encoding="utf-8")),
            json.loads(ready.read_text(encoding="utf-8")),
            output,
        )
    )


if __name__ == "__main__":
    main()
