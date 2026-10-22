"""Six bounded loopback peer observations; no browser or performance claim."""

import argparse
import asyncio
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import ssl
import subprocess
import sys
import traceback
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def complete_frames(chunks, direction, preface):
    frames, trailing = split_frames(chunks, direction, preface=preface)
    check(trailing == 0, f"{direction}: trailing or truncated frame bytes")
    pending = None
    for frame in frames:
        if frame.frame_type in (1, 5) and not frame.flags & 4:
            pending = frame.stream_id
        elif frame.frame_type == 9 and frame.flags & 4:
            pending = None
    check(pending is None, f"{direction}: incomplete header block")
    return frames


def observations(run, mode, token):
    labels = ["first", "reused"] + ([] if mode == "baseline" else ["cookie-first", "cookie-reused",
        "above-three-quarters", "full-table", "marker-before-oversized", "oversized", "marker-after-oversized"])
    count = 2 if mode == "baseline" else 9
    check(len(run.connections) == run.admitted_connections == 1, "expected one connection")
    check(run.request_count == count and run.done.is_set(), "request count or completion differs")
    record = run.connections[0]
    check(record.protocol == record.alpn == "h2" and not record.failure, "connection is not clean h2")
    check(record.client_hello is not None and record.client_hello.complete, "incomplete ClientHello")
    check(record.client_hello.server_name == "server.phantom.test", "ClientHello SNI differs")
    check(record.client_hello.alpn_offer is not None and "h2" in record.client_hello.alpn_offer, "ClientHello does not offer h2")
    client = complete_frames(record.client_chunks, "client", True)
    server = complete_frames(record.server_chunks, "server", False)
    settings = [(int.from_bytes(f.payload[i:i+2], "big"), int.from_bytes(f.payload[i+2:i+6], "big"))
                for f in server if f.frame_type == 4 and not f.flags & 1
                for i in range(0, len(f.payload), 6)]
    check([value for key, value in settings if key == 1] == [4096], "server table SETTINGS is not 4096")
    analysis = analyze_http2(record)
    ids = list(range(1, count * 2, 2))
    check([b.stream_id for b in analysis.client_headers] == ids, "request streams differ")
    check([f.stream_id for f in client if f.frame_type == 1] == ids, "extra or incomplete request headers")
    check(all(any(f.stream_id == stream and f.flags & 1 and f.frame_type in (0, 1)
                  for f in frames) for stream in ids for frames in (client, server)), "unfinished stream")
    decoder, blocks = Decoder(), []
    for index, block in enumerate(analysis.client_headers):
        fields = decode_header_block(decoder, block.block)
        target = urlsplit(block.field(b":path").decode("ascii"))
        check(target.path == ("/done" if index == count - 1 else "/ws.html")
              and parse_qs(target.query) == {"run": [token], "case": [labels[index]]}
              and block.field(b":method") == b"GET", "unexpected request target or method")
        table = list(decoder.header_table.dynamic_entries)
        blocks.append({"stream": block.stream_id, "case": parse_qs(target.query).get("case"),
                       "special_fields": [{"name": f.name.decode("ascii"), "bytes": len(f.value),
                                           "representation": f.representation, "index": f.index,
                                           "entry_size": 32 + len(f.name) + len(f.value),
                                           "in_table": (f.name, f.value) in table}
                                          for f in fields if f.name in (b"cookie", b"x-hpack-size", b"x-table-marker")],
                       "marker_in_table": (b"x-table-marker", b"retained-marker") in table})
    result = {"requests": count, "server_settings": settings, "blocks": blocks}
    if mode == "boundary":
        entries = [blocks[index]["special_fields"][0] for index in (4, 5, 7)]
        result["source_prediction_matches"] = (
            [f["entry_size"] for f in entries] == [3073, 4096, 4097]
            and all(f["representation"] == "incremental" and f["in_table"] for f in entries[:2])
            and entries[2]["representation"] in ("without-indexing", "never-indexed")
            and not entries[2]["in_table"] and blocks[6]["marker_in_table"]
            and blocks[7]["marker_in_table"] and blocks[8]["marker_in_table"]
            and blocks[8]["special_fields"][0]["representation"] == "indexed")
    return result


async def capture(consumer, output, mode, index, env):
    directory = output / f"{mode}-{index}"
    directory.mkdir()
    token = f"{mode}-{index}"
    certificate = generate_certificate()
    (directory / "certificate.pem").write_bytes(certificate.certificate_pem)
    (directory / "certificate.der").write_bytes(certificate.der)
    server = CaptureServer(certificate)
    run = CaptureRun(token, ServerPolicy(), {"tls": b"peer capture\n"}, observation_seconds=0)
    process, failures, result, interruption = None, [], None, None
    with (directory / "stdout.jsonl").open("xb") as stdout, (directory / "stderr.txt").open("xb") as stderr:
        try:
            await asyncio.wait_for(server.start("127.0.0.1"), 5)
            server.begin_run(run)
            check(server.tls_address is not None, "listener has no TLS address")
            command = [str(consumer), str(directory / "certificate.pem"),
                       f"https://server.phantom.test:{server.tls_address[1]}", str(directory), mode, token]
            write(directory / "command.json", command)
            process = await asyncio.create_subprocess_exec(*command, env=env, stdout=stdout, stderr=stderr)
            check(await asyncio.wait_for(process.wait(), 65) == 0, "consumer failed; see stderr")
            await asyncio.wait_for(run.done.wait(), 5)
        except BaseException as error:
            failures.append({"phase": "capture", "traceback": traceback.format_exc()})
            if not isinstance(error, Exception):
                interruption = error
        finally:
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                    await asyncio.wait_for(process.wait(), 5)
                except BaseException as error:
                    failures.append({"phase": "process cleanup", "traceback": traceback.format_exc()})
                    if not isinstance(error, Exception) and interruption is None:
                        interruption = error
            try:
                await asyncio.wait_for(server.close(), 5)
            except BaseException as error:
                failures.append({"phase": "server cleanup", "traceback": traceback.format_exc()})
                if not isinstance(error, Exception) and interruption is None:
                    interruption = error
            write(directory / "exit.json", {"returncode": None if process is None else process.returncode})
    # Retain every raw record even if later analysis rejects the first one.
    for number, record in enumerate(run.connections):
        (directory / f"connection-{number}.client.bin").write_bytes(record.client_stream())
        (directory / f"connection-{number}.server.bin").write_bytes(b"".join(b for _, b in record.server_chunks))
        if record.client_hello is not None:
            (directory / f"connection-{number}.hello.bin").write_bytes(bytes(record.client_hello.handshake))
    for phase, operation in (("retention", lambda: retain_capture(directory, run)),
                             ("analysis", lambda: observations(run, mode, token))):
        try:
            value = operation()
            if phase == "analysis":
                result = value
                write(directory / "observations.json", result)
        except BaseException as error:
            failures.append({"phase": phase, "traceback": traceback.format_exc()})
            if not isinstance(error, Exception) and interruption is None:
                interruption = error
    write(directory / "failures.json", failures)
    write(directory / "sha256.json", {p.name: sha(p) for p in sorted(directory.iterdir()) if p.is_file()})
    if interruption is not None:
        raise interruption
    return {"run": directory.name, "failures": failures, "observations": result}


async def main():
    global CaptureRun, CaptureServer, ServerPolicy, generate_certificate
    global analyze_http2, decode_header_block, split_frames, Decoder, retain_capture
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "consumer", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    source, consumer, output = (p.resolve() for p in (args.source, args.consumer, args.output))
    check(sys.platform == "linux", "run driver and Linux consumer together in WSL")
    windows_source = subprocess.check_output(["wslpath", "-w", str(source)], text=True).strip()
    git = ["/mnt/c/Program Files/Git/cmd/git.exe", "-C", windows_source]
    check(subprocess.check_output([*git, "status", "--porcelain"]) == b"", "source checkout is dirty")
    check(consumer.is_file() and os.access(consumer, os.X_OK), "consumer must be an executable file")
    retention = source / "target/tmp/safari-ios-comparison/capture.py"
    check(retention.is_file(), "retention helper is missing")
    sys.path.insert(0, str(source))
    from scripts.capture.http2_session import CaptureRun, CaptureServer, ServerPolicy, generate_certificate
    from scripts.capture.http2_analysis import analyze_http2, decode_header_block, split_frames
    from hpack import Decoder
    spec = importlib.util.spec_from_file_location("retained_ios_capture", retention)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    retain_capture = module.retain_capture
    output.mkdir(parents=True, exist_ok=False)
    prep = Path(__file__).resolve().parent
    identities = [Path(__file__).resolve(), consumer, retention, prep / "preparation-sha256.json",
                  *(prep / "consumer" / name for name in ("main.go", "go.mod", "go.sum")),
                  source / "scripts/capture/http2_session.py", source / "scripts/capture/http2_analysis.py"]
    write(output / "identity.json", {"source": str(source),
        "commit": subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip(),
        "python": sys.version, "platform": platform.platform(), "openssl": ssl.OPENSSL_VERSION,
        "packages": {name: importlib.metadata.version(name) for name in ("h2", "hpack", "cryptography")},
        "sha256": {str(path): sha(path) for path in identities},
        "scope": "controlled peer wire observations; not browser fidelity or performance"})
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy") and k.upper() != "SSLKEYLOGFILE"}
    results = []
    try:
        for mode in ("baseline", "boundary"):
            for index in range(1, 4):
                result = await capture(consumer, output, mode, index, env)
                results.append(result)
                write(output / f"summary-{len(results)}.json", results)
                if result["failures"]:
                    return 1
        return int(any(r["observations"].get("source_prediction_matches") is False for r in results))
    except BaseException:
        results.append({"run": f"{mode}-{index}", "interrupted": traceback.format_exc()})
        raise
    finally:
        write(output / "summary.json", results)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
