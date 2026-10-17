"""Run the existing public-client peers as bounded release smoke checks."""

import json
import queue
import subprocess
import threading


def messages(process):
    result = queue.Queue()

    def read():
        for line in process.stdout:
            result.put(line)
        result.put(None)

    threading.Thread(target=read, daemon=True).start()
    return result


def expect(events, name):
    line = events.get(timeout=45)
    if line is None or json.loads(line).get("event") != name:
        raise RuntimeError(f"expected {name}, received {line!r}")


def send(process, command):
    process.stdin.write(command + "\n")
    process.stdin.flush()


def check(binary, output):
    for protocol in ("h1", "h2", "h3"):
        for profile in ("chrome", "firefox"):
            for cold in (False, True):
                scenario = output / f"{protocol}-{profile}-{'cold' if cold else 'warm'}"
                scenario.mkdir(parents=True)
                config, ready = scenario / "config.json", scenario / "ready.json"
                config.write_text(
                    json.dumps(
                        {
                            "protocol": protocol,
                            "profile": profile,
                            "cold": cold,
                            "requests": 4,
                            "warmup": 1,
                            "bytes": 1024,
                        }
                    ),
                    encoding="utf-8",
                )
                processes = []
                try:
                    with (scenario / "stderr.log").open(
                        "w", encoding="utf-8"
                    ) as errors:

                        def start(
                            mode,
                            result,
                            config=config,
                            ready=ready,
                            processes=processes,
                        ):
                            process = subprocess.Popen(
                                [
                                    str(binary),
                                    mode,
                                    str(config),
                                    str(ready),
                                    str(result),
                                ],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=errors,
                                text=True,
                                encoding="utf-8",
                            )
                            processes.append(process)
                            return process, messages(process)

                        peer, peer_events = start("serve", scenario / "peer.json")
                        expect(peer_events, "ready")
                        client, client_events = start("run", scenario / "client.json")
                        expect(client_events, "ready")
                        send(client, "go")
                        expect(client_events, "phase_end")
                        send(peer, "snapshot")
                        expect(peer_events, "snapshotted")
                        send(client, "save")
                        expect(client_events, "saved")
                        if client.wait(timeout=10):
                            raise RuntimeError(f"client failed: {scenario}")
                        send(peer, "stop")
                        expect(peer_events, "stopped")
                        if peer.wait(timeout=10):
                            raise RuntimeError(f"peer failed: {scenario}")
                    samples = json.loads(
                        (scenario / "client.json").read_text(encoding="utf-8")
                    )["samples"]
                    peer_result = json.loads(
                        (scenario / "peer.json").read_text(encoding="utf-8")
                    )
                    if len(samples) != 4 or any(
                        row["error"] or row["bytes"] != 1024 for row in samples
                    ):
                        raise RuntimeError(f"incomplete request or body: {scenario}")
                    if peer_result["requests"] != 5 or peer_result["failures"]:
                        raise RuntimeError(
                            f"peer count or failure: {scenario}: {peer_result}"
                        )
                finally:
                    for process in processes:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=10)
                print(f"Protocol smoke passed: {scenario.name}", flush=True)
