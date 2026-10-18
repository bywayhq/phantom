"""Effective workload defaults shared with the native tool's Config schema."""

DEFAULTS = {
    "name": "warm-h2",
    "protocol": "h2",
    "profile": "chrome",
    "route": "direct",
    "concurrency": 1,
    "requests": 2000,
    "warmup": 100,
    "bytes": 1024,
    "method": "GET",
    "upload_bytes": 0,
    "redirects": 0,
    "cancel_after_bytes": 0,
    "consume": "stream",
    "cold": False,
    "origins": 1,
    "server_delay_ms": 0,
    "chunk_bytes": 16384,
    "chunk_delay_ms": 0,
    "gzip": False,
    "template": False,
    "arrival_interval_us": 0,
    "workers": 2,
    "peer_workers": None,
    "speculative_tls": False,
    "proxy_delay_ms": 0,
    "proxy_auth": False,
    "diagnostic_events": 0,
    "diagnostic_snapshot": True,
}


def effective_config(config):
    if not isinstance(config, dict) or config.keys() - DEFAULTS.keys():
        raise ValueError("unknown benchmark configuration fields")
    return DEFAULTS | config


def validate_cancellation(config):
    cutoff = config["cancel_after_bytes"]
    if type(cutoff) is not int or cutoff < 0:
        raise ValueError("invalid cancellation byte threshold")
    if cutoff and (
        config["protocol"] != "h2"
        or config["route"] != "direct"
        or config["consume"] != "stream"
        or config["cold"]
        or config["origins"] != 1
        or config["method"] != "GET"
        or config["gzip"]
        or config["redirects"] != 0
        or config["warmup"] != 1
        or config["concurrency"] != 2
        or config["requests"] < 2
        or config["requests"] % 2
        or cutoff >= config["bytes"]
        or not config["chunk_delay_ms"]
        or config["arrival_interval_us"] != 0
    ):
        raise ValueError(
            "body cancellation requires warm direct H2 streams, one origin and two workers"
        )
