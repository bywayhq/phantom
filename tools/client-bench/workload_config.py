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
    "diagnostic_events": 0,
    "diagnostic_snapshot": True,
}


def effective_config(config):
    if not isinstance(config, dict) or config.keys() - DEFAULTS.keys():
        raise ValueError("unknown benchmark configuration fields")
    return DEFAULTS | config
