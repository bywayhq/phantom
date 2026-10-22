"""HTTP/1 connection timers and DNS-cache declaration values."""

from .declarations import (
    MAX_U32,
    DeclarationError,
    bounded_integer,
    choice,
    keys,
    validate_duration,
)


def validate_http1_values(values):
    # Compiled declarations fit both 32-bit and 64-bit usize. Custom typed
    # settings retain their native host-sized range.
    bounded_integer(
        values["max_connections_per_origin"], 1, MAX_U32, "connection limit"
    )
    timeout = values["idle_timeout"]
    if not isinstance(timeout, dict):
        raise DeclarationError("HTTP/1.1 idle timeout must be a typed record")
    kind = choice(
        timeout.get("kind"),
        ("Unlimited", "CheckedOnRequest", "ClosedOnTimer"),
        "HTTP/1.1 idle timeout",
    )
    if kind == "Unlimited":
        keys(timeout, ("kind",), "HTTP/1.1 idle timeout")
        return
    keys(timeout, ("kind", "duration"), "HTTP/1.1 idle timeout")
    validate_duration(timeout["duration"], "HTTP/1.1 idle timeout")
    duration = timeout["duration"]
    if kind == "ClosedOnTimer" and (
        duration["seconds"] > 65_535
        or (duration["seconds"] == 65_535 and duration["nanoseconds"] != 0)
    ):
        raise DeclarationError(
            "HTTP/1.1 timer idle limit must be at most 65535 seconds"
        )


def validate_dns_values(values):
    policy = values["address_failure_policy"]
    keys(policy, ("kind", "max_unusable_addresses"), "DNS address failure policy")
    kind = choice(policy["kind"], ("Ignore", "Record"), "DNS address failure policy")
    if kind == "Ignore":
        if policy["max_unusable_addresses"] is not None:
            raise DeclarationError(
                "Ignore address failure policy requires a null limit"
            )
    else:
        bounded_integer(
            policy["max_unusable_addresses"], 1, MAX_U32, "unusable address limit"
        )
    choice(values["system_ttl"], ("Ignore", "FirefoxWindows"), "system DNS TTL policy")
    bounded_integer(values["max_entries"], 1, MAX_U32, "DNS cache entry limit")
    for field in ("ttl", "min_record_ttl", "stale_grace"):
        validate_duration(values[field], field)
    if values["negative_ttl"] is not None:
        validate_duration(values["negative_ttl"], "negative_ttl")
