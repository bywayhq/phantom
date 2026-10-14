"""Closed TCP socket, keepalive and address-selection policies."""

from .declarations import (
    MAX_U32,
    DeclarationError,
    boolean,
    bounded_integer,
    choice,
    duration_is_zero,
    keys,
    validate_duration,
)
from .rust_literals import (
    rust_duration,
    rust_option,
)


def tcp_whole_seconds(value, maximum, context):
    validate_duration(value, context)
    if value["nanoseconds"] != 0 or not 1 <= value["seconds"] <= maximum:
        raise DeclarationError(f"{context} must be whole seconds in 1..={maximum}")


def tcp_delay(value):
    validate_duration(value, "TCP fallback delay")
    if (
        duration_is_zero(value)
        or value["seconds"] > 10
        or (value["seconds"] == 10 and value["nanoseconds"] != 0)
    ):
        raise DeclarationError(
            "TCP fallback delay must be nonzero and at most 10 seconds"
        )


def validate_tcp_values(values):
    boolean(values["nodelay"], "nodelay")
    if values["send_buffer_size"] is not None:
        bounded_integer(values["send_buffer_size"], 1, (1 << 31) - 1, "TCP send buffer")
    keepalive = values["keepalive"]
    if not isinstance(keepalive, dict):
        raise DeclarationError("TCP keepalive must be a typed policy")
    kind = choice(
        keepalive.get("kind"),
        ("Unchanged", "Fixed", "Schedule"),
        "TCP keepalive policy",
    )
    if kind == "Unchanged":
        keys(keepalive, ("kind",), "TCP keepalive")
    elif kind == "Fixed":
        keys(keepalive, ("kind", "idle", "interval"), "TCP keepalive")
        tcp_whole_seconds(keepalive["idle"], 32_767, "TCP keepalive idle")
        if keepalive["interval"] is not None:
            tcp_whole_seconds(keepalive["interval"], 32_767, "TCP keepalive interval")
    else:
        keys(
            keepalive,
            (
                "kind",
                "short_lived_idle",
                "long_lived_idle",
                "minimum_interval",
                "short_lived_time",
                "probe_count",
            ),
            "TCP keepalive schedule",
        )
        for field in ("short_lived_idle", "long_lived_idle", "minimum_interval"):
            tcp_whole_seconds(keepalive[field], 32_767, field)
        tcp_whole_seconds(keepalive["short_lived_time"], 300, "short_lived_time")
        bounded_integer(keepalive["probe_count"], 1, 127, "TCP keepalive probe count")
    selection = values["address_selection"]
    if not isinstance(selection, dict):
        raise DeclarationError("TCP address selection must be a typed policy")
    kind = choice(
        selection.get("kind"),
        ("Sequential", "Racing", "Backup"),
        "TCP address selection",
    )
    if kind == "Sequential":
        keys(selection, ("kind", "advance"), "TCP sequential addresses")
        choice(
            selection["advance"],
            ("AfterAnyFailure", "AfterRefusalOrTimeout"),
            "TCP address advance",
        )
    elif kind == "Racing":
        keys(selection, ("kind", "fallback_delay"), "TCP racing addresses")
        tcp_delay(selection["fallback_delay"])
    else:
        keys(
            selection,
            ("kind", "delay", "known_family_backup_timeout"),
            "TCP backup addresses",
        )
        tcp_delay(selection["delay"])
        if selection["known_family_backup_timeout"] is not None:
            tcp_whole_seconds(
                selection["known_family_backup_timeout"],
                600,
                "known_family_backup_timeout",
            )
    port = values["port_randomization"]
    if port is not None:
        keys(port, ("minimum_windows_build",), "TCP port randomization")
        bounded_integer(
            port["minimum_windows_build"], 0, MAX_U32, "minimum_windows_build"
        )


def rust_tcp_value(field, value):
    if field == "nodelay":
        return str(value).lower()
    if field == "send_buffer_size":
        return rust_option(
            value,
            lambda size: (
                f'const {{ match std::num::NonZeroU32::new({size}) {{ Some(value) => value, None => panic!("invalid nonzero component literal") }} }}'
            ),
        )
    if field == "port_randomization":
        return rust_option(
            value,
            lambda policy: (
                f"crate::TcpPortRandomization {{ minimum_windows_build: {policy['minimum_windows_build']} }}"
            ),
        )
    kind = value["kind"]
    if field == "keepalive":
        expression = f"crate::TcpKeepalivePolicy::{kind}"
        if kind == "Unchanged":
            return expression
        if kind == "Fixed":
            return (
                expression
                + "(crate::TcpKeepalive { "
                + f"idle: {rust_duration(value['idle'])}, interval: {rust_option(value['interval'], rust_duration)}"
                + " })"
            )
        fields = [
            f"{name}: {rust_duration(value[name])}"
            for name in (
                "short_lived_idle",
                "long_lived_idle",
                "minimum_interval",
                "short_lived_time",
            )
        ]
        fields.append(f"probe_count: {value['probe_count']}")
        return (
            expression + "(crate::TcpKeepaliveSchedule { " + ", ".join(fields) + " })"
        )
    expression = f"crate::TcpAddressSelection::{kind}"
    if kind == "Sequential":
        return expression + f"(crate::TcpAddressAdvance::{value['advance']})"
    if kind == "Racing":
        return (
            expression
            + f"(crate::TcpAddressRacing {{ fallback_delay: {rust_duration(value['fallback_delay'])} }})"
        )
    return (
        expression
        + f"(crate::TcpBackupConnection {{ delay: {rust_duration(value['delay'])}, known_family_backup_timeout: {rust_option(value['known_family_backup_timeout'], rust_duration)} }})"
    )
