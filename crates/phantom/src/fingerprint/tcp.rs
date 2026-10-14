//! Complete TCP description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{
    TcpAddressAdvance, TcpAddressRacing, TcpAddressSelection, TcpBackupConnection, TcpKeepalive,
    TcpKeepalivePolicy, TcpKeepaliveSchedule, TcpPortRandomization, TcpSettings,
};

pub(super) fn parse(v: &Value) -> Result<TcpSettings> {
    v.record(
        &[
            "nodelay",
            "send_buffer_size",
            "keepalive",
            "address_selection",
            "port_randomization",
        ],
        "tcp",
    )?;
    let settings = TcpSettings {
        nodelay: v.member("nodelay", "tcp.nodelay")?.boolean("tcp.nodelay")?,
        send_buffer_size: v
            .member("send_buffer_size", "tcp.send_buffer_size")?
            .optional(|v| v.nonzero_u32("tcp.send_buffer_size"))?,
        keepalive: keepalive(v.member("keepalive", "tcp.keepalive")?)?,
        address_selection: selection(v.member("address_selection", "tcp.address_selection")?)?,
        port_randomization: v
            .member("port_randomization", "tcp.port_randomization")?
            .optional(ports)?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("tcp", error))?;
    Ok(settings)
}

pub(super) fn ports(v: &Value) -> Result<TcpPortRandomization> {
    v.record(&["minimum_windows_build"], "tcp.port_randomization")?;
    let settings = TcpPortRandomization {
        minimum_windows_build: v
            .member(
                "minimum_windows_build",
                "tcp.port_randomization.minimum_windows_build",
            )?
            .integer("tcp.port_randomization.minimum_windows_build")?,
    };
    Ok(settings)
}

fn keepalive(v: &Value) -> Result<TcpKeepalivePolicy> {
    match v
        .member("kind", "tcp.keepalive.kind")?
        .text("tcp.keepalive.kind")?
    {
        "Unchanged" => {
            v.record(&["kind"], "tcp.keepalive")?;
            Ok(TcpKeepalivePolicy::Unchanged)
        }
        "Fixed" => {
            v.record(&["kind", "idle", "interval"], "tcp.keepalive")?;
            Ok(TcpKeepalivePolicy::Fixed(TcpKeepalive {
                idle: v
                    .member("idle", "tcp.keepalive.idle")?
                    .duration("tcp.keepalive.idle")?,
                interval: v
                    .member("interval", "tcp.keepalive.interval")?
                    .optional(|v| v.duration("tcp.keepalive.interval"))?,
            }))
        }
        "Schedule" => {
            v.record(
                &[
                    "kind",
                    "short_lived_idle",
                    "long_lived_idle",
                    "minimum_interval",
                    "short_lived_time",
                    "probe_count",
                ],
                "tcp.keepalive",
            )?;
            Ok(TcpKeepalivePolicy::Schedule(TcpKeepaliveSchedule {
                short_lived_idle: v
                    .member("short_lived_idle", "tcp.keepalive.short_lived_idle")?
                    .duration("tcp.keepalive.short_lived_idle")?,
                long_lived_idle: v
                    .member("long_lived_idle", "tcp.keepalive.long_lived_idle")?
                    .duration("tcp.keepalive.long_lived_idle")?,
                minimum_interval: v
                    .member("minimum_interval", "tcp.keepalive.minimum_interval")?
                    .duration("tcp.keepalive.minimum_interval")?,
                short_lived_time: v
                    .member("short_lived_time", "tcp.keepalive.short_lived_time")?
                    .duration("tcp.keepalive.short_lived_time")?,
                probe_count: v
                    .member("probe_count", "tcp.keepalive.probe_count")?
                    .integer("tcp.keepalive.probe_count")?,
            }))
        }
        _ => Err(json::unsupported("tcp.keepalive.kind")),
    }
}
fn selection(v: &Value) -> Result<TcpAddressSelection> {
    match v
        .member("kind", "tcp.address_selection.kind")?
        .text("tcp.address_selection.kind")?
    {
        "Sequential" => {
            v.record(&["kind", "advance"], "tcp.address_selection")?;
            let advance = match v
                .member("advance", "tcp.address_selection.advance")?
                .text("tcp.address_selection.advance")?
            {
                "AfterAnyFailure" => TcpAddressAdvance::AfterAnyFailure,
                "AfterRefusalOrTimeout" => TcpAddressAdvance::AfterRefusalOrTimeout,
                _ => return Err(json::unsupported("tcp.address_selection.advance")),
            };
            Ok(TcpAddressSelection::Sequential(advance))
        }
        "Racing" => {
            v.record(&["kind", "fallback_delay"], "tcp.address_selection")?;
            Ok(TcpAddressSelection::Racing(TcpAddressRacing {
                fallback_delay: v
                    .member("fallback_delay", "tcp.address_selection.fallback_delay")?
                    .duration("tcp.address_selection.fallback_delay")?,
            }))
        }
        "Backup" => {
            v.record(
                &["kind", "delay", "known_family_backup_timeout"],
                "tcp.address_selection",
            )?;
            Ok(TcpAddressSelection::Backup(TcpBackupConnection {
                delay: v
                    .member("delay", "tcp.address_selection.delay")?
                    .duration("tcp.address_selection.delay")?,
                known_family_backup_timeout: v
                    .member(
                        "known_family_backup_timeout",
                        "tcp.address_selection.known_family_backup_timeout",
                    )?
                    .optional(|v| {
                        v.duration("tcp.address_selection.known_family_backup_timeout")
                    })?,
            }))
        }
        _ => Err(json::unsupported("tcp.address_selection.kind")),
    }
}
