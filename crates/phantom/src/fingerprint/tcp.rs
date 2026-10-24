//! Complete TCP description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{
    SocksProxyDnsFeedback, TcpAddressAdvance, TcpAddressRacing, TcpAddressSelection,
    TcpBackupConnection, TcpKeepalive, TcpKeepalivePolicy, TcpKeepaliveSchedule,
    TcpPortRandomization, TcpSettings,
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
                    "set_interval",
                    "set_probe_count",
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
                set_interval: v
                    .member("set_interval", "tcp.keepalive.set_interval")?
                    .boolean("tcp.keepalive.set_interval")?,
                set_probe_count: v
                    .member("set_probe_count", "tcp.keepalive.set_probe_count")?
                    .boolean("tcp.keepalive.set_probe_count")?,
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
            let feedback = v.member(
                "socks_proxy_dns_feedback",
                "tcp.address_selection.socks_proxy_dns_feedback",
            )?;
            v.record(
                &[
                    "kind",
                    "delay",
                    "known_family_backup_timeout",
                    "socks_proxy_dns_feedback",
                ],
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
                socks_proxy_dns_feedback: match feedback
                    .text("tcp.address_selection.socks_proxy_dns_feedback")?
                {
                    "AllConnectFailures" => SocksProxyDnsFeedback::AllConnectFailures,
                    "InitialConnectFailures" => SocksProxyDnsFeedback::InitialConnectFailures,
                    _ => {
                        return Err(json::unsupported(
                            "tcp.address_selection.socks_proxy_dns_feedback",
                        ));
                    }
                },
            }))
        }
        _ => Err(json::unsupported("tcp.address_selection.kind")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn scheduled(interval: &str, count: &str) -> String {
        format!(
            r#"{{"kind":"Schedule","short_lived_idle":{{"seconds":10,"nanoseconds":0}},"long_lived_idle":{{"seconds":600,"nanoseconds":0}},"minimum_interval":{{"seconds":1,"nanoseconds":0}},"short_lived_time":{{"seconds":60,"nanoseconds":0}},"probe_count":8,"set_interval":{interval},"set_probe_count":{count}}}"#
        )
    }

    #[test]
    fn schedule_import_keeps_socket_setters_separate_from_timer_inputs() -> TestResult {
        for (interval, count) in [(false, false), (true, false), (false, true), (true, true)] {
            let payload = scheduled(&interval.to_string(), &count.to_string());
            let value = json::parse(payload.as_bytes())?;
            let TcpKeepalivePolicy::Schedule(schedule) = keepalive(&value)? else {
                return Err("schedule changed kind".into());
            };
            assert_eq!(schedule.set_interval, interval);
            assert_eq!(schedule.set_probe_count, count);
            assert_eq!(schedule.probe_count, 8);
            assert_eq!(schedule.minimum_interval, std::time::Duration::from_secs(1));
        }
        Ok(())
    }

    #[test]
    fn schedule_import_requires_boolean_socket_setters() -> TestResult {
        for invalid in ["null", "0", "1", "\"true\"", "[]"] {
            for payload in [scheduled(invalid, "false"), scheduled("false", invalid)] {
                let value = json::parse(payload.as_bytes())?;
                assert!(keepalive(&value).is_err());
            }
        }
        let complete = scheduled("false", "false");
        for missing in [",\"set_interval\":false", ",\"set_probe_count\":false"] {
            let value = json::parse(complete.replace(missing, "").as_bytes())?;
            assert!(keepalive(&value).is_err());
        }
        Ok(())
    }

    #[test]
    fn socks_proxy_feedback_requires_an_explicit_supported_value() -> TestResult {
        let base = serde_json::json!({
            "kind": "Backup",
            "delay": {"seconds": 0, "nanoseconds": 250_000_000},
            "known_family_backup_timeout": null,
            "socks_proxy_dns_feedback": "AllConnectFailures"
        });
        for (name, expected) in [
            (
                "AllConnectFailures",
                SocksProxyDnsFeedback::AllConnectFailures,
            ),
            (
                "InitialConnectFailures",
                SocksProxyDnsFeedback::InitialConnectFailures,
            ),
        ] {
            let mut value = base.clone();
            value["socks_proxy_dns_feedback"] = name.into();
            let parsed = json::parse(&serde_json::to_vec(&value)?)?;
            let TcpAddressSelection::Backup(backup) = selection(&parsed)? else {
                return Err("backup policy changed kind".into());
            };
            assert_eq!(backup.socks_proxy_dns_feedback, expected);
        }
        for invalid in [
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!(1),
            serde_json::json!("Initial"),
            serde_json::json!([]),
        ] {
            let mut value = base.clone();
            value["socks_proxy_dns_feedback"] = invalid;
            let parsed = json::parse(&serde_json::to_vec(&value)?)?;
            let error = selection(&parsed)
                .err()
                .ok_or("invalid feedback accepted")?;
            assert_eq!(
                error.field(),
                "tcp.address_selection.socks_proxy_dns_feedback"
            );
        }
        let mut missing = base;
        missing
            .as_object_mut()
            .ok_or("backup must be an object")?
            .remove("socks_proxy_dns_feedback");
        let parsed = json::parse(&serde_json::to_vec(&missing)?)?;
        let error = selection(&parsed)
            .err()
            .ok_or("missing feedback accepted")?;
        assert_eq!(
            error.kind(),
            super::super::FingerprintImportErrorKind::MissingField
        );
        assert_eq!(
            error.field(),
            "tcp.address_selection.socks_proxy_dns_feedback"
        );
        Ok(())
    }
}
