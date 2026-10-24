//! tcp settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

tokens!(TcpAddressAdvance, AfterAnyFailure, AfterRefusalOrTimeout);
tokens!(
    SocksProxyDnsFeedback,
    AllConnectFailures,
    InitialConnectFailures
);
record!(TcpKeepalive, idle, interval);
record!(
    TcpKeepaliveSchedule,
    short_lived_idle,
    long_lived_idle,
    minimum_interval,
    short_lived_time,
    probe_count,
    set_interval,
    set_probe_count
);
record!(TcpAddressRacing, fallback_delay);
record!(
    TcpBackupConnection,
    delay,
    known_family_backup_timeout,
    socks_proxy_dns_feedback
);
record!(TcpPortRandomization, minimum_windows_build);
record!(
    TcpSettings,
    nodelay,
    send_buffer_size,
    keepalive,
    address_selection,
    port_randomization
);

impl Encode for TcpKeepalivePolicy {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Unchanged => object!(e, f, "kind" => "Unchanged"),
            Self::Fixed(v) => {
                object!(e, f, "kind" => "Fixed", "idle" => &v.idle, "interval" => &v.interval)
            }
            Self::Schedule(v) => object!(e, f, "kind" => "Schedule",
                "short_lived_idle" => &v.short_lived_idle, "long_lived_idle" => &v.long_lived_idle,
                "minimum_interval" => &v.minimum_interval, "short_lived_time" => &v.short_lived_time,
                "probe_count" => &v.probe_count, "set_interval" => &v.set_interval, "set_probe_count" => &v.set_probe_count),
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}
impl Encode for TcpAddressSelection {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Sequential(advance) => {
                object!(e, f, "kind" => "Sequential", "advance" => advance)
            }
            Self::Racing(v) => {
                object!(e, f, "kind" => "Racing", "fallback_delay" => &v.fallback_delay)
            }
            Self::Backup(v) => object!(e, f, "kind" => "Backup", "delay" => &v.delay,
                "known_family_backup_timeout" => &v.known_family_backup_timeout,
                "socks_proxy_dns_feedback" => &v.socks_proxy_dns_feedback),
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}
