//! TCP socket options and connection behavior a client applies to its
//! outgoing connections.

use std::{error::Error, fmt, num::NonZeroU32, time::Duration};

/// Largest keepalive idle time or interval, in whole seconds.
///
/// Linux rejects `TCP_KEEPIDLE` and `TCP_KEEPINTVL` values above 32,767
/// seconds, so a larger value could not be applied on every supported host.
pub const MAX_TCP_KEEPALIVE_SECONDS: u64 = 32_767;

/// Largest delay before a second concurrent connection attempt.
pub const MAX_TCP_FALLBACK_DELAY: Duration = Duration::from_secs(10);

/// Largest [`TcpKeepaliveSchedule::probe_count`].
///
/// Firefox clamps its keepalive probe count to `kMaxTCPKeepCount`
/// (`netwerk/base/nsSocketTransportService2.h:62` at tag
/// `FIREFOX_157_0_RELEASE`).
pub const MAX_TCP_KEEPALIVE_PROBES: u32 = 127;

/// Largest [`TcpKeepaliveSchedule::short_lived_time`], in whole seconds.
///
/// Firefox clamps `network.http.tcp_keepalive.short_lived_time` to
/// `1..=300` (`netwerk/protocol/http/nsHttpHandler.cpp:1897-1902` at tag
/// `FIREFOX_157_0_RELEASE`).
pub const MAX_TCP_SHORT_LIVED_SECONDS: u64 = 300;

/// TCP keepalive timing applied to a socket.
///
/// Setting a keepalive also enables `SO_KEEPALIVE`. On Windows both values
/// are applied together through `SIO_KEEPALIVE_VALS`, which has no
/// operating-system default for either one, so [`Self::interval`] is
/// required there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpKeepalive {
    /// Idle time before the first keepalive probe.
    ///
    /// This is `TCP_KEEPIDLE` on Linux, `TCP_KEEPALIVE` on Apple platforms,
    /// and the keepalive time of `SIO_KEEPALIVE_VALS` on Windows. It must be
    /// a whole number of seconds in `1..=`[`MAX_TCP_KEEPALIVE_SECONDS`].
    pub idle: Duration,
    /// Interval between unacknowledged keepalive probes.
    ///
    /// `None` leaves the operating-system default where one exists. A value
    /// has the same bounds as [`Self::idle`].
    pub interval: Option<Duration>,
}

/// Keepalive that follows what an HTTP connection is doing, as Firefox's
/// `nsHttpConnection` sets it.
///
/// Every value is applied to the connected socket, never before `connect`:
///
/// - When a connection opens for a request, and again whenever an HTTP/1
///   request is dispatched on it, keepalive is enabled with
///   [`Self::short_lived_idle`], and a switch to long-lived keepalive is
///   scheduled. A connection opened for a TLS origin applies it before the
///   TLS handshake.
/// - At the switch the connection gets [`Self::long_lived_idle`], unless it
///   is idle with no request outstanding; then it keeps the short-lived
///   values until its next request.
/// - A connection that negotiates HTTP/2 disables keepalive.
/// - An HTTP/1 connection upgraded to another protocol, such as WebSocket,
///   switches to long-lived keepalive at once.
///
/// The probe interval is the whole seconds the connection's attempt took to
/// connect, at least [`Self::minimum_interval`]. An attempt starts when the
/// host lookup starts, or, for the backup attempt of a
/// [`TcpBackupConnection`], when that attempt starts. The switch comes [`Self::short_lived_time`]
/// less its remainder modulo [`Self::short_lived_idle`], plus
/// [`Self::probe_count`] intervals, plus two seconds, after the request's
/// dispatch.
///
/// Phantom applies the interval wherever the host can set one; see
/// [`TcpKeepalive`] for how each operating system takes the values. A change
/// reaches the socket before the connection's next read or write, so a
/// connection nobody reads or writes takes it late.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpKeepaliveSchedule {
    /// Idle time while a request is outstanding or the connection has not
    /// yet switched to long-lived keepalive.
    ///
    /// It has the bounds of [`TcpKeepalive::idle`].
    pub short_lived_idle: Duration,
    /// Idle time after the switch, and from an upgrade on.
    ///
    /// It has the bounds of [`TcpKeepalive::idle`].
    pub long_lived_idle: Duration,
    /// Smallest probe interval.
    ///
    /// It has the bounds of [`TcpKeepalive::idle`].
    pub minimum_interval: Duration,
    /// Base time from a request's dispatch until the switch.
    ///
    /// It must be a whole number of seconds in
    /// `1..=`[`MAX_TCP_SHORT_LIVED_SECONDS`].
    pub short_lived_time: Duration,
    /// Keepalive probes the switch time leaves room for, in
    /// `1..=`[`MAX_TCP_KEEPALIVE_PROBES`].
    ///
    /// Phantom does not set the operating system's probe count.
    pub probe_count: u32,
}

/// When and how a client sets TCP keepalive.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TcpKeepalivePolicy {
    /// Leaves `SO_KEEPALIVE` and its timing at the operating-system default.
    #[default]
    Unchanged,
    /// Applies one timing to each socket before it connects.
    Fixed(TcpKeepalive),
    /// Changes the timing over each HTTP connection's life.
    Schedule(TcpKeepaliveSchedule),
}

/// Concurrent attempts across a host's resolved addresses.
///
/// This is the Happy Eyeballs behavior of Chromium's `TcpConnectJob`, applied
/// to one complete set of resolved addresses. Line numbers are for Chromium
/// tag `153.0.8010.48`:
///
/// - The first attempt prefers IPv6 (`net/socket/tcp_connect_job.h:211`).
///   After an attempt fails, the next one prefers the other address family
///   (`net/socket/tcp_connect_job_connector.cc:300-303`).
/// - [`Self::fallback_delay`] after the first attempt starts, a second
///   concurrent attempt begins. From then on one attempt prefers IPv6 and the
///   other IPv4; an attempt already on IPv4 continues as the IPv4 one
///   (`net/socket/tcp_connect_job.cc:450-473`, `:580-616`, `:691-694`).
/// - An attempt uses the other family when its preferred family has no
///   untried address. No address is tried twice and at most two attempts run
///   at once (`net/socket/tcp_connect_job.cc:703-746`).
/// - The first established connection wins and the other attempt is
///   cancelled. When every attempt fails, the most recent failure is
///   returned (`net/socket/tcp_connect_job.cc:406-431`, `:946-958`).
///
/// Addresses keep the resolver's order within each family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpAddressRacing {
    /// Delay after the first attempt starts before the second one begins.
    ///
    /// It must be nonzero and at most [`MAX_TCP_FALLBACK_DELAY`].
    pub fallback_delay: Duration,
}

/// A backup connection restricted to IPv4, started when the first attempt
/// is slow, as Firefox's `DnsAndConnectSocket` opens one, except for what
/// happens to the slower attempt.
///
/// - The primary attempt tries the resolved addresses one at a time in
///   resolver order.
/// - [`Self::delay`] after the primary attempt starts connecting, while it
///   has not connected, a backup attempt starts. It tries only the IPv4
///   addresses, one at a time in resolver order.
/// - Each attempt moves to its next address only after a connect is refused,
///   finds the network or host unreachable or the address unavailable, is
///   denied, or times out; any other failure ends that attempt.
/// - The first established connection wins and the other attempt is
///   cancelled. When both attempts fail, the most recent failure is
///   returned. A primary attempt that fails before the delay ends the
///   connection without a backup.
///
/// Firefox keeps the slower attempt's connection, finishes its TLS
/// handshake, and pools it. Phantom closes the slower attempt's socket
/// instead, so a server that already answered its SYN sees the connection
/// end without a request. No built-in recipe uses this selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpBackupConnection {
    /// Delay after the primary attempt starts before the backup one begins.
    ///
    /// It must be nonzero and at most [`MAX_TCP_FALLBACK_DELAY`].
    pub delay: Duration,
}

/// Which connect failures move an attempt to its next address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TcpAddressAdvance {
    /// Every failure.
    #[default]
    AfterAnyFailure,
    /// A refused connect, an unreachable network or host, an unavailable
    /// address, a denied connect, or a timeout, as Firefox moves on after
    /// them (`netwerk/base/nsSocketTransport2.cpp:169-200`, `:1747-1755` at
    /// tag `FIREFOX_157_0_RELEASE`). Any other failure ends the attempt.
    AfterRefusalOrTimeout,
}

/// How a client chooses among a host's resolved addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpAddressSelection {
    /// Tries the addresses one at a time in resolver order, moving on after
    /// the failures the value names.
    Sequential(TcpAddressAdvance),
    /// Races the address families as [`TcpAddressRacing`] describes.
    Racing(TcpAddressRacing),
    /// Opens an IPv4 backup connection as [`TcpBackupConnection`] describes.
    Backup(TcpBackupConnection),
}

impl Default for TcpAddressSelection {
    /// One address at a time, moving on after any failure.
    fn default() -> Self {
        Self::Sequential(TcpAddressAdvance::AfterAnyFailure)
    }
}

/// TCP socket options and address selection applied to each outgoing
/// connection.
///
/// A value applies to every TCP connection a client opens: to an origin, to an
/// HTTP, HTTPS, or SOCKS5 proxy, and for a SOCKS5 UDP association's control
/// connection. A field that asks for nothing leaves the socket at its
/// operating-system default. [`Self::default`] asks for nothing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpSettings {
    /// Whether to disable Nagle's algorithm with `TCP_NODELAY`.
    ///
    /// `false` leaves the option untouched, which keeps Nagle's algorithm
    /// enabled on every supported operating system.
    pub nodelay: bool,
    /// Socket send buffer size in bytes, set with `SO_SNDBUF` before the
    /// socket connects, or `None` to keep the operating-system default.
    ///
    /// Linux caps the value at `net.core.wmem_max` and reports twice what it
    /// keeps.
    pub send_buffer_size: Option<NonZeroU32>,
    /// When and how keepalive is set.
    pub keepalive: TcpKeepalivePolicy,
    /// How the resolved addresses are tried.
    pub address_selection: TcpAddressSelection,
}

impl TcpSettings {
    /// Validates settings that are independent of the host operating system.
    pub fn validate(&self) -> Result<(), InvalidTcpSettings> {
        if let Some(size) = self.send_buffer_size
            && i32::try_from(size.get()).is_err()
        {
            return Err(InvalidTcpSettings::new(
                "send_buffer_size",
                "send buffer size must fit in a signed 32-bit socket option",
            ));
        }
        match self.keepalive {
            TcpKeepalivePolicy::Unchanged => {}
            TcpKeepalivePolicy::Fixed(keepalive) => {
                validate_keepalive_seconds(keepalive.idle, "keepalive.idle")?;
                if let Some(interval) = keepalive.interval {
                    validate_keepalive_seconds(interval, "keepalive.interval")?;
                }
            }
            TcpKeepalivePolicy::Schedule(schedule) => validate_schedule(schedule)?,
        }
        match self.address_selection {
            TcpAddressSelection::Sequential(_) => Ok(()),
            TcpAddressSelection::Racing(racing) => {
                validate_delay(racing.fallback_delay, "address_selection.fallback_delay")
            }
            TcpAddressSelection::Backup(backup) => {
                validate_delay(backup.delay, "address_selection.delay")
            }
        }
    }
}

fn validate_schedule(schedule: TcpKeepaliveSchedule) -> Result<(), InvalidTcpSettings> {
    validate_keepalive_seconds(schedule.short_lived_idle, "keepalive.short_lived_idle")?;
    validate_keepalive_seconds(schedule.long_lived_idle, "keepalive.long_lived_idle")?;
    validate_keepalive_seconds(schedule.minimum_interval, "keepalive.minimum_interval")?;
    let time = schedule.short_lived_time;
    if time.subsec_nanos() != 0 || !(1..=MAX_TCP_SHORT_LIVED_SECONDS).contains(&time.as_secs()) {
        return Err(InvalidTcpSettings::new(
            "keepalive.short_lived_time",
            "the short-lived time must be whole seconds in 1..=300",
        ));
    }
    if !(1..=MAX_TCP_KEEPALIVE_PROBES).contains(&schedule.probe_count) {
        return Err(InvalidTcpSettings::new(
            "keepalive.probe_count",
            "the probe count must be in 1..=127",
        ));
    }
    Ok(())
}

fn validate_keepalive_seconds(
    value: Duration,
    field: &'static str,
) -> Result<(), InvalidTcpSettings> {
    if value.subsec_nanos() != 0 || !(1..=MAX_TCP_KEEPALIVE_SECONDS).contains(&value.as_secs()) {
        return Err(InvalidTcpSettings::new(
            field,
            "keepalive times must be whole seconds in 1..=32767",
        ));
    }
    Ok(())
}

fn validate_delay(delay: Duration, field: &'static str) -> Result<(), InvalidTcpSettings> {
    if delay.is_zero() || delay > MAX_TCP_FALLBACK_DELAY {
        return Err(InvalidTcpSettings::new(
            field,
            "the delay must be nonzero and at most 10 seconds",
        ));
    }
    Ok(())
}

/// Error returned when TCP profile settings cannot be applied as written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidTcpSettings {
    field: &'static str,
    message: Box<str>,
}

impl InvalidTcpSettings {
    fn new(field: &'static str, message: impl Into<Box<str>>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for InvalidTcpSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid TCP {}: {}", self.field, self.message)
    }
}

impl Error for InvalidTcpSettings {}

#[cfg(test)]
mod tests;
