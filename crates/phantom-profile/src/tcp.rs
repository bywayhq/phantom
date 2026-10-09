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
#[non_exhaustive]
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

/// Largest [`TcpBackupConnection::known_family_backup_timeout`], in whole
/// seconds.
///
/// Firefox clamps `network.http.fallback-connection-timeout` to `0..=600`
/// (`netwerk/protocol/http/nsHttpHandler.cpp:1491-1494` at tag
/// `FIREFOX_157_0_RELEASE`), where 0 sets no timeout.
pub const MAX_TCP_BACKUP_TIMEOUT_SECONDS: u64 = 600;

/// A backup connection started when the first attempt is slow, as Firefox's
/// `DnsAndConnectSocket` opens one.
///
/// Line numbers are for Firefox tag `FIREFOX_157_0_RELEASE`:
///
/// - The primary attempt tries the resolved addresses one at a time in
///   resolver order.
/// - [`Self::delay`] after the primary attempt starts connecting, while it
///   has not connected, a backup attempt starts. It tries only the IPv4
///   addresses, one at a time in resolver order
///   (`netwerk/protocol/http/DnsAndConnectSocket.cpp:179-186`, `:222-225`,
///   `:242-265`).
/// - Each attempt moves to its next address only after a connect is refused,
///   finds the network or host unreachable or the address unavailable, is
///   denied, or times out; any other failure ends that attempt.
/// - The first established connection carries the request. The other
///   attempt keeps connecting, and its connection joins the origin's pool
///   without a request, as Firefox's does (`DnsAndConnectSocket.cpp:671-745`);
///   see the HTTP pools for what happens to it there. When both attempts
///   fail, the most recent failure is returned. A primary attempt that fails
///   before the delay ends the connection without a backup.
///
/// A pool remembers, for each origin and route across every runtime, the
/// address family of the first connection that succeeds, and later
/// connections to it try that family alone, both attempts, the backup with
/// [`Self::known_family_backup_timeout`] on each connect
/// (`DnsAndConnectSocket.cpp:167-178`, `:1150-1164`, `:1295-1303`;
/// `netwerk/protocol/http/ConnectionEntry.cpp:125-149`). An attempt whose
/// remembered family has no address, or none left after a refusal, an
/// unreachable network or host, or a timeout, tries the other family, and
/// the entry then remembers the family that connects
/// (`DnsAndConnectSocket.cpp:1014-1046`, `:1063`, `:1402-1412`;
/// `netwerk/base/nsSocketTransport2.cpp:1799-1825`).
///
/// A connection that the caller cannot pool, such as one to a proxy, closes
/// the slower attempt instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpBackupConnection {
    /// Delay after the primary attempt starts before the backup one begins.
    ///
    /// It must be nonzero and at most [`MAX_TCP_FALLBACK_DELAY`].
    pub delay: Duration,
    /// Longest wait for each connect of the backup attempt once the origin's
    /// address family is remembered, or `None` for no limit.
    ///
    /// A connect that takes longer counts as timed out, so the attempt moves
    /// to its next address. It must be whole seconds in
    /// `1..=`[`MAX_TCP_BACKUP_TIMEOUT_SECONDS`].
    pub known_family_backup_timeout: Option<Duration>,
}

/// Which connect failures move an attempt to its next address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
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
#[non_exhaustive]
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

/// Asks Windows to choose each socket's local port at random, with
/// `SO_RANDOMIZE_PORT`, rather than the next free port in sequence.
///
/// A server sees the difference in the source ports of successive
/// connections. Windows rejects the option on a socket that is already
/// bound, so it is set after the other options and before a source binding
/// binds the socket; a source-bound connection gets a random port too. A
/// rejection fails the connection attempt, as for every other option.
///
/// Only Windows has the option. Elsewhere the setting changes nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpPortRandomization {
    /// The first Windows build number that gets the option.
    ///
    /// It applies on Windows version 10.0 from this build on, and on any
    /// later major version. Windows 10 and 11 both report version 10.0;
    /// build 22621 is Windows 11 22H2. Older Windows connects from the
    /// operating system's sequential ports.
    pub minimum_windows_build: u32,
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
    /// Whether and from which Windows build to ask Windows for a random
    /// local port, or `None` to keep the operating system's choice.
    pub port_randomization: Option<TcpPortRandomization>,
}

impl TcpSettings {
    /// Validates settings that are independent of the host operating system.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTcpSettings`] for an oversized send buffer, invalid
    /// keepalive timing or probe count, or an invalid connection fallback
    /// delay or backup timeout. Host support is checked by the transport.
    pub fn validate(&self) -> Result<(), InvalidTcpSettings> {
        if let Some(size) = self.send_buffer_size
            && i32::try_from(size.get()).is_err()
        {
            return Err(InvalidTcpSettings::new(
                crate::ValidationErrorKind::OutOfRange,
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
                validate_delay(backup.delay, "address_selection.delay")?;
                match backup.known_family_backup_timeout {
                    Some(timeout)
                        if timeout.subsec_nanos() != 0
                            || !(1..=MAX_TCP_BACKUP_TIMEOUT_SECONDS)
                                .contains(&timeout.as_secs()) =>
                    {
                        Err(InvalidTcpSettings::new(
                            crate::ValidationErrorKind::OutOfRange,
                            "address_selection.known_family_backup_timeout",
                            "the backup timeout must be whole seconds in 1..=600",
                        ))
                    }
                    _ => Ok(()),
                }
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
            crate::ValidationErrorKind::OutOfRange,
            "keepalive.short_lived_time",
            "the short-lived time must be whole seconds in 1..=300",
        ));
    }
    if !(1..=MAX_TCP_KEEPALIVE_PROBES).contains(&schedule.probe_count) {
        return Err(InvalidTcpSettings::new(
            crate::ValidationErrorKind::OutOfRange,
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
            crate::ValidationErrorKind::OutOfRange,
            field,
            "keepalive times must be whole seconds in 1..=32767",
        ));
    }
    Ok(())
}

fn validate_delay(delay: Duration, field: &'static str) -> Result<(), InvalidTcpSettings> {
    if delay.is_zero() || delay > MAX_TCP_FALLBACK_DELAY {
        return Err(InvalidTcpSettings::new(
            crate::ValidationErrorKind::OutOfRange,
            field,
            "the delay must be nonzero and at most 10 seconds",
        ));
    }
    Ok(())
}

/// Error returned when TCP profile settings cannot be applied as written.
///
/// Use [`Self::kind`] for recovery and [`Self::field`] and [`Self::reason`]
/// for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidTcpSettings {
    kind: crate::ValidationErrorKind,
    field: &'static str,
    message: Box<str>,
}

impl InvalidTcpSettings {
    /// Returns the stable recovery category.
    #[must_use]
    pub const fn kind(&self) -> crate::ValidationErrorKind {
        self.kind
    }

    fn new(
        kind: crate::ValidationErrorKind,
        field: &'static str,
        message: impl Into<Box<str>>,
    ) -> Self {
        Self {
            kind,
            field,
            message: message.into(),
        }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the reason the setting is invalid.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.message
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
