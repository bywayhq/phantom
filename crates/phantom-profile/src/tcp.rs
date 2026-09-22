//! TCP socket options a client applies to its outgoing connections.

use std::{error::Error, fmt, time::Duration};

/// Largest keepalive idle time or interval, in whole seconds.
///
/// Linux rejects `TCP_KEEPIDLE` and `TCP_KEEPINTVL` values above 32,767
/// seconds, so a larger value could not be applied on every supported host.
pub const MAX_TCP_KEEPALIVE_SECONDS: u64 = 32_767;

/// TCP keepalive timing applied to each outgoing connection.
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

/// TCP socket options applied to each outgoing connection before it connects.
///
/// A value applies to every TCP connection a client opens: to an origin, to an
/// HTTP, HTTPS, or SOCKS5 proxy, and for a SOCKS5 UDP association's control
/// connection. A field that asks for nothing leaves the socket at its
/// operating-system default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSettings {
    /// Whether to disable Nagle's algorithm with `TCP_NODELAY`.
    ///
    /// `false` leaves the option untouched, which keeps Nagle's algorithm
    /// enabled on every supported operating system.
    pub nodelay: bool,
    /// Keepalive timing, or `None` to leave `SO_KEEPALIVE` untouched.
    pub keepalive: Option<TcpKeepalive>,
}

impl TcpSettings {
    /// Validates settings that are independent of the host operating system.
    pub fn validate(&self) -> Result<(), InvalidTcpSettings> {
        if let Some(keepalive) = self.keepalive {
            validate_keepalive_seconds(keepalive.idle, "keepalive.idle")?;
            if let Some(interval) = keepalive.interval {
                validate_keepalive_seconds(interval, "keepalive.interval")?;
            }
        }
        Ok(())
    }
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
