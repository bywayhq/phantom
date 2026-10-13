//! HTTP/1.1 connection policy a client applies to each origin and route.

use std::{error::Error, fmt, num::NonZeroUsize, time::Duration};

/// The longest idle limit [`Http1IdleTimeout::ClosedOnTimer`] accepts, in
/// seconds; see [`Http1Settings::validate`].
const MAX_HTTP1_TIMER_IDLE_SECONDS: u64 = 0xffff;

/// How many HTTP/1.1 connections a client keeps to one origin and route, and
/// when an idle one stops being reused.
///
/// HTTP/1.1 carries one request at a time on a connection, so a browser runs
/// requests to the same host in parallel by opening several connections to
/// it, up to a fixed per-host limit. Idle connections count toward the limit.
/// A request reuses an idle connection before a new one opens, and waits in
/// order once the limit is reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1Settings {
    /// Most HTTP/1.1 connections open at once to one origin and route,
    /// counting idle connections and those still being established.
    pub max_connections_per_origin: NonZeroUsize,
    /// When an idle connection stops being reused.
    pub idle_timeout: Http1IdleTimeout,
}

impl Http1Settings {
    /// Validates the settings.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHttp1Settings`] when a
    /// [`Http1IdleTimeout::ClosedOnTimer`] limit is longer than 65,535
    /// seconds, the most Firefox takes for `network.http.keep-alive.timeout`
    /// (`netwerk/protocol/http/nsHttpHandler.cpp:1352-1356` at tag
    /// `FIREFOX_157_0_RELEASE`).
    pub fn validate(&self) -> Result<(), InvalidHttp1Settings> {
        match self.idle_timeout {
            Http1IdleTimeout::ClosedOnTimer(limit)
                if limit > Duration::from_secs(MAX_HTTP1_TIMER_IDLE_SECONDS) =>
            {
                Err(InvalidHttp1Settings {
                    kind: crate::ValidationErrorKind::OutOfRange,
                    field: "idle_timeout",
                    message: "a timer's idle limit must be at most 65535 seconds",
                })
            }
            _ => Ok(()),
        }
    }
}

/// When an idle HTTP/1.1 connection, one that carries no request, stops being
/// reused.
///
/// A connection joins the idle list after it has carried a request, what
/// Chromium calls a used idle socket, or, for the slower attempt of a
/// [`TcpBackupConnection`](crate::tcp::TcpBackupConnection), once it has
/// connected and finished any TLS handshake. Its idle time counts from then.
///
/// Browsers apply their limits differently. Chromium checks its limit only
/// when a request reaches the pool, which [`Self::CheckedOnRequest`] models.
/// Firefox also closes an idle connection on a timer once its limit passes,
/// whether or not a request comes, which [`Self::ClosedOnTimer`] models.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http1IdleTimeout {
    /// Reuse an idle connection until the server closes it.
    #[default]
    Unlimited,
    /// Close an idle connection instead of reusing it once it has been idle
    /// this long, checked when a request reaches the connections of its
    /// origin and route.
    ///
    /// The request then reuses another idle connection or opens a new one.
    /// Nothing closes an idle connection between requests, and
    /// `CheckedOnRequest(Duration::ZERO)` never reuses one.
    CheckedOnRequest(Duration),
    /// Close an idle connection once it has been idle this long, checked
    /// when a request arrives and by a timer, as Firefox's connection manager
    /// prunes its idle connections.
    ///
    /// One timer serves all of a client's HTTP/1.1 connections, those of
    /// negotiated requests included. It is set when a connection becomes
    /// idle, for the time that connection has left in whole seconds, at least
    /// one, unless it is already set to fire sooner. When it fires it closes
    /// every idle connection idle at least this long and is set again for the
    /// connection that expires next, if any. A connection therefore closes
    /// within a second after its limit, as Firefox's does
    /// (`nsHttpConnection::TimeToLive`,
    /// `netwerk/protocol/http/nsHttpConnection.cpp:1009-1025`;
    /// `netwerk/protocol/http/nsHttpConnectionMgr.cpp:258-271`, `:2572-2625`,
    /// `:4075-4084` at tag `FIREFOX_157_0_RELEASE`). The same timer ends what
    /// a [`TcpBackupConnection`](crate::tcp::TcpBackupConnection) remembers
    /// of an origin with no connection left.
    ///
    /// `ClosedOnTimer(Duration::ZERO)` never reuses an idle connection, and
    /// [`Http1Settings::validate`] rejects a limit over 65,535 seconds.
    ClosedOnTimer(Duration),
}

impl Http1IdleTimeout {
    /// Returns the limit checked when a request arrives, if any.
    ///
    /// [`Self::ClosedOnTimer`] is checked then as well.
    #[must_use]
    pub const fn checked_on_request(self) -> Option<Duration> {
        match self {
            Self::Unlimited => None,
            Self::CheckedOnRequest(timeout) | Self::ClosedOnTimer(timeout) => Some(timeout),
        }
    }

    /// Returns the limit a timer enforces between requests, if any.
    #[must_use]
    pub const fn closed_on_timer(self) -> Option<Duration> {
        match self {
            Self::Unlimited | Self::CheckedOnRequest(_) => None,
            Self::ClosedOnTimer(timeout) => Some(timeout),
        }
    }
}

/// Error returned when HTTP/1.1 profile settings cannot be applied as written.
///
/// Use [`Self::kind`] for recovery and [`Self::field`] and [`Self::reason`]
/// for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidHttp1Settings {
    kind: crate::ValidationErrorKind,
    field: &'static str,
    message: &'static str,
}

impl InvalidHttp1Settings {
    /// Returns the stable recovery category.
    #[must_use]
    pub const fn kind(&self) -> crate::ValidationErrorKind {
        self.kind
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the reason the setting is invalid.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for InvalidHttp1Settings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid HTTP/1.1 {}: {}",
            self.field, self.message
        )
    }
}

impl Error for InvalidHttp1Settings {}

#[cfg(test)]
mod tests {
    use crate::{browser::chrome, browser::firefox};

    #[test]
    fn chromium_154_opens_six_http1_connections_per_origin() {
        // `g_max_sockets_per_group` for the normal pool,
        // `net/socket/client_socket_pool_manager.cc:54-58` at `154.0.8037.58`.
        assert_eq!(chrome::v154_http1().max_connections_per_origin.get(), 6);
    }

    #[test]
    fn firefox_157_opens_six_http1_connections_per_origin() {
        // `network.http.max-persistent-connections-per-server`,
        // `modules/libpref/init/all.js:1153` at `FIREFOX_157_0_RELEASE`.
        assert_eq!(firefox::v157_http1().max_connections_per_origin.get(), 6);
    }

    #[test]
    fn chromium_154_stops_reusing_a_connection_idle_300_seconds() {
        // `g_used_idle_socket_timeout_s`, `net/socket/client_socket_pool.cc:42`
        // at `154.0.8037.58`.
        assert_eq!(
            chrome::v154_http1().idle_timeout,
            crate::Http1IdleTimeout::CheckedOnRequest(std::time::Duration::from_secs(300))
        );
    }

    #[test]
    fn firefox_157_closes_a_connection_idle_115_seconds_on_a_timer() {
        // `network.http.keep-alive.timeout`, `modules/libpref/init/all.js:1136`
        // at `FIREFOX_157_0_RELEASE`.
        let timeout = firefox::v157_http1().idle_timeout;
        assert_eq!(
            timeout,
            crate::Http1IdleTimeout::ClosedOnTimer(std::time::Duration::from_secs(115))
        );
        assert_eq!(timeout.checked_on_request(), timeout.closed_on_timer());
    }

    #[test]
    fn only_the_timer_variant_closes_connections_between_requests() {
        let limit = std::time::Duration::from_secs(5);
        assert_eq!(crate::Http1IdleTimeout::Unlimited.closed_on_timer(), None);
        assert_eq!(
            crate::Http1IdleTimeout::CheckedOnRequest(limit).closed_on_timer(),
            None
        );
        assert_eq!(
            crate::Http1IdleTimeout::ClosedOnTimer(limit).closed_on_timer(),
            Some(limit)
        );
    }

    #[test]
    fn a_timer_idle_limit_is_valid_up_to_firefox_range() {
        let settings = |limit| crate::Http1Settings {
            idle_timeout: crate::Http1IdleTimeout::ClosedOnTimer(limit),
            ..firefox::v157_http1()
        };
        let most = std::time::Duration::from_secs(super::MAX_HTTP1_TIMER_IDLE_SECONDS);
        assert_eq!(settings(most).validate(), Ok(()));
        assert_eq!(settings(std::time::Duration::ZERO).validate(), Ok(()));
        let over = most + std::time::Duration::from_nanos(1);
        for limit in [over, std::time::Duration::MAX] {
            let error = settings(limit).validate().err();
            assert_eq!(error.map(|error| error.field()), Some("idle_timeout"));
        }
    }

    #[test]
    fn the_browser_http1_settings_are_valid() {
        assert_eq!(chrome::v154_http1().validate(), Ok(()));
        assert_eq!(firefox::v157_http1().validate(), Ok(()));
    }
}
