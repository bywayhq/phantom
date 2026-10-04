use http::Method;

/// A reason to repeat a complete wire attempt within one redirect hop.
#[derive(Clone, Copy)]
pub(super) enum ReplayClass {
    CriticalClientHints,
    ProxyAuthentication,
    /// A reused HTTP/1.1 connection closed before any response byte.
    ReusedConnection,
    /// The HTTP/2 or HTTP/3 peer reported that it did not process the
    /// request; bounded by the request-scoped unprocessed-replay budget
    /// rather than once per hop.
    Unprocessed,
    /// A caller-listed retryable response status; bounded by the
    /// request-scoped status-retry budget rather than once per hop.
    Status,
    /// The request's HTTP/2 connection closed itself after an unanswered
    /// PING; bounded per hop by the profile's
    /// [`phantom_profile::Http2Settings::ping_failure_retries`].
    Http2PingFailure,
    /// No HTTP/3 connection could be set up for an exact HTTP/3 request,
    /// which the caller lets fall back to HTTP/2.
    Http2Fallback,
}

impl ReplayClass {
    fn permits(self, method: &Method) -> bool {
        match self {
            Self::CriticalClientHints => method.is_safe(),
            // RFC 9113, section 8.7, and RFC 9114, section 4.1.1: the server
            // did not process the request, so any method may be repeated.
            Self::ProxyAuthentication | Self::Unprocessed => true,
            // No QUIC connection carried the request, so the server
            // processed none of it.
            Self::Http2Fallback => true,
            // Chromium resends after `ERR_HTTP2_PING_FAILED` whatever the
            // method (`net/http/http_network_transaction.cc:2222-2233` at
            // `154.0.8037.58`).
            Self::Http2PingFailure => true,
            // RFC 9110, section 9.2.2: the request may already have reached
            // the origin, so only idempotent methods may be repeated.
            Self::ReusedConnection | Self::Status => method.is_idempotent(),
        }
    }
}

/// Every class except [`ReplayClass::Unprocessed`], [`ReplayClass::Status`],
/// and [`ReplayClass::Http2PingFailure`] replays at most once per redirect
/// hop; the last replays up to the profile's limit per hop.
pub(super) struct ReplayState {
    critical_client_hints: bool,
    proxy_authentication: bool,
    reused_connection: bool,
    http2_fallback: bool,
    unprocessed: usize,
    status: usize,
    http2_ping_failures: u8,
    http2_ping_failure_limit: u8,
}

impl ReplayState {
    /// Replay state for a request whose profile resends a request up to
    /// `http2_ping_failure_limit` times per hop after a PING failure.
    pub(super) const fn new(http2_ping_failure_limit: u8) -> Self {
        Self {
            critical_client_hints: false,
            proxy_authentication: false,
            reused_connection: false,
            http2_fallback: false,
            unprocessed: 0,
            status: 0,
            http2_ping_failures: 0,
            http2_ping_failure_limit,
        }
    }

    pub(super) fn start_hop(&mut self) {
        *self = Self::new(self.http2_ping_failure_limit);
    }

    /// Returns whether a PING failure may ever be replayed, so an attempt
    /// keeps what it sent for the replay.
    pub(super) const fn replays_http2_ping_failures(&self) -> bool {
        self.http2_ping_failure_limit > 0
    }

    /// Records a replay of `class` and returns whether it may proceed.
    pub(super) fn try_begin(&mut self, class: ReplayClass, method: &Method) -> bool {
        if !class.permits(method) {
            return false;
        }
        let performed = match class {
            ReplayClass::CriticalClientHints => &mut self.critical_client_hints,
            ReplayClass::ProxyAuthentication => &mut self.proxy_authentication,
            ReplayClass::ReusedConnection => &mut self.reused_connection,
            ReplayClass::Http2Fallback => &mut self.http2_fallback,
            ReplayClass::Unprocessed => {
                self.unprocessed += 1;
                return true;
            }
            ReplayClass::Status => {
                self.status += 1;
                return true;
            }
            ReplayClass::Http2PingFailure => {
                if self.http2_ping_failures >= self.http2_ping_failure_limit {
                    return false;
                }
                self.http2_ping_failures += 1;
                return true;
            }
        };
        if *performed {
            return false;
        }
        *performed = true;
        true
    }

    /// Returns whether `class` has replayed during the current hop.
    pub(super) const fn performed(&self, class: ReplayClass) -> bool {
        match class {
            ReplayClass::CriticalClientHints => self.critical_client_hints,
            ReplayClass::ProxyAuthentication => self.proxy_authentication,
            ReplayClass::ReusedConnection => self.reused_connection,
            ReplayClass::Http2Fallback => self.http2_fallback,
            ReplayClass::Unprocessed => self.unprocessed > 0,
            ReplayClass::Status => self.status > 0,
            ReplayClass::Http2PingFailure => self.http2_ping_failures > 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use http::Method;

    use super::{ReplayClass, ReplayState};

    #[test]
    fn critical_hint_replay_requires_a_safe_method() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
            assert!(ReplayState::new(0).try_begin(ReplayClass::CriticalClientHints, &method));
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(!ReplayState::new(0).try_begin(ReplayClass::CriticalClientHints, &method));
        }
    }

    #[test]
    fn idempotent_replay_classes_require_an_idempotent_method() {
        for class in [ReplayClass::ReusedConnection, ReplayClass::Status] {
            for method in [
                Method::GET,
                Method::HEAD,
                Method::OPTIONS,
                Method::TRACE,
                Method::PUT,
                Method::DELETE,
            ] {
                assert!(ReplayState::new(0).try_begin(class, &method));
            }
            for method in [Method::POST, Method::PATCH, Method::CONNECT] {
                assert!(!ReplayState::new(0).try_begin(class, &method));
            }
        }
    }

    #[test]
    fn reused_connection_replay_runs_once_per_hop() {
        let mut replays = ReplayState::new(0);
        assert!(replays.try_begin(ReplayClass::ReusedConnection, &Method::GET));
        assert!(!replays.try_begin(ReplayClass::ReusedConnection, &Method::GET));
        replays.start_hop();
        assert!(replays.try_begin(ReplayClass::ReusedConnection, &Method::GET));
    }

    #[test]
    fn unprocessed_replay_permits_every_method_and_is_not_limited_per_hop() {
        for method in [Method::GET, Method::POST, Method::PATCH, Method::DELETE] {
            let mut replays = ReplayState::new(0);
            assert!(replays.try_begin(ReplayClass::Unprocessed, &method));
            assert!(replays.try_begin(ReplayClass::Unprocessed, &method));
            assert!(replays.performed(ReplayClass::Unprocessed));
            replays.start_hop();
            assert!(!replays.performed(ReplayClass::Unprocessed));
        }
    }

    #[test]
    fn status_replay_is_not_limited_per_hop() {
        let mut replays = ReplayState::new(0);
        assert!(!replays.performed(ReplayClass::Status));
        assert!(replays.try_begin(ReplayClass::Status, &Method::GET));
        assert!(replays.try_begin(ReplayClass::Status, &Method::GET));
        assert!(replays.performed(ReplayClass::Status));
        replays.start_hop();
        assert!(!replays.performed(ReplayClass::Status));
    }

    #[test]
    fn http2_ping_failure_replay_permits_every_method() {
        for method in [Method::GET, Method::POST, Method::PATCH, Method::CONNECT] {
            assert!(ReplayState::new(2).try_begin(ReplayClass::Http2PingFailure, &method));
        }
    }

    #[test]
    fn http2_ping_failure_replay_stops_at_the_limit_and_resets_per_hop() {
        let mut replays = ReplayState::new(2);
        assert!(replays.try_begin(ReplayClass::Http2PingFailure, &Method::POST));
        assert!(replays.try_begin(ReplayClass::Http2PingFailure, &Method::POST));
        assert!(!replays.try_begin(ReplayClass::Http2PingFailure, &Method::POST));
        assert!(replays.performed(ReplayClass::Http2PingFailure));
        replays.start_hop();
        assert!(!replays.performed(ReplayClass::Http2PingFailure));
        assert!(replays.try_begin(ReplayClass::Http2PingFailure, &Method::POST));
    }

    #[test]
    fn a_zero_limit_never_replays_http2_ping_failures() {
        let mut replays = ReplayState::new(0);
        assert!(!replays.replays_http2_ping_failures());
        assert!(!replays.try_begin(ReplayClass::Http2PingFailure, &Method::GET));
    }
}
