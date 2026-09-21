use http::Method;

/// A reason to repeat a complete wire attempt within one redirect hop.
#[derive(Clone, Copy)]
pub(super) enum ReplayClass {
    CriticalClientHints,
    ProxyAuthentication,
    /// A reused HTTP/1.1 connection closed before any response byte.
    ReusedConnection,
    /// A caller-listed retryable response status; bounded by the
    /// request-scoped status-retry budget rather than once per hop.
    Status,
}

impl ReplayClass {
    fn permits(self, method: &Method) -> bool {
        match self {
            Self::CriticalClientHints => method.is_safe(),
            Self::ProxyAuthentication => true,
            // RFC 9110, section 9.2.2: the request may already have reached
            // the origin, so only idempotent methods may be repeated.
            Self::ReusedConnection | Self::Status => method.is_idempotent(),
        }
    }
}

/// Every class except [`ReplayClass::Status`] replays at most once per
/// redirect hop.
pub(super) struct ReplayState {
    critical_client_hints: bool,
    proxy_authentication: bool,
    reused_connection: bool,
    status: usize,
}

impl ReplayState {
    pub(super) const fn new() -> Self {
        Self {
            critical_client_hints: false,
            proxy_authentication: false,
            reused_connection: false,
            status: 0,
        }
    }

    pub(super) fn start_hop(&mut self) {
        *self = Self::new();
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
            ReplayClass::Status => {
                self.status += 1;
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
            ReplayClass::Status => self.status > 0,
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
            assert!(ReplayState::new().try_begin(ReplayClass::CriticalClientHints, &method));
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(!ReplayState::new().try_begin(ReplayClass::CriticalClientHints, &method));
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
                assert!(ReplayState::new().try_begin(class, &method));
            }
            for method in [Method::POST, Method::PATCH, Method::CONNECT] {
                assert!(!ReplayState::new().try_begin(class, &method));
            }
        }
    }

    #[test]
    fn reused_connection_replay_runs_once_per_hop() {
        let mut replays = ReplayState::new();
        assert!(replays.try_begin(ReplayClass::ReusedConnection, &Method::GET));
        assert!(!replays.try_begin(ReplayClass::ReusedConnection, &Method::GET));
        replays.start_hop();
        assert!(replays.try_begin(ReplayClass::ReusedConnection, &Method::GET));
    }

    #[test]
    fn status_replay_is_not_limited_per_hop() {
        let mut replays = ReplayState::new();
        assert!(!replays.performed(ReplayClass::Status));
        assert!(replays.try_begin(ReplayClass::Status, &Method::GET));
        assert!(replays.try_begin(ReplayClass::Status, &Method::GET));
        assert!(replays.performed(ReplayClass::Status));
        replays.start_hop();
        assert!(!replays.performed(ReplayClass::Status));
    }
}
