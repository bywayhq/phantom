use http::Method;

/// A reason to repeat a complete wire attempt within one redirect hop.
#[derive(Clone, Copy)]
pub(super) enum ReplayClass {
    CriticalClientHints,
    ProxyAuthentication,
}

impl ReplayClass {
    fn permits(self, method: &Method) -> bool {
        match self {
            Self::CriticalClientHints => method.is_safe(),
            Self::ProxyAuthentication => true,
        }
    }
}

/// Each class replays at most once per redirect hop.
pub(super) struct ReplayState {
    critical_client_hints: bool,
    proxy_authentication: bool,
}

impl ReplayState {
    pub(super) const fn new() -> Self {
        Self {
            critical_client_hints: false,
            proxy_authentication: false,
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
        let performed = self.performed_mut(class);
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
        }
    }

    fn performed_mut(&mut self, class: ReplayClass) -> &mut bool {
        match class {
            ReplayClass::CriticalClientHints => &mut self.critical_client_hints,
            ReplayClass::ProxyAuthentication => &mut self.proxy_authentication,
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
}
