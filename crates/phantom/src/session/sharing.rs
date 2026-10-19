use std::sync::Arc;

use crate::Client;

/// State selected for live sharing by [`Client::fork`].
///
/// The default starts each fork with empty state. Enabling a category shares
/// later changes, expiry and clearing in both directions. It does not enable
/// a category that was disabled when the source client was built.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct SessionSharing {
    #[cfg(feature = "cookies")]
    cookies: bool,
    dns: bool,
    client_hints: bool,
    discovery: bool,
    tickets: bool,
}

impl SessionSharing {
    /// Starts with no shared state.
    pub const fn none() -> Self {
        Self {
            #[cfg(feature = "cookies")]
            cookies: false,
            dns: false,
            client_hints: false,
            discovery: false,
            tickets: false,
        }
    }

    /// Shares the enabled cookie jar, including its existing cookies.
    #[cfg(feature = "cookies")]
    pub const fn cookies(mut self, enabled: bool) -> Self {
        self.cookies = enabled;
        self
    }

    /// Shares Phantom's address cache, including in-flight lookup work.
    ///
    /// Custom resolver callbacks retain their own caller-owned state regardless
    /// of this choice. Host overrides and resolver configuration are preserved.
    pub const fn dns(mut self, enabled: bool) -> Self {
        self.dns = enabled;
        self
    }

    /// Shares learned `Accept-CH` preferences.
    pub const fn client_hints(mut self, enabled: bool) -> Self {
        self.client_hints = enabled;
        self
    }

    /// Shares Alt-Svc entries, racing history and enabled HTTPS-record state.
    pub const fn discovery(mut self, enabled: bool) -> Self {
        self.discovery = enabled;
        self
    }

    /// Shares live TLS ticket stores while keeping connection pools independent.
    ///
    /// New connections use the first matching store. Existing work can finish
    /// with an older store; clearing visits both. Portable export and import
    /// report `Unsupported` while several live stores have the same identity.
    /// A caller-owned CONNECT-UDP pool rejects a conflicting store selected
    /// by another sharing group with a configuration error.
    /// Shared stores survive either client being dropped. Their bounded cache
    /// evicts least-recently-selected stores. Single-use tickets are never copied.
    /// The store bound is four times the retained H1 pool limit, plus twice
    /// the H2 limit and three times the H3 limit.
    pub const fn tickets(mut self, enabled: bool) -> Self {
        self.tickets = enabled;
        self
    }
}

impl Client {
    /// Creates independent connection pools with selected shared session state.
    ///
    /// Preserves the profile, trust, routes, hooks, custom connectors, timeouts
    /// and pool limits. Origin and HTTPS-proxy pools, request admission and
    /// shutdown are independent. Learned proxy authentication starts empty.
    /// Unselected tickets, caches and cookies start empty, with the
    /// same limits as the source. Ordinary [`Clone::clone`] keeps sharing pools.
    ///
    /// A default CONNECT-UDP route receives a fresh outer pool. A route supplied
    /// on a later request retains its caller-owned pool. Resolver and connector
    /// callbacks keep their caller-owned state. Hooks and key-log sinks remain
    /// shared. A fork can be created from a closed client and starts open.
    ///
    /// ```no_run
    /// use phantom::{Client, SessionSharing, profile::browser::chrome};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::builder(chrome::v154_windows()).build()?;
    /// let worker = client.fork(SessionSharing::none().dns(true));
    /// // Closing worker leaves client usable; their DNS cache is shared.
    /// # drop(worker);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn fork(&self, sharing: SessionSharing) -> Self {
        let inner = Arc::new(self.inner.fork(sharing.dns, sharing.tickets));
        #[cfg_attr(not(feature = "cookies"), allow(unused_mut))]
        let mut options = self.state.options.clone();
        #[cfg(feature = "cookies")]
        {
            options.cookie_jar = self.state.cookies.as_ref().map(|jar| {
                if sharing.cookies {
                    Arc::clone(jar)
                } else {
                    Arc::new(jar.empty_with_same_limits())
                }
            });
        }
        let tickets = sharing.tickets.then(|| {
            self.state.tickets.enable_sharing(
                // Exact H1 and negotiated entries each have origin/proxy
                // stores. H2 has two; H3 can retain origin and outer stores.
                options
                    .max_retained_http1_connections
                    .get()
                    .saturating_mul(4)
                    .saturating_add(
                        options
                            .max_retained_http2_connections
                            .get()
                            .saturating_mul(2),
                    )
                    .saturating_add(
                        options
                            .max_retained_http3_connections
                            .get()
                            .saturating_mul(3),
                    ),
            );
            Arc::clone(&self.state.tickets)
        });
        let mut state = options.build_with_tickets(&inner, tickets);
        if sharing.client_hints {
            state.client_hints.clone_from(&self.state.client_hints);
        }
        if sharing.discovery {
            state.alt_svc.clone_from(&self.state.alt_svc);
            state.rtt_history.clone_from(&self.state.rtt_history);
            state.http3.set_rtt_history(state.rtt_history.clone());
            #[cfg(feature = "https-records")]
            {
                state.https_records.clone_from(&self.state.https_records);
                state.http1.set_https_records(state.https_records.clone());
                state
                    .http1_or_2
                    .set_https_records(state.https_records.clone());
                state.http2.set_https_records(state.https_records.clone());
                state.http3.set_https_records(state.https_records.clone());
            }
        }
        Self {
            inner,
            state: Arc::new(state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AltSvcSnapshot, AltSvcSnapshotEntry, RedirectPolicy, RequestTimeouts};
    use phantom_profile::{ClientProfile, Http3ClientSettings, browser::chrome};
    use std::{
        num::NonZeroUsize,
        time::{Duration, SystemTime},
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn client() -> Result<Client, crate::BuildError> {
        Client::builder(
            ClientProfile::new(chrome::v154_tcp_tls())
                .with_http1(chrome::v154_http1())
                .with_http2(chrome::v154_http2())
                .with_client_hints(chrome::v154_windows_client_hints())
                .with_http3(Http3ClientSettings::new(
                    chrome::v154_quic_tls(),
                    chrome::v154_quic(),
                    chrome::v154_http3(),
                    chrome::v154_http3_request(),
                )),
        )
        .alt_svc(NonZeroUsize::MIN)
        .max_pending_http1_requests_per_origin(NonZeroUsize::MIN)
        .request_timeouts(RequestTimeouts::new().total(Duration::from_secs(17)))
        .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
        .build()
    }

    #[tokio::test]
    async fn forks_preserve_settings_and_have_independent_shutdown() -> TestResult {
        let original = client()?;
        let fork = original.fork(SessionSharing::none());
        assert_eq!(format!("{original:?}"), format!("{fork:?}"));
        assert!(!Arc::ptr_eq(&original.state, &fork.state));
        assert!(!Arc::ptr_eq(&original.state.tickets, &fork.state.tickets));
        fork.shutdown().await;
        assert!(fork.is_closed());
        assert!(!original.is_closed());
        assert!(!fork.fork(SessionSharing::none()).is_closed());
        original.shutdown().await;
        Ok(())
    }

    #[test]
    fn selected_discovery_is_shared_live_and_unselected_discovery_starts_empty() -> TestResult {
        let original = client()?;
        let shared = original.fork(SessionSharing::none().discovery(true));
        let isolated = original.fork(SessionSharing::none());
        original.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
            "https://example.com",
            "alt.example.com",
            443,
            SystemTime::now() + Duration::from_secs(60),
        )]))?;
        assert_eq!(
            shared.export_alt_svc().ok_or("discovery disabled")?.len(),
            1
        );
        assert!(
            isolated
                .export_alt_svc()
                .ok_or("discovery disabled")?
                .is_empty()
        );
        shared.clear_alt_svc();
        assert!(
            original
                .export_alt_svc()
                .ok_or("discovery disabled")?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn selected_client_hints_share_learning_and_clearing() -> TestResult {
        let original = client()?;
        let shared = original.fork(SessionSharing::none().client_hints(true));
        let isolated = original.fork(SessionSharing::none());
        let endpoint = crate::authority::Endpoint::new("example.com".parse()?, 443)?;
        let settings = original
            .inner
            .client_hints
            .as_ref()
            .ok_or("hints disabled")?;
        let mut response = http::HeaderMap::new();
        response.insert(
            "accept-ch",
            http::HeaderValue::from_static("Sec-CH-UA-Arch"),
        );
        original.learn_client_hints_and_should_retry(
            &endpoint,
            true,
            settings,
            &response,
            &[],
            &[],
        );
        let has_arch = |client: &Client| {
            client.state.client_hints.as_ref().is_some_and(|store| {
                store
                    .prepare(&endpoint, settings, Vec::new())
                    .iter()
                    .any(|header| header.name() == "sec-ch-ua-arch")
            })
        };
        assert!(has_arch(&shared));
        assert!(!has_arch(&isolated));
        shared.clear_client_hints();
        assert!(!has_arch(&original));
        Ok(())
    }

    #[cfg(feature = "cookies")]
    #[test]
    fn selected_cookies_share_later_updates_while_other_forks_start_empty() -> TestResult {
        let bounded = Client::builder(ClientProfile::new(chrome::v154_tcp_tls()))
            .cookie_jar(crate::CookieJar::with_limits(crate::CookieLimits::new(
                NonZeroUsize::MIN,
                NonZeroUsize::MIN,
                NonZeroUsize::MIN,
            )))
            .build()?;
        for candidate in [
            &bounded,
            &bounded.fork(SessionSharing::none().cookies(true)),
            &bounded.fork(SessionSharing::none()),
        ] {
            assert!(
                candidate
                    .cookie_jar()
                    .ok_or("jar missing")?
                    .set_cookie("https://example.com/", "a=1")
                    .is_err()
            );
        }
        let original = Client::builder(ClientProfile::new(chrome::v154_tcp_tls()))
            .cookies()
            .build()?;
        let shared = original.fork(SessionSharing::none().cookies(true));
        let isolated = original.fork(SessionSharing::none());
        original
            .cookie_jar()
            .ok_or("jar missing")?
            .set_cookie("https://example.com/", "a=1")?;
        assert_eq!(
            shared
                .cookie_jar()
                .ok_or("jar missing")?
                .request_value("https://example.com/")?
                .as_deref(),
            Some("a=1")
        );
        shared
            .cookie_jar()
            .ok_or("jar missing")?
            .set_cookie("https://example.com/", "a=2")?;
        assert_eq!(
            original
                .cookie_jar()
                .ok_or("jar missing")?
                .request_value("https://example.com/")?
                .as_deref(),
            Some("a=2")
        );
        assert_eq!(
            isolated
                .cookie_jar()
                .ok_or("jar missing")?
                .request_value("https://example.com/")?,
            None
        );
        Ok(())
    }
}
