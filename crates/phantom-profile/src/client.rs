//! Protocol settings grouped for client construction.

use crate::{
    ClientHintSettings, CookiePlacement, DnsCacheSettings, Http1Settings, Http2Settings,
    Http3RequestSettings, Http3Settings, ProxyConnectTemplate, TcpSettings, TlsSettings,
    UdpSettings, WebSocketSettings, quic::QuicTransportSettings,
};

/// TLS, QUIC transport, HTTP/3 connection, and request settings for one client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http3ClientSettings {
    tls: TlsSettings,
    quic_transport: QuicTransportSettings,
    http3: Http3Settings,
    request: Http3RequestSettings,
}

impl Http3ClientSettings {
    /// Groups the settings required to construct an HTTP/3 client.
    #[must_use]
    pub fn new(
        tls: TlsSettings,
        quic_transport: QuicTransportSettings,
        http3: Http3Settings,
        request: Http3RequestSettings,
    ) -> Self {
        Self {
            tls,
            quic_transport,
            http3,
            request,
        }
    }

    /// Returns the HTTP/3 connection's TLS settings.
    #[must_use]
    pub fn tls(&self) -> &TlsSettings {
        &self.tls
    }

    /// Returns the QUIC transport settings.
    #[must_use]
    pub fn quic_transport(&self) -> &QuicTransportSettings {
        &self.quic_transport
    }

    /// Returns the HTTP/3 connection settings.
    #[must_use]
    pub fn http3(&self) -> &Http3Settings {
        &self.http3
    }

    /// Returns the HTTP/3 request settings.
    #[must_use]
    pub fn request(&self) -> &Http3RequestSettings {
        &self.request
    }
}

/// Protocol settings selected for one client wire profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientProfile {
    tcp: Option<TcpSettings>,
    udp: Option<UdpSettings>,
    dns_cache: Option<DnsCacheSettings>,
    tls: TlsSettings,
    http1: Option<Http1Settings>,
    http2: Option<Http2Settings>,
    http3: Option<Http3ClientSettings>,
    client_hints: Option<ClientHintSettings>,
    websocket: Option<WebSocketSettings>,
    proxy_connect: Option<ProxyConnectTemplate>,
    cookie_placement: CookiePlacement,
}

impl ClientProfile {
    /// Creates a profile with the required TLS settings.
    #[must_use]
    pub fn new(tls: TlsSettings) -> Self {
        Self {
            tcp: None,
            udp: None,
            dns_cache: None,
            tls,
            http1: None,
            http2: None,
            http3: None,
            client_hints: None,
            websocket: None,
            proxy_connect: None,
            cookie_placement: CookiePlacement::last(),
        }
    }

    /// Adds TCP socket options applied to every TCP connection.
    ///
    /// Without them, TCP sockets keep their operating-system defaults.
    #[must_use]
    pub fn with_tcp(mut self, tcp: TcpSettings) -> Self {
        self.tcp = Some(tcp);
        self
    }

    /// Adds socket options for QUIC and Phantom's own DNS queries.
    ///
    /// These apply to address and HTTPS-record UDP query sockets that Phantom
    /// opens, alongside QUIC sockets. DNS sockets opened by the operating
    /// system are unaffected. Without settings, Phantom does not set
    /// these options.
    #[must_use]
    pub fn with_udp(mut self, udp: UdpSettings) -> Self {
        self.udp = Some(udp);
        self
    }

    /// Adds the address cache the client keeps for its own DNS lookups.
    ///
    /// Without it, the client resolves a host name for every new connection.
    #[must_use]
    pub fn with_dns_cache(mut self, dns_cache: DnsCacheSettings) -> Self {
        self.dns_cache = Some(dns_cache);
        self
    }

    /// Adds the HTTP/1.1 connection policy to the profile.
    ///
    /// Without it, a client keeps one HTTP/1.1 connection per origin and route
    /// and runs that pool key's requests on it one at a time.
    #[must_use]
    pub fn with_http1(mut self, http1: Http1Settings) -> Self {
        self.http1 = Some(http1);
        self
    }

    /// Adds HTTP/2 settings to the profile.
    #[must_use]
    pub fn with_http2(mut self, http2: Http2Settings) -> Self {
        self.http2 = Some(http2);
        self
    }

    /// Adds HTTP/3 settings to the profile.
    #[must_use]
    pub fn with_http3(mut self, http3: Http3ClientSettings) -> Self {
        self.http3 = Some(http3);
        self
    }

    /// Adds ordered client-hint request fields to the profile.
    #[must_use]
    pub fn with_client_hints(mut self, client_hints: ClientHintSettings) -> Self {
        self.client_hints = Some(client_hints);
        self
    }

    /// Adds WebSocket opening templates and connection choice to the profile.
    #[must_use]
    pub fn with_websocket(mut self, websocket: WebSocketSettings) -> Self {
        self.websocket = Some(websocket);
        self
    }

    /// Adds the ordered fields of the CONNECT request that opens an HTTP
    /// proxy tunnel.
    ///
    /// They apply to an HTTP proxy route whose CONNECT fields the caller has
    /// not set with `HttpProxy::header`, `headers`, or `connect_headers`.
    /// Without them, such a CONNECT request carries only `Host` and, when
    /// needed, `Proxy-Authorization`.
    #[must_use]
    pub fn with_proxy_connect(mut self, proxy_connect: ProxyConnectTemplate) -> Self {
        self.proxy_connect = Some(proxy_connect);
        self
    }

    /// Sets where the automatic `Cookie` request field goes.
    #[must_use]
    pub fn with_cookie_placement(mut self, cookie_placement: CookiePlacement) -> Self {
        self.cookie_placement = cookie_placement;
        self
    }

    /// Makes the draws the profile takes once per client, as
    /// [`TlsSettings::draw_per_client`] describes, for the TLS settings and
    /// then the HTTP/3 TLS settings, calling `random` once for each draw.
    ///
    /// A `phantom` client makes these draws when it is built, so that all of
    /// its connectors share them.
    ///
    /// # Errors
    ///
    /// Returns the first error from `random`. A draw made before it is kept.
    pub fn draw_per_client<E>(
        &mut self,
        mut random: impl FnMut() -> Result<u64, E>,
    ) -> Result<(), E> {
        self.tls.draw_per_client(&mut random)?;
        if let Some(http3) = &mut self.http3 {
            http3.tls.draw_per_client(&mut random)?;
        }
        Ok(())
    }

    /// Returns the profile's TCP socket options when configured.
    #[must_use]
    pub fn tcp(&self) -> Option<&TcpSettings> {
        self.tcp.as_ref()
    }

    /// Returns the profile's UDP socket options when configured.
    #[must_use]
    pub fn udp(&self) -> Option<&UdpSettings> {
        self.udp.as_ref()
    }

    /// Returns the profile's address cache settings when configured.
    #[must_use]
    pub fn dns_cache(&self) -> Option<&DnsCacheSettings> {
        self.dns_cache.as_ref()
    }

    /// Returns the profile's TLS settings.
    #[must_use]
    pub fn tls(&self) -> &TlsSettings {
        &self.tls
    }

    /// Returns the profile's HTTP/1.1 connection policy when configured.
    #[must_use]
    pub fn http1(&self) -> Option<&Http1Settings> {
        self.http1.as_ref()
    }

    /// Returns the profile's HTTP/2 settings when configured.
    #[must_use]
    pub fn http2(&self) -> Option<&Http2Settings> {
        self.http2.as_ref()
    }

    /// Returns the profile's HTTP/3 settings when configured.
    #[must_use]
    pub fn http3(&self) -> Option<&Http3ClientSettings> {
        self.http3.as_ref()
    }

    /// Returns the client-hint settings when configured.
    #[must_use]
    pub fn client_hints(&self) -> Option<&ClientHintSettings> {
        self.client_hints.as_ref()
    }

    /// Returns the WebSocket settings when configured.
    #[must_use]
    pub fn websocket(&self) -> Option<&WebSocketSettings> {
        self.websocket.as_ref()
    }

    /// Returns the CONNECT request fields when configured.
    #[must_use]
    pub fn proxy_connect(&self) -> Option<&ProxyConnectTemplate> {
        self.proxy_connect.as_ref()
    }

    /// Returns where the automatic `Cookie` request field goes.
    #[must_use]
    pub fn cookie_placement(&self) -> &CookiePlacement {
        &self.cookie_placement
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        CipherSuite, ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile,
        Http3ClientSettings, TlsVersion, TrustAnchorIds, chromium, opera,
    };

    #[test]
    fn new_owns_tls_settings_without_enabling_http2() {
        let tls = chromium::v154_tls();
        let profile = ClientProfile::new(tls.clone());

        assert_eq!(profile.tls(), &tls);
        assert_eq!(profile.tcp(), None);
        assert_eq!(profile.http1(), None);
        assert_eq!(profile.http2(), None);
        assert_eq!(profile.http3(), None);
    }

    #[test]
    fn with_tcp_owns_and_exposes_tcp_settings() {
        let tcp = chromium::v154_tcp();
        let profile = ClientProfile::new(chromium::v154_tls()).with_tcp(tcp);

        assert_eq!(profile.tcp(), Some(&tcp));
    }

    #[test]
    fn with_udp_owns_and_exposes_udp_settings() {
        let udp = chromium::v154_udp();
        let profile = ClientProfile::new(chromium::v154_tls()).with_udp(udp);

        assert_eq!(profile.udp(), Some(&udp));
        assert_eq!(ClientProfile::new(chromium::v154_tls()).udp(), None);
    }

    #[test]
    fn with_dns_cache_owns_and_exposes_dns_cache_settings() {
        let dns_cache = chromium::v154_dns_cache();
        let profile = ClientProfile::new(chromium::v154_tls()).with_dns_cache(dns_cache);

        assert_eq!(profile.dns_cache(), Some(&dns_cache));
        assert_eq!(ClientProfile::new(chromium::v154_tls()).dns_cache(), None);
    }

    #[test]
    fn with_http1_owns_and_exposes_http1_settings() {
        let http1 = chromium::v154_http1();
        let profile = ClientProfile::new(chromium::v154_tls()).with_http1(http1);

        assert_eq!(profile.http1(), Some(&http1));
    }

    #[test]
    fn with_http2_owns_and_exposes_http2_settings() {
        let tls = chromium::v154_tls();
        let http2 = chromium::v154_http2();
        let profile = ClientProfile::new(tls.clone()).with_http2(http2.clone());

        assert_eq!(profile.tls(), &tls);
        assert_eq!(profile.http2(), Some(&http2));
    }

    #[test]
    fn with_client_hints_owns_and_exposes_ordered_settings() {
        let hints = ClientHintSettings::new(vec![ClientHint::new(
            "sec-ch-ua",
            "value",
            ClientHintDelivery::Default,
        )]);
        let profile = ClientProfile::new(chromium::v154_tls()).with_client_hints(hints.clone());

        assert_eq!(profile.client_hints(), Some(&hints));
    }

    #[test]
    fn http3_settings_own_and_expose_each_protocol_layer() {
        let tls = chromium::v154_tls();
        let quic_transport = chromium::v154_quic();
        let http3 = chromium::v154_http3();
        let request = chromium::v154_http3_request();
        let settings = Http3ClientSettings::new(
            tls.clone(),
            quic_transport.clone(),
            http3.clone(),
            request.clone(),
        );

        assert_eq!(settings.tls(), &tls);
        assert_eq!(settings.quic_transport(), &quic_transport);
        assert_eq!(settings.http3(), &http3);
        assert_eq!(settings.request(), &request);
    }

    #[test]
    fn with_http3_owns_and_exposes_http3_settings() {
        let tcp_tls = chromium::v154_tls();
        let mut http3_tls = chromium::v154_tls();
        http3_tls.min_version = TlsVersion::Tls13;
        http3_tls.max_version = TlsVersion::Tls13;
        http3_tls.cipher_suites = vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::Chacha20Poly1305Sha256,
        ];
        http3_tls.alpn_protocols = vec![Box::from(*b"h3")];
        http3_tls.alps = None;
        http3_tls.session_tickets = false;
        let http2 = chromium::v154_http2();
        let http3 = Http3ClientSettings::new(
            http3_tls.clone(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        );
        let profile = ClientProfile::new(tcp_tls.clone())
            .with_http2(http2.clone())
            .with_http3(http3.clone());

        assert_eq!(profile.tls(), &tcp_tls);
        assert_eq!(profile.http2(), Some(&http2));
        assert_eq!(profile.http3(), Some(&http3));
        assert_eq!(
            profile.http3().map(Http3ClientSettings::tls),
            Some(&http3_tls)
        );
    }

    /// Opera draws its TCP order once per process and its QUIC order per
    /// connection, so a client's draw fixes only the TCP order.
    #[test]
    fn per_client_draw_fixes_the_tcp_trust_anchor_order_only() {
        let http3 = Http3ClientSettings::new(
            opera::v136_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        );
        let mut profile = ClientProfile::new(opera::v136_tls()).with_http3(http3.clone());
        let mut draws = 0;
        let drawn = profile.draw_per_client(|| {
            draws += 1;
            Ok::<_, ()>(u64::MAX)
        });

        assert_eq!(drawn, Ok(()));
        assert_eq!(draws, 1);
        let tcp_orders = opera::v136_tls()
            .requested_trust_anchor_ids
            .map(|ids| ids.orders().to_vec());
        let last = tcp_orders.and_then(|orders| orders.last().cloned());
        assert_eq!(
            profile.tls().requested_trust_anchor_ids,
            last.map(TrustAnchorIds::Fixed)
        );
        assert_eq!(profile.http3(), Some(&http3));
    }
}
