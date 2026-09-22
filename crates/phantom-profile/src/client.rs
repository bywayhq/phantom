//! Protocol settings grouped for client construction.

use crate::{
    ClientHintSettings, CookiePlacement, Http2Settings, Http3RequestSettings, Http3Settings,
    TcpSettings, TlsSettings, WebSocketSettings, quic::QuicTransportSettings,
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
    tls: TlsSettings,
    http2: Option<Http2Settings>,
    http3: Option<Http3ClientSettings>,
    client_hints: Option<ClientHintSettings>,
    websocket: Option<WebSocketSettings>,
    cookie_placement: CookiePlacement,
}

impl ClientProfile {
    /// Creates a profile with the required TLS settings.
    #[must_use]
    pub fn new(tls: TlsSettings) -> Self {
        Self {
            tcp: None,
            tls,
            http2: None,
            http3: None,
            client_hints: None,
            websocket: None,
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

    /// Sets where the automatic `Cookie` request field goes.
    #[must_use]
    pub fn with_cookie_placement(mut self, cookie_placement: CookiePlacement) -> Self {
        self.cookie_placement = cookie_placement;
        self
    }

    /// Returns the profile's TCP socket options when configured.
    #[must_use]
    pub fn tcp(&self) -> Option<&TcpSettings> {
        self.tcp.as_ref()
    }

    /// Returns the profile's TLS settings.
    #[must_use]
    pub fn tls(&self) -> &TlsSettings {
        &self.tls
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
        Http3ClientSettings, TlsVersion, chromium,
    };

    #[test]
    fn new_owns_tls_settings_without_enabling_http2() {
        let tls = chromium::v152_tls();
        let profile = ClientProfile::new(tls.clone());

        assert_eq!(profile.tls(), &tls);
        assert_eq!(profile.tcp(), None);
        assert_eq!(profile.http2(), None);
        assert_eq!(profile.http3(), None);
    }

    #[test]
    fn with_tcp_owns_and_exposes_tcp_settings() {
        let tcp = chromium::v153_tcp();
        let profile = ClientProfile::new(chromium::v153_tls()).with_tcp(tcp);

        assert_eq!(profile.tcp(), Some(&tcp));
    }

    #[test]
    fn with_http2_owns_and_exposes_http2_settings() {
        let tls = chromium::v152_tls();
        let http2 = chromium::v152_http2();
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
        let profile = ClientProfile::new(chromium::v152_tls()).with_client_hints(hints.clone());

        assert_eq!(profile.client_hints(), Some(&hints));
    }

    #[test]
    fn http3_settings_own_and_expose_each_protocol_layer() {
        let tls = chromium::v152_tls();
        let quic_transport = chromium::v152_quic();
        let http3 = chromium::v152_http3();
        let request = chromium::v152_http3_request();
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
        let tcp_tls = chromium::v152_tls();
        let mut http3_tls = chromium::v152_tls();
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
        let http2 = chromium::v152_http2();
        let http3 = Http3ClientSettings::new(
            http3_tls.clone(),
            chromium::v152_quic(),
            chromium::v152_http3(),
            chromium::v152_http3_request(),
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
}
