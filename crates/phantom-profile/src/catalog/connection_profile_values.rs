//! Immutable typed component selection and fresh owned profile construction.

use crate::{ClientProfile, Http3ClientSettings};

use super::connection_profile_definitions::{
    ClientHintsComponent, CookieComponent, DnsComponent, Http1Component, Http2Component,
    Http3Component, Http3RequestComponent, ProxyConnectComponent, QuicComponent, TcpComponent,
    TlsComponent, UdpComponent, WebSocketComponent,
};

#[derive(Debug)]
pub(super) struct ConnectionProfileDefinition {
    pub(super) tls: TlsComponent,
    pub(super) tcp: Option<TcpComponent>,
    pub(super) udp: Option<UdpComponent>,
    pub(super) dns_cache: Option<DnsComponent>,
    pub(super) http1: Option<Http1Component>,
    pub(super) http2: Option<Http2Component>,
    pub(super) http3: Option<Http3Definition>,
    pub(super) client_hints: Option<ClientHintsComponent>,
    pub(super) websocket: Option<WebSocketComponent>,
    pub(super) proxy_connect: Option<ProxyConnectComponent>,
    pub(super) cookie_placement: Option<CookieComponent>,
}

#[derive(Debug)]
pub(super) struct Http3Definition {
    pub(super) tls: TlsComponent,
    pub(super) quic_transport: QuicComponent,
    pub(super) http3: Http3Component,
    pub(super) request: Http3RequestComponent,
}

impl ConnectionProfileDefinition {
    pub(super) fn instantiate(&self) -> ClientProfile {
        let mut profile = ClientProfile::new(self.tls.create());
        if let Some(component) = self.tcp {
            profile = profile.with_tcp(component.create());
        }
        if let Some(component) = self.udp {
            profile = profile.with_udp(component.create());
        }
        if let Some(component) = self.dns_cache {
            profile = profile.with_dns_cache(component.create());
        }
        if let Some(component) = self.http1 {
            profile = profile.with_http1(component.create());
        }
        if let Some(component) = self.http2 {
            profile = profile.with_http2(component.create());
        }
        if let Some(definition) = &self.http3 {
            profile = profile.with_http3(Http3ClientSettings::new(
                definition.tls.create(),
                definition.quic_transport.create(),
                definition.http3.create(),
                definition.request.create(),
            ));
        }
        if let Some(component) = self.client_hints {
            profile = profile.with_client_hints(component.create());
        }
        if let Some(component) = self.websocket {
            profile = profile.with_websocket(component.create());
        }
        if let Some(component) = self.proxy_connect {
            profile = profile.with_proxy_connect(component.create());
        }
        if let Some(component) = self.cookie_placement {
            profile = profile.with_cookie_placement(component.create());
        }
        profile
    }
}
