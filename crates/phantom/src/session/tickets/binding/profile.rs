use phantom_profile::{ClientProfile, TrustAnchorIds};

use super::{PreparationError, encoding::Encoder, http, quic, requests, tls};

pub(super) fn encode(
    value: &ClientProfile,
    tcp_anchors: Option<&TrustAnchorIds>,
    quic_anchors: Option<&TrustAnchorIds>,
) -> Result<Vec<u8>, PreparationError> {
    let mut e = Encoder::new();
    e.bytes(b"phantom-ticket-profile-policy")?;
    e.u16(4)?;
    e.option(value.tcp(), http::tcp)?;
    e.option(value.udp(), http::udp)?;
    e.option(value.dns_cache(), http::dns)?;
    tls::encode(&mut e, value.tls(), tcp_anchors)?;
    e.option(value.http1(), http::http1)?;
    e.option(value.http2(), http::http2)?;
    e.option(value.http3(), |e, value| {
        tls::encode(e, value.tls(), quic_anchors)?;
        quic::encode(e, value.quic_transport())?;
        http::http3(e, value.http3())?;
        http::http3_request(e, value.request())
    })?;
    e.option(value.client_hints(), requests::hints)?;
    e.option(value.websocket(), requests::websocket)?;
    e.option(value.proxy_connect(), requests::connect)?;
    requests::cookies(&mut e, value.cookie_placement())?;
    e.option(value.request_template(), requests::template)?;
    Ok(e.finish())
}
