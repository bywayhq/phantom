//! Wire settings retained from Microsoft Edge browser observations.
//!
//! Edge 153.0.4234.48 on Windows 11 (build 26200) matches Chrome
//! 153.0.8010.48 on the H2 startup, request pseudo-header order and priority,
//! extended CONNECT shape, WebSocket connection choice and opening fields,
//! QUIC transport parameters, and H3 SETTINGS and request order. Use
//! [`chromium::v153_http2`], [`chromium::v153_websocket`],
//! [`chromium::v153_quic`], [`chromium::v153_http3`], and
//! [`chromium::v153_http3_request`] for those layers. The TLS offers, client
//! hints, and request identity differ, so only they have Edge recipes here.
//!
//! There is no Edge TCP recipe. Socket options are not visible in captures,
//! and Edge's network-stack source is not public, so no retained evidence
//! shows whether Edge keeps the Chromium options in [`chromium::v153_tcp`].

use crate::{
    chromium,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    request_template::{ProductVersion, RequestIdentity, RequestTemplate},
    tls::TlsSettings,
};

/// Returns TLS settings captured from Edge 153.0.4234.48 on Windows 11.
///
/// Edge 153.0.4234.48 (Windows 11 build 26200) sends the Chrome 153 TCP
/// ClientHello without the trust-anchor IDs extension. Every other compared
/// field matches [`chromium::v153_tls`] across 20 fresh processes, so this
/// reuses that recipe and removes only the ID list.
#[must_use]
pub fn v153_tls() -> TlsSettings {
    let mut settings = chromium::v153_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns TLS settings for the Edge 153.0.4234.48 HTTP/3 offer on Windows 11.
///
/// The QUIC ClientHello matches [`chromium::v153_http3_tls`] without the
/// trust-anchor IDs extension, so this reuses that recipe and removes only
/// the ID list.
#[must_use]
pub fn v153_http3_tls() -> TlsSettings {
    let mut settings = chromium::v153_http3_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns client-hint fields observed from Edge 153 on Windows 11 x64.
///
/// Names, order, and delivery match Chrome 153. The values carry Edge's brand
/// list, the exact 153.0.4234.48 build, the Chromium 153.0.8010.53 base it
/// reports in the full version list, and Windows platform data. The returned
/// value is owned and may be customized before client creation.
#[must_use]
pub fn v153_windows_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""153.0.4234.48""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Microsoft Edge";v="153.0.4234.48", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.53""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

/// Returns navigation request fields observed from Edge 153.0.4234.48 on Windows 11.
///
/// Edge sends the fields of [`chromium::v153_windows_navigation_template`] in
/// the same order and with the same values on HTTP/1.1, HTTP/2, and HTTP/3,
/// except `User-Agent` and the brand-bearing client hints, which come from
/// [`v153_windows_client_hints`]. `User-Agent` is a caller slot: every
/// retained Edge capture ran headless and sent `HeadlessChrome`, and no
/// headful Edge capture backs a literal value. The template's identity
/// requires an `Edg/153` product and rejects `HeadlessChrome`.
#[must_use]
pub fn v153_windows_navigation_template() -> RequestTemplate {
    chromium::v153_navigation_template(None, v153_identity())
}

/// Returns same-origin no-store `fetch` request fields observed from Edge
/// 153.0.4234.48 on Windows 11.
///
/// The order and values match [`chromium::v153_windows_fetch_no_store_template`]
/// on HTTP/1.1 and HTTP/2, with `User-Agent` as a caller slot for the reason
/// given in [`v153_windows_navigation_template`]. No capture backs this
/// request kind on HTTP/3.
#[must_use]
pub fn v153_windows_fetch_no_store_template() -> RequestTemplate {
    chromium::v153_fetch_no_store_template(None, v153_identity())
}

fn v153_identity() -> RequestIdentity {
    RequestIdentity {
        user_agent_products: vec![ProductVersion::new("Edg", 153)],
        excluded_user_agent_products: vec![Box::from("HeadlessChrome"), Box::from("Firefox")],
        client_hint_brands: Some(vec![
            ProductVersion::new("Microsoft Edge", 153),
            ProductVersion::new("Chromium", 153),
        ]),
    }
}

#[cfg(test)]
mod tests;
