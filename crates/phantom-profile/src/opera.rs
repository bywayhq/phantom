//! Wire settings retained from Opera browser observations.
//!
//! Opera 136.0.6008.52 on Windows 11 (build 26200) is built on Chromium
//! 152.0.7977.130, and Phantom carries no Chromium 152 recipe, so each Opera
//! capture is compared with the Chrome 154 recipes. Opera matches them on the
//! H2 startup, request pseudo-header order and priority, extended CONNECT
//! shape, WebSocket connection choice and opening fields, proxy CONNECT
//! fields, QUIC transport parameters, H3 SETTINGS and request order, and the
//! request fields other than `User-Agent`. Those captures are replayed
//! against [`chromium::v154_http2`], [`chromium::v154_websocket`],
//! [`chromium::v154_proxy_connect`], [`chromium::v154_quic`],
//! [`chromium::v154_http3`], and [`chromium::v154_http3_request`]. The
//! trust-anchor IDs and the client hints differ, so only the TLS offers and
//! client hints, and request templates with a caller `User-Agent`, have Opera
//! recipes here.
//!
//! The retained Opera cookie captures place `Cookie` and split it into crumbs
//! as Chrome 154 does over HTTP/1.1, HTTP/2, and HTTP/3, so they are replayed
//! against [`chromium::v154_cookie_placement`] with the H2 and H3 recipes.
//!
//! Opera's network-stack source is not public, and no wire capture shows socket
//! options or cache lifetimes. Frida hook logs of Opera 136's network service,
//! under `fixtures/socket-hooks/`, show the `TCP_NODELAY`, keepalive, and
//! `SO_RANDOMIZE_PORT` of [`chromium::v154_tcp`] on every origin socket, its
//! 300 ms IPv4 fallback, six connections to one origin as in
//! [`chromium::v154_http1`], and system-resolver answers kept for the 60 s of
//! [`chromium::v154_dns_cache`], as Chrome 154's logs do. Opera profiles
//! therefore use those recipes; Opera has no TCP, HTTP/1.1 connection, or
//! address cache recipe of its own.
//!
//! The macOS 15.5 arm64 capture host still runs Opera 135.0.5973.92, so its
//! client hints keep [`v135_macos_client_hints`].

use crate::{
    chromium,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    request_template::RequestTemplate,
    tls::TlsSettings,
};

// Chromium 152 encodes the trust-anchor ID list in the iteration order of a
// hash set. Over TCP the order is fixed within a browser process and differs
// between processes: these are the 32 IDs in the most frequent order of the
// 29 Opera 136.0.6008.52 processes tallied in `trust-anchor-orders.txt` (5 of
// 29; 16 distinct orders), whose 100 retained ClientHellos never change order
// within a process. Chrome 154 sorts the list and lacks four of these IDs:
// `d6790902`, `d6790903`, `d6790909`, and `d679090e`.
const V136_TRUST_ANCHOR_IDS: &[&[u8]] = &[
    &[0xd6, 0x79, 0x09, 0x0e],
    &[0x82, 0xdf, 0x13, 0x02, 0x14],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a],
    &[0x82, 0xdf, 0x13, 0x02, 0x01],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09],
    &[0xd6, 0x79, 0x09, 0x08],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08],
    &[0xd6, 0x79, 0x09, 0x01],
    &[0xd6, 0x79, 0x09, 0x0d],
    &[0xd6, 0x79, 0x09, 0x0c],
    &[0x82, 0xdf, 0x13, 0x02, 0x0d],
    &[0xd6, 0x79, 0x09, 0x03],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d],
    &[0xd6, 0x79, 0x09, 0x05],
    &[0x82, 0xdf, 0x13, 0x02, 0x0e],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07],
    &[0xd6, 0x79, 0x09, 0x0b],
    &[0x82, 0xdf, 0x13, 0x02, 0x0f],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13],
    &[0x82, 0xdf, 0x13, 0x02, 0x12],
    &[0xd6, 0x79, 0x09, 0x07],
    &[0x82, 0xdf, 0x13, 0x02, 0x06],
    &[0x82, 0xdf, 0x13, 0x02, 0x13],
    &[0xd6, 0x79, 0x09, 0x0f],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12],
    &[0xd6, 0x79, 0x09, 0x04],
    &[0xd6, 0x79, 0x09, 0x0a],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b],
    &[0xd6, 0x79, 0x09, 0x09],
    &[0xd6, 0x79, 0x09, 0x06],
    &[0xd6, 0x79, 0x09, 0x02],
];

// Over QUIC, Opera 136 draws an order per connection: the 20 retained QUIC
// ClientHellos of 6 processes carry 19 orders, and a process's connections
// differ from each other. This is the one order seen twice, on two
// connections of one process.
const V136_QUIC_TRUST_ANCHOR_IDS: &[&[u8]] = &[
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08],
    &[0xd6, 0x79, 0x09, 0x0e],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c],
    &[0xd6, 0x79, 0x09, 0x06],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d],
    &[0xd6, 0x79, 0x09, 0x09],
    &[0x82, 0xdf, 0x13, 0x02, 0x14],
    &[0x82, 0xdf, 0x13, 0x02, 0x01],
    &[0x82, 0xdf, 0x13, 0x02, 0x06],
    &[0x82, 0xdf, 0x13, 0x02, 0x13],
    &[0xd6, 0x79, 0x09, 0x01],
    &[0xd6, 0x79, 0x09, 0x0d],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12],
    &[0x82, 0xdf, 0x13, 0x02, 0x12],
    &[0xd6, 0x79, 0x09, 0x08],
    &[0x82, 0xdf, 0x13, 0x02, 0x0e],
    &[0xd6, 0x79, 0x09, 0x05],
    &[0xd6, 0x79, 0x09, 0x0b],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13],
    &[0x82, 0xdf, 0x13, 0x02, 0x0f],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a],
    &[0xd6, 0x79, 0x09, 0x0c],
    &[0x82, 0xdf, 0x13, 0x02, 0x0d],
    &[0xd6, 0x79, 0x09, 0x03],
    &[0xd6, 0x79, 0x09, 0x0f],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b],
    &[0xd6, 0x79, 0x09, 0x04],
    &[0xd6, 0x79, 0x09, 0x0a],
    &[0xd6, 0x79, 0x09, 0x07],
    &[0xd6, 0x79, 0x09, 0x02],
];

fn trust_anchor_ids(ids: &[&[u8]]) -> Option<Vec<Box<[u8]>>> {
    Some(ids.iter().map(|id| Box::from(*id)).collect())
}

/// Returns TLS settings captured from Opera 136.0.6008.52 on Windows 11.
///
/// Opera 136.0.6008.52 (Windows 11 build 26200) sends the Chrome 154 TCP
/// ClientHello, signature-algorithm GREASE included, in all 29 processes
/// whose ClientHellos are retained (20 startups and 9 resumption runs), with
/// one difference: its trust-anchor IDs extension carries 32 IDs in a
/// per-process order where Chrome 154 sends 28 in sorted order. This reuses
/// [`chromium::v154_tls`] with the most frequent of those processes' orders,
/// which 5 of them used; a recipe cannot draw a new order per process. The
/// retained `client-hello.txt`, one of those five, is replayed against the
/// result. It leaves [`TlsSettings::ech_from_https_records`] unset: no
/// capture shows Opera using an HTTPS record's `ech`.
#[must_use]
pub fn v136_tls() -> TlsSettings {
    let mut settings = chromium::v154_tls();
    settings.requested_trust_anchor_ids = trust_anchor_ids(V136_TRUST_ANCHOR_IDS);
    settings.ech_from_https_records = false;
    settings
}

/// Returns TLS settings for the Opera 136.0.6008.52 HTTP/3 offer on Windows 11.
///
/// The QUIC ClientHellos match [`chromium::v154_http3_tls`] except in the
/// trust-anchor IDs, which are the 32 IDs of [`v136_tls`] in an order drawn
/// per connection: 20 retained QUIC ClientHellos carry 19 orders. This sends
/// the one order Opera sent twice, on two connections of one process, on
/// every connection; the per-connection draw is not modeled. It inherits that
/// recipe's ticket resumption, whose Chromium source basis was read at 154,
/// not at Opera's Chromium 152 base. It clears
/// [`TlsSettings::ech_from_https_records`], as [`v136_tls`] does: no capture
/// shows Opera using an HTTPS record's `ech`.
#[must_use]
pub fn v136_http3_tls() -> TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.requested_trust_anchor_ids = trust_anchor_ids(V136_QUIC_TRUST_ANCHOR_IDS);
    settings.ech_from_https_records = false;
    settings
}

/// Returns client-hint fields observed from Opera 136 on Windows 11 x64.
///
/// Names, order, and delivery match the Chromium client-hint recipes. The
/// values carry Opera's brand list, which leads with Chromium and puts the
/// greased brand `"Not?A_Brand";v="24"` second, the exact 136.0.6008.52
/// build, the Chromium 152.0.7977.130 base it reports in the full version
/// list, and Windows platform data. Three headless runs of the retained
/// navigation capture agree. The returned value is owned and may be
/// customized before client creation.
#[must_use]
pub fn v136_windows_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="152", "Not?A_Brand";v="24", "Opera";v="136""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""136.0.6008.52""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="152.0.7977.130", "Not?A_Brand";v="24.0.0.0", "Opera";v="136.0.6008.52""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

/// Returns client-hint fields observed from Opera 135 on macOS 15.5 arm64.
///
/// Names, order, and delivery match the Chromium client-hint recipes; three
/// headless runs of the retained navigation capture of Opera 135.0.5973.92 on
/// macOS 15.5 (24F74) on Apple silicon agree. The values carry Opera 135's
/// brand list, which puts the greased brand first, its Chromium
/// 151.0.7922.176 base, and macOS platform data: `sec-ch-ua-platform` is
/// `"macOS"`, `sec-ch-ua-platform-version` is `"15.5.0"`, and
/// `sec-ch-ua-arch` is `"arm"`, while `sec-ch-ua-bitness` stays `"64"` and
/// `sec-ch-ua-wow64` stays `?0`. Opera 136 changed the brand list, so these
/// hints are not [`v136_windows_client_hints`] with other platform data. The
/// returned value is owned and may be customized before client creation.
#[must_use]
pub fn v135_macos_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Not=A?Brand";v="99", "Opera";v="135", "Chromium";v="151""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""135.0.5973.92""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""arm""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""macOS""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.5.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Not=A?Brand";v="99.0.0.0", "Opera";v="135.0.5973.92", "Chromium";v="151.0.7922.176""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

/// Returns navigation request fields observed from Opera 136.0.6008.52 on Windows 11.
///
/// Opera sends the fields of [`chromium::v154_windows_navigation_template`]
/// in the same order and with the same values on HTTP/1.1, HTTP/2, and
/// HTTP/3, except `User-Agent` and the brand-bearing client hints, which come
/// from [`v136_windows_client_hints`]. `User-Agent` is a required caller slot:
/// every retained Opera capture ran headless and sent `HeadlessChrome`, and
/// no headful Opera capture backs a literal value. The retained proxy route
/// captures show the Chromium change for a URL that is not potentially
/// trustworthy: to `origin.phantom.test` Opera sends no `Sec-Fetch-*` field
/// and `Accept-Encoding: gzip, deflate`.
///
/// The template also matches the Opera 135.0.5973.92 captures on macOS 15.5
/// arm64 on HTTP/1.1 and HTTP/2, with [`v135_macos_client_hints`], so there
/// is no separate macOS template.
#[must_use]
pub fn v136_windows_navigation_template() -> RequestTemplate {
    chromium::v154_navigation_template(None)
}

/// Returns same-origin no-store `fetch` request fields observed from Opera
/// 136.0.6008.52 on Windows 11.
///
/// The order and values match [`chromium::v154_windows_fetch_no_store_template`]
/// on HTTP/1.1 and HTTP/2, including the HTTP/2 HEADERS priority weight 220,
/// with `User-Agent` as a required caller slot for the reason given in
/// [`v136_windows_navigation_template`]. No capture backs this request kind on
/// HTTP/3, and none shows where hints requested through `Accept-CH` go on a
/// fetch. The macOS 15.5 arm64 captures match it as well.
#[must_use]
pub fn v136_windows_fetch_no_store_template() -> RequestTemplate {
    chromium::v154_fetch_no_store_template(None)
}

#[cfg(test)]
mod tests;
