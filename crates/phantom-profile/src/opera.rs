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
//! `SO_RANDOMIZE_PORT` of [`chromium::v154_tcp`] on every origin socket, the
//! `SO_RANDOMIZE_PORT` of [`chromium::v154_udp`] on every UDP socket it
//! opens, its 300 ms IPv4 fallback, six connections to one origin as in
//! [`chromium::v154_http1`], and system-resolver answers kept for the 60 s of
//! [`chromium::v154_dns_cache`], as Chrome 154's logs do. Opera profiles
//! therefore use those recipes; Opera has no TCP, UDP, HTTP/1.1 connection,
//! or address cache recipe of its own.
//!
//! On macOS 15.5 arm64, Opera 136.0.6008.52 sends the Windows client hints
//! with macOS platform data, [`v136_macos_client_hints`], and the fields of the
//! Windows request templates.

use crate::{
    chromium,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    request_template::RequestTemplate,
    tls::{TlsSettings, TrustAnchorIds},
};

// Chromium 152 encodes the trust-anchor ID list by iterating an
// `absl::flat_hash_set` copied from the network service's SSL configuration
// (`net/ssl/ssl_config_service.cc:101-123`). Each copy takes a new 8-bit
// per-table hash seed, so the order changes with every copy: once per
// process for TCP, whose `SSLClientContext` keeps one copy
// (`net/socket/ssl_client_socket.cc:233`), and once per QUIC session, which
// copies the configuration for each ClientHello
// (`net/quic/quic_chromium_client_session.cc:1750-1771`). Chrome 154 sorts
// the list and lacks four of these IDs: `d6790902`, `d6790903`, `d6790909`,
// and `d679090e`.

/// Opera 136's 32 trust-anchor IDs, in ascending byte order. The orders
/// below list positions in this array.
const V136_TRUST_ANCHOR_IDS: [&[u8]; 32] = [
    &[0x82, 0xdf, 0x13, 0x02, 0x01],
    &[0x82, 0xdf, 0x13, 0x02, 0x06],
    &[0x82, 0xdf, 0x13, 0x02, 0x0d],
    &[0x82, 0xdf, 0x13, 0x02, 0x0e],
    &[0x82, 0xdf, 0x13, 0x02, 0x0f],
    &[0x82, 0xdf, 0x13, 0x02, 0x12],
    &[0x82, 0xdf, 0x13, 0x02, 0x13],
    &[0x82, 0xdf, 0x13, 0x02, 0x14],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13],
    &[0xd6, 0x79, 0x09, 0x01],
    &[0xd6, 0x79, 0x09, 0x02],
    &[0xd6, 0x79, 0x09, 0x03],
    &[0xd6, 0x79, 0x09, 0x04],
    &[0xd6, 0x79, 0x09, 0x05],
    &[0xd6, 0x79, 0x09, 0x06],
    &[0xd6, 0x79, 0x09, 0x07],
    &[0xd6, 0x79, 0x09, 0x08],
    &[0xd6, 0x79, 0x09, 0x09],
    &[0xd6, 0x79, 0x09, 0x0a],
    &[0xd6, 0x79, 0x09, 0x0b],
    &[0xd6, 0x79, 0x09, 0x0c],
    &[0xd6, 0x79, 0x09, 0x0d],
    &[0xd6, 0x79, 0x09, 0x0e],
    &[0xd6, 0x79, 0x09, 0x0f],
];

/// Each TCP order of the 29 Opera 136.0.6008.52 processes tallied in
/// `trust-anchor-orders.txt`, with the number of processes that sent it. A
/// process sent one order on every connection.
const V136_TCP_ORDERS: [(usize, [u8; 32]); 16] = [
    (
        5,
        [
            30, 7, 11, 0, 10, 24, 9, 17, 29, 28, 2, 19, 14, 21, 3, 8, 27, 4, 13, 16, 5, 23, 1, 6,
            31, 15, 20, 26, 12, 25, 22, 18,
        ],
    ),
    (
        4,
        [
            8, 14, 2, 1, 6, 22, 17, 28, 29, 4, 9, 5, 10, 18, 0, 30, 25, 11, 19, 31, 12, 20, 7, 26,
            16, 23, 15, 24, 13, 21, 3, 27,
        ],
    ),
    (
        3,
        [
            7, 29, 0, 19, 13, 31, 20, 8, 27, 6, 1, 14, 28, 15, 5, 18, 30, 3, 16, 26, 4, 23, 22, 2,
            10, 12, 11, 25, 24, 21, 9, 17,
        ],
    ),
    (
        2,
        [
            27, 5, 23, 4, 16, 13, 6, 1, 18, 20, 15, 26, 12, 25, 11, 22, 0, 10, 30, 7, 9, 24, 21,
            17, 29, 28, 14, 2, 19, 31, 3, 8,
        ],
    ),
    (
        2,
        [
            27, 3, 4, 5, 23, 26, 8, 13, 16, 6, 1, 31, 20, 15, 12, 25, 11, 22, 18, 0, 30, 7, 10, 29,
            9, 24, 17, 28, 2, 19, 14, 21,
        ],
    ),
    (
        2,
        [
            30, 15, 6, 1, 4, 24, 5, 17, 3, 16, 28, 29, 11, 19, 10, 2, 12, 21, 27, 7, 23, 31, 20,
            26, 0, 9, 8, 14, 22, 13, 25, 18,
        ],
    ),
    (
        2,
        [
            4, 23, 2, 11, 26, 10, 3, 17, 12, 25, 22, 24, 21, 27, 29, 0, 7, 9, 19, 31, 8, 20, 13,
            14, 28, 5, 18, 15, 6, 30, 16, 1,
        ],
    ),
    (
        1,
        [
            22, 5, 11, 28, 1, 4, 27, 3, 21, 12, 2, 24, 23, 15, 16, 26, 20, 31, 13, 19, 7, 25, 14,
            8, 0, 30, 18, 29, 17, 9, 10, 6,
        ],
    ),
    (
        1,
        [
            2, 19, 12, 29, 31, 3, 11, 20, 27, 4, 28, 10, 5, 9, 1, 6, 18, 30, 26, 23, 22, 8, 0, 14,
            17, 7, 13, 25, 24, 16, 21, 15,
        ],
    ),
    (
        1,
        [
            29, 28, 12, 2, 19, 17, 31, 3, 11, 27, 10, 4, 23, 5, 1, 18, 6, 9, 20, 26, 25, 22, 14, 8,
            0, 30, 7, 13, 24, 16, 21, 15,
        ],
    ),
    (
        1,
        [
            16, 15, 30, 10, 11, 6, 1, 22, 25, 5, 4, 29, 17, 3, 21, 24, 2, 28, 9, 27, 13, 31, 8, 14,
            19, 23, 12, 26, 7, 20, 0, 18,
        ],
    ),
    (
        1,
        [
            20, 1, 25, 14, 22, 18, 0, 8, 30, 13, 7, 16, 24, 15, 17, 29, 28, 2, 12, 11, 19, 21, 3,
            27, 10, 4, 26, 23, 5, 9, 6, 31,
        ],
    ),
    (
        1,
        [
            4, 23, 24, 10, 26, 21, 9, 11, 27, 28, 22, 12, 0, 17, 7, 29, 15, 2, 16, 3, 18, 30, 14,
            13, 8, 25, 5, 19, 31, 1, 6, 20,
        ],
    ),
    (
        1,
        [
            29, 15, 13, 18, 3, 16, 30, 14, 8, 25, 2, 19, 6, 1, 20, 31, 9, 4, 26, 23, 5, 10, 24, 21,
            0, 27, 28, 11, 22, 12, 17, 7,
        ],
    ),
    (
        1,
        [
            11, 12, 28, 18, 30, 0, 26, 7, 23, 9, 22, 8, 17, 13, 25, 14, 5, 24, 21, 15, 6, 1, 27, 3,
            16, 29, 4, 19, 2, 31, 10, 20,
        ],
    ),
    (
        1,
        [
            11, 26, 3, 23, 16, 2, 22, 13, 30, 25, 12, 24, 21, 17, 10, 9, 29, 7, 0, 14, 19, 8, 31,
            1, 27, 6, 28, 4, 5, 18, 15, 20,
        ],
    ),
];

/// Each QUIC order of the 20 QUIC ClientHellos tallied in
/// `trust-anchor-orders.txt`, with the number of ClientHellos that carried
/// it. A process drew a new order for each connection.
const V136_QUIC_ORDERS: [(usize, [u8; 32]); 19] = [
    (
        2,
        [
            10, 9, 30, 8, 13, 22, 14, 25, 7, 0, 1, 6, 17, 29, 15, 5, 24, 3, 21, 27, 16, 4, 11, 28,
            2, 19, 31, 12, 20, 26, 23, 18,
        ],
    ),
    (
        1,
        [
            6, 29, 11, 1, 7, 0, 5, 27, 10, 19, 12, 21, 28, 3, 20, 31, 2, 9, 23, 4, 26, 14, 8, 30,
            18, 22, 25, 13, 15, 17, 16, 24,
        ],
    ),
    (
        1,
        [
            3, 23, 18, 26, 8, 30, 14, 25, 16, 13, 17, 15, 22, 12, 7, 29, 0, 11, 27, 1, 21, 24, 5,
            28, 6, 10, 20, 31, 2, 9, 19, 4,
        ],
    ),
    (
        1,
        [
            27, 13, 20, 31, 16, 15, 19, 23, 12, 7, 0, 26, 11, 18, 5, 25, 10, 30, 6, 1, 9, 2, 22, 4,
            29, 17, 3, 8, 21, 14, 24, 28,
        ],
    ),
    (
        1,
        [
            10, 24, 18, 7, 9, 30, 25, 2, 22, 31, 3, 14, 8, 20, 23, 26, 5, 13, 4, 21, 16, 6, 1, 27,
            28, 15, 19, 12, 29, 0, 17, 11,
        ],
    ),
    (
        1,
        [
            22, 17, 12, 7, 29, 10, 24, 9, 21, 0, 27, 14, 13, 8, 28, 19, 6, 1, 31, 20, 15, 4, 26, 5,
            2, 23, 18, 3, 11, 30, 16, 25,
        ],
    ),
    (
        1,
        [
            11, 27, 13, 4, 5, 28, 19, 0, 31, 16, 1, 20, 6, 15, 26, 23, 18, 2, 14, 30, 3, 8, 25, 10,
            22, 7, 17, 29, 9, 24, 12, 21,
        ],
    ),
    (
        1,
        [
            22, 5, 23, 16, 26, 1, 6, 13, 30, 18, 15, 7, 28, 0, 27, 8, 20, 31, 14, 19, 29, 10, 21,
            9, 2, 24, 25, 4, 12, 3, 11, 17,
        ],
    ),
    (
        1,
        [
            13, 20, 18, 23, 8, 14, 0, 16, 30, 5, 25, 15, 4, 22, 29, 12, 17, 6, 1, 24, 2, 21, 11, 9,
            3, 10, 27, 19, 31, 28, 7, 26,
        ],
    ),
    (
        1,
        [
            12, 17, 22, 7, 29, 10, 24, 9, 21, 0, 27, 14, 13, 8, 28, 19, 6, 31, 1, 20, 15, 4, 26,
            23, 5, 2, 18, 16, 11, 30, 3, 25,
        ],
    ),
    (
        1,
        [
            28, 19, 26, 6, 1, 5, 20, 4, 18, 3, 9, 23, 2, 16, 13, 30, 8, 22, 14, 25, 29, 12, 7, 17,
            0, 15, 21, 24, 27, 10, 11, 31,
        ],
    ),
    (
        1,
        [
            8, 13, 23, 5, 6, 18, 1, 16, 4, 15, 20, 26, 22, 12, 25, 30, 11, 0, 7, 10, 21, 9, 24, 17,
            29, 28, 2, 31, 19, 3, 27, 14,
        ],
    ),
    (
        1,
        [
            10, 12, 31, 22, 20, 25, 11, 26, 15, 23, 21, 16, 3, 27, 8, 28, 2, 13, 19, 1, 6, 17, 14,
            29, 4, 5, 24, 18, 0, 30, 9, 7,
        ],
    ),
    (
        1,
        [
            17, 21, 11, 24, 29, 12, 22, 15, 30, 3, 13, 16, 25, 14, 2, 8, 18, 20, 6, 1, 26, 23, 4,
            19, 9, 5, 31, 27, 10, 0, 28, 7,
        ],
    ),
    (
        1,
        [
            23, 26, 16, 10, 30, 11, 18, 6, 1, 22, 25, 5, 12, 29, 4, 17, 3, 9, 24, 2, 13, 27, 21, 8,
            19, 14, 28, 7, 20, 0, 31, 15,
        ],
    ),
    (
        1,
        [
            9, 2, 13, 29, 27, 8, 21, 19, 14, 28, 7, 20, 0, 31, 15, 23, 26, 16, 10, 30, 18, 1, 6,
            22, 11, 5, 25, 12, 4, 17, 3, 24,
        ],
    ),
    (
        1,
        [
            29, 15, 12, 31, 3, 24, 20, 5, 28, 11, 19, 4, 10, 1, 18, 6, 9, 30, 23, 26, 0, 7, 14, 17,
            25, 8, 22, 13, 16, 21, 27, 2,
        ],
    ),
    (
        1,
        [
            19, 7, 18, 12, 0, 30, 10, 23, 26, 9, 14, 29, 8, 13, 17, 25, 1, 6, 5, 22, 4, 15, 2, 21,
            3, 27, 16, 24, 20, 31, 11, 28,
        ],
    ),
    (
        1,
        [
            28, 10, 9, 8, 14, 19, 31, 13, 29, 17, 0, 27, 1, 6, 23, 15, 4, 5, 20, 3, 16, 26, 25, 11,
            22, 2, 18, 30, 12, 7, 24, 21,
        ],
    ),
];

/// Expands `orders` into the list a draw selects from: each order once for
/// every observation of it, so the draw follows the observed frequencies.
fn observed_orders(orders: &[(usize, [u8; 32])]) -> Vec<Vec<Box<[u8]>>> {
    orders
        .iter()
        .flat_map(|(count, positions)| {
            let order = positions
                .iter()
                .map(|&position| Box::from(V136_TRUST_ANCHOR_IDS[usize::from(position)]))
                .collect::<Vec<_>>();
            std::iter::repeat_n(order, *count)
        })
        .collect()
}

/// Returns TLS settings captured from Opera 136.0.6008.52 on Windows 11.
///
/// Opera 136.0.6008.52 (Windows 11 build 26200) sends the Chrome 154 TCP
/// ClientHello, signature-algorithm GREASE included, in all 29 processes
/// whose ClientHellos are retained (20 startups and 9 resumption runs), with
/// one difference: its trust-anchor IDs extension carries 32 IDs in a
/// per-process order where Chrome 154 sends 28 in sorted order. This reuses
/// [`chromium::v154_tls`] with [`TrustAnchorIds::PerClient`]: each client
/// draws one of the 29 processes' orders, 16 distinct, and keeps it on every
/// TCP connection, as a process does. The retained `client-hello.txt` is
/// replayed against the result. It keeps
/// [`TlsSettings::ech_from_https_records`] set: given an HTTPS record with
/// `ech` from its DNS-over-HTTPS server, Opera 136 sent the configuration,
/// and after a rejection it retried once with the server's retry
/// configuration, as Chrome 154 does.
#[must_use]
pub fn v136_tls() -> TlsSettings {
    let mut settings = chromium::v154_tls();
    settings.requested_trust_anchor_ids =
        Some(TrustAnchorIds::PerClient(observed_orders(&V136_TCP_ORDERS)));
    settings
}

/// Returns TLS settings for the Opera 136.0.6008.52 HTTP/3 offer on Windows 11.
///
/// The QUIC ClientHellos match [`chromium::v154_http3_tls`] except in the
/// trust-anchor IDs, which are the 32 IDs of [`v136_tls`] in an order drawn
/// per connection: 20 retained QUIC ClientHellos carry 19 orders. This sends
/// them with [`TrustAnchorIds::PerConnection`], drawing one of those 20
/// ClientHellos' orders for each connection. It inherits that recipe's
/// ticket resumption, whose Chromium source basis was read at 154, not at
/// Opera's Chromium 152 base. It keeps
/// [`TlsSettings::ech_from_https_records`], as [`v136_tls`] does: Opera 136
/// sent an HTTPS record's `ech` over QUIC, and closed a rejected QUIC
/// connection with `ech_required` without retrying it there, as Chrome 154
/// does.
#[must_use]
pub fn v136_http3_tls() -> TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::PerConnection(observed_orders(
        &V136_QUIC_ORDERS,
    )));
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

/// Returns client-hint fields observed from Opera 136 on macOS 15.5 arm64.
///
/// Names, order, delivery, the brand list, and the versions match
/// [`v136_windows_client_hints`]; three headless runs of the retained
/// navigation capture of Opera 136.0.6008.52 on macOS 15.5 (24F74) on Apple
/// silicon agree. Only the platform data differs: `sec-ch-ua-platform` is
/// `"macOS"`, `sec-ch-ua-platform-version` is `"15.5.0"`, and
/// `sec-ch-ua-arch` is `"arm"`, while `sec-ch-ua-bitness` stays `"64"` and
/// `sec-ch-ua-wow64` stays `?0`. The returned value is owned and may be
/// customized before client creation, for example to carry another macOS
/// version.
#[must_use]
pub fn v136_macos_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="152", "Not?A_Brand";v="24", "Opera";v="136""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""136.0.6008.52""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""arm""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""macOS""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.5.0""#, AcceptCh),
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
/// The template also matches the Opera 136.0.6008.52 captures on macOS 15.5
/// arm64 on HTTP/1.1, HTTP/2, and HTTP/3, with [`v136_macos_client_hints`],
/// so there is no separate macOS template.
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
