//! Wire settings retained from Opera browser observations.
//!
//! Opera 135.0.5973.92 on Windows 11 (build 26200) is built on Chromium
//! 151.0.7922.176, and Phantom carries no Chromium 151 recipe, so each Opera
//! capture is compared with the Chrome 154 recipes. Opera matches them on the
//! H2 startup, request pseudo-header order and priority, extended CONNECT
//! shape, WebSocket connection choice and opening fields, proxy CONNECT
//! fields, QUIC transport parameters, H3 SETTINGS and request order, and the
//! request fields other than `User-Agent`. Those captures are replayed
//! against [`chromium::v154_http2`], [`chromium::v154_websocket`],
//! [`chromium::v154_proxy_connect`], [`chromium::v154_quic`],
//! [`chromium::v154_http3`], and [`chromium::v154_http3_request`]. The TLS
//! offers and client hints differ, so only they, and request templates with
//! a caller `User-Agent`, have Opera recipes here.
//!
//! The retained Opera cookie captures place `Cookie` and split it into crumbs
//! as Chrome 154 does over HTTP/1.1, HTTP/2, and HTTP/3, so they are replayed
//! against [`chromium::v154_cookie_placement`] with the H2 and H3 recipes.
//!
//! There is no Opera TCP, HTTP/1.1 connection, or address cache recipe.
//! Those behaviors are not visible in these captures, and Opera's
//! network-stack source is not public.

use crate::{
    chromium,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    request_template::RequestTemplate,
    tls::TlsSettings,
};

/// Returns TLS settings captured from Opera 135.0.5973.92 on Windows 11.
///
/// Opera 135.0.5973.92 (Windows 11 build 26200) sends the Chrome 154 TCP
/// ClientHello with two differences, across 19 fresh processes: no
/// trust-anchor IDs extension, and no GREASE value at the head of
/// `signature_algorithms`. This reuses [`chromium::v154_tls`], removes the ID
/// list, and clears [`TlsSettings::grease_signature_algorithms`]; the
/// retained Opera ClientHello is replayed against the result. It leaves
/// [`TlsSettings::ech_from_https_records`] unset: no capture shows Opera
/// using an HTTPS record's `ech`.
#[must_use]
pub fn v135_tls() -> TlsSettings {
    let mut settings = chromium::v154_tls();
    settings.requested_trust_anchor_ids = None;
    settings.grease_signature_algorithms = false;
    settings.ech_from_https_records = false;
    settings
}

/// Returns TLS settings for the Opera 135.0.5973.92 HTTP/3 offer on Windows 11.
///
/// The QUIC ClientHellos match [`chromium::v154_http3_tls`] without the
/// trust-anchor IDs extension. That recipe already sends no signature
/// algorithm GREASE over QUIC, so this removes only the ID list. It inherits
/// that recipe's ticket resumption, whose Chromium source basis was read at
/// 154, not at Opera's Chromium 151 base. It clears
/// [`TlsSettings::ech_from_https_records`], as [`v135_tls`] does: no capture
/// shows Opera using an HTTPS record's `ech`.
#[must_use]
pub fn v135_http3_tls() -> TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.requested_trust_anchor_ids = None;
    settings.ech_from_https_records = false;
    settings
}

/// Returns client-hint fields observed from Opera 135 on Windows 11 x64.
///
/// Names, order, and delivery match the Chromium client-hint recipes. The
/// values carry Opera's brand list, which puts the greased brand first, the
/// exact 135.0.5973.92 build, the Chromium 151.0.7922.176 base it reports in
/// the full version list, and Windows platform data. Three headless runs of
/// the retained navigation capture agree. The returned value is owned and
/// may be customized before client creation.
#[must_use]
pub fn v135_windows_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Not=A?Brand";v="99", "Opera";v="135", "Chromium";v="151""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""135.0.5973.92""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
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

/// Returns client-hint fields observed from Opera 135 on macOS 15.5 arm64.
///
/// Names, order, delivery, and the brand and version values match
/// [`v135_windows_client_hints`]; three headless runs of the retained
/// navigation capture of Opera 135.0.5973.92 on macOS 15.5 (24F74) on Apple
/// silicon agree. Only the platform data differs: `sec-ch-ua-platform` is
/// `"macOS"`,
/// `sec-ch-ua-platform-version` is `"15.5.0"`, and `sec-ch-ua-arch` is
/// `"arm"`, while `sec-ch-ua-bitness` stays `"64"` and `sec-ch-ua-wow64`
/// stays `?0`. The returned value is owned and may be customized before
/// client creation.
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

/// Returns navigation request fields observed from Opera 135.0.5973.92 on Windows 11.
///
/// Opera sends the fields of [`chromium::v154_windows_navigation_template`]
/// in the same order and with the same values on HTTP/1.1, HTTP/2, and
/// HTTP/3, except `User-Agent` and the brand-bearing client hints, which come
/// from [`v135_windows_client_hints`]. `User-Agent` is a required caller slot:
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
pub fn v135_windows_navigation_template() -> RequestTemplate {
    chromium::v154_navigation_template(None)
}

/// Returns same-origin no-store `fetch` request fields observed from Opera
/// 135.0.5973.92 on Windows 11.
///
/// The order and values match [`chromium::v154_windows_fetch_no_store_template`]
/// on HTTP/1.1 and HTTP/2, including the HTTP/2 HEADERS priority weight 220,
/// with `User-Agent` as a required caller slot for the reason given in
/// [`v135_windows_navigation_template`]. No capture backs this request kind on
/// HTTP/3, and none shows where hints requested through `Accept-CH` go on a
/// fetch. The macOS 15.5 arm64 captures match it as well.
#[must_use]
pub fn v135_windows_fetch_no_store_template() -> RequestTemplate {
    chromium::v154_fetch_no_store_template(None)
}

#[cfg(test)]
mod tests;
