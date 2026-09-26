//! Wire settings retained from Microsoft Edge browser observations.
//!
//! Edge 153.0.4234.48 on Windows 11 (build 26200) matches the retained
//! Chromium captures on the H2 startup, request pseudo-header order and
//! priority, extended CONNECT shape, WebSocket connection choice and opening
//! fields, QUIC transport parameters, and H3 SETTINGS and request order. Those
//! layers were byte-identical or field-for-field equal between Chrome 153 and
//! Chrome 154, so the Edge captures are replayed against the surviving
//! [`chromium::v154_http2`], [`chromium::v154_websocket`],
//! [`chromium::v154_quic`], [`chromium::v154_http3`], and
//! [`chromium::v154_http3_request`] recipes. The TLS offers, client hints, and
//! `User-Agent` differ, so only they have Edge recipes here.
//!
//! There is no Edge TCP recipe. Socket options are not visible in captures,
//! and Edge's network-stack source is not public, so no retained evidence
//! shows whether Edge keeps the Chromium options in [`chromium::v154_tcp`].

use crate::{
    chromium,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    request_template::RequestTemplate,
    tls::TlsSettings,
};

/// Returns TLS settings captured from Edge 153.0.4234.48 on Windows 11.
///
/// Edge 153.0.4234.48 (Windows 11 build 26200) sends the Chromium TCP
/// ClientHello without the trust-anchor IDs extension, across 20 fresh
/// processes. The Chrome 153 and Chrome 154 ClientHellos differ only in that
/// extension, so this reuses [`chromium::v154_tls`] and removes the ID list;
/// the retained Edge ClientHello is replayed against the result.
///
/// It keeps [`TlsSettings::ech_from_https_records`] from that recipe. Given
/// an HTTPS record with `ech`, Edge 153.0.4234.48 encrypted its ClientHello
/// with the record's configuration and retried a rejection with the
/// server's retry configurations, with the same outer fields and extension
/// set as Chrome 154, in three runs of each scenario.
#[must_use]
pub fn v153_tls() -> TlsSettings {
    let mut settings = chromium::v154_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns TLS settings for the Edge 153.0.4234.48 HTTP/3 offer on Windows 11.
///
/// The QUIC ClientHello matches [`chromium::v154_http3_tls`] without the
/// trust-anchor IDs extension, so this reuses that recipe and removes only
/// the ID list. It inherits that recipe's ticket resumption, whose Chromium
/// source basis was read at 154, not at Edge's Chromium 153 base.
///
/// It also keeps [`TlsSettings::ech_from_https_records`]. Given an HTTPS
/// record that lists `h3` and carries `ech`, Edge 153.0.4234.48 encrypted its
/// QUIC ClientHello with the record's configuration and did not repeat a
/// rejected QUIC connection, as Chrome 154 does, in three runs of each
/// scenario.
#[must_use]
pub fn v153_http3_tls() -> TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns client-hint fields observed from Edge 153 on Windows 11 x64.
///
/// Names, order, and delivery match the Chromium client-hint recipes. The
/// values carry Edge's brand
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

/// Returns client-hint fields observed from Edge 153 on macOS 15.5 arm64.
///
/// Names, order, delivery, and the brand and version values match
/// [`v153_windows_client_hints`]; three headless runs of the retained
/// navigation capture of Edge 153.0.4234.48 on macOS 15.5 (24F74) on Apple
/// silicon agree. Only the platform data differs: `sec-ch-ua-platform` is
/// `"macOS"`, `sec-ch-ua-platform-version` is `"15.5.0"`, and
/// `sec-ch-ua-arch` is `"arm"`, while `sec-ch-ua-bitness` stays `"64"` and
/// `sec-ch-ua-wow64` stays `?0`. The returned value is owned and may be
/// customized before client creation, for example to carry another macOS
/// version.
#[must_use]
pub fn v153_macos_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""153.0.4234.48""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""arm""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""macOS""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.5.0""#, AcceptCh),
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
/// Edge sends the fields of [`chromium::v154_windows_navigation_template`] in
/// the same order and with the same values on HTTP/1.1, HTTP/2, and HTTP/3,
/// except `User-Agent` and the brand-bearing client hints, which come from
/// [`v153_windows_client_hints`]. `User-Agent` is a required caller slot:
/// every retained Edge capture ran headless and sent `HeadlessChrome`, and no
/// headful Edge capture backs a literal value. The `phantom` client fails a
/// request without a caller `User-Agent` instead of sending Edge brand hints
/// with no `User-Agent`.
///
/// The retained Edge proxy route captures show the Chromium change for a URL
/// that is not potentially trustworthy too: to `origin.phantom.test` Edge
/// sends no `Sec-Fetch-*` field and `Accept-Encoding: gzip, deflate`.
///
/// The template also matches the Edge 153.0.4234.48 captures on macOS 15.5
/// arm64 on HTTP/1.1 and HTTP/2, with [`v153_macos_client_hints`], so there
/// is no separate macOS template. On macOS Edge takes `Accept-Language` from
/// the system language list and ignores `--lang`; those captures ran with
/// `--accept-lang=en-US`, which gives this template's `en-US,en;q=0.9`.
#[must_use]
pub fn v153_windows_navigation_template() -> RequestTemplate {
    chromium::v154_navigation_template(None)
}

/// Returns same-origin no-store `fetch` request fields observed from Edge
/// 153.0.4234.48 on Windows 11.
///
/// The order and values match [`chromium::v154_windows_fetch_no_store_template`]
/// on HTTP/1.1 and HTTP/2, including the captured HTTP/2 HEADERS priority
/// weight 220 that differs from the navigation's 256, with `User-Agent` as a
/// required caller slot for the reason given in
/// [`v153_windows_navigation_template`].
/// No capture backs this request kind on HTTP/3. As with Chrome, no capture
/// shows where hints requested through `Accept-CH` go on a fetch, so a
/// requested hint cannot be sent with this template. The macOS 15.5 arm64
/// captures match it as well, as for [`v153_windows_navigation_template`].
#[must_use]
pub fn v153_windows_fetch_no_store_template() -> RequestTemplate {
    chromium::v154_fetch_no_store_template(None)
}

#[cfg(test)]
mod tests;
