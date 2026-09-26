//! Wire settings retained from Microsoft Edge browser observations.
//!
//! Edge 154.0.4258.37 on Windows 11 (build 26200) matches the retained
//! Chromium captures on the H2 startup, request pseudo-header order and
//! priority, extended CONNECT shape, WebSocket connection choice and opening
//! fields, QUIC transport parameters, and H3 SETTINGS and request order, so
//! the Edge captures are replayed against [`chromium::v154_http2`],
//! [`chromium::v154_websocket`], [`chromium::v154_quic`],
//! [`chromium::v154_http3`], and [`chromium::v154_http3_request`]. The TLS
//! offers, client hints, and `User-Agent` differ, so only they have Edge
//! recipes here.
//!
//! Edge 154 changed only the client hints from Edge 153.0.4234.48: the brand
//! list, its order, and the versions. The TCP and QUIC ClientHellos, the H2
//! startup, and the H3 SETTINGS are unchanged. The macOS client hints remain
//! those of Edge 153, the version on the retained Mac.
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

/// Returns TLS settings captured from Edge 154.0.4258.37 on Windows 11.
///
/// Edge 154.0.4258.37 (Windows 11 build 26200) sends the Chromium TCP
/// ClientHello without the trust-anchor IDs extension, as Edge 153 did across
/// 20 fresh processes, so this reuses [`chromium::v154_tls`] and removes the
/// ID list; the retained Edge 154 ClientHello is replayed against the result.
///
/// It keeps [`TlsSettings::ech_from_https_records`] from that recipe. Given
/// an HTTPS record with `ech`, Edge 153.0.4234.48 encrypted its ClientHello
/// with the record's configuration and retried a rejection with the
/// server's retry configurations, with the same outer fields and extension
/// set as Chrome 154, in three runs of each scenario. No Edge 154 capture
/// repeats those scenarios; its ClientHello without an HTTPS record is
/// unchanged from Edge 153's.
#[must_use]
pub fn v154_tls() -> TlsSettings {
    let mut settings = chromium::v154_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns TLS settings for the Edge 154.0.4258.37 HTTP/3 offer on Windows 11.
///
/// The QUIC ClientHello matches [`chromium::v154_http3_tls`] without the
/// trust-anchor IDs extension, so this reuses that recipe and removes only
/// the ID list. It inherits that recipe's ticket resumption.
///
/// It also keeps [`TlsSettings::ech_from_https_records`]. Given an HTTPS
/// record that lists `h3` and carries `ech`, Edge 153.0.4234.48 encrypted its
/// QUIC ClientHello with the record's configuration and did not repeat a
/// rejected QUIC connection, as Chrome 154 does, in three runs of each
/// scenario. No Edge 154 capture repeats those scenarios.
#[must_use]
pub fn v154_http3_tls() -> TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns client-hint fields observed from Edge 154 on Windows 11 x64.
///
/// Names, order, and delivery match the Chromium client-hint recipes. The
/// values carry Edge's brand list, the exact 154.0.4258.37 build, the
/// Chromium 154.0.8037.58 base it reports in the full version list, and
/// Windows platform data. Edge 154 lists `Chromium` first and sends the
/// `Not A(Brand` GREASE brand at version 99, where Edge 153 listed
/// `Microsoft Edge` first with `Not_A Brand` at version 8. The returned value
/// is owned and may be customized before client creation.
#[must_use]
pub fn v154_windows_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Microsoft Edge";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.4258.37""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.58", "Microsoft Edge";v="154.0.4258.37", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

/// Returns client-hint fields observed from Edge 153 on macOS 15.5 arm64.
///
/// Three headless runs of the retained navigation capture of Edge
/// 153.0.4234.48 on macOS 15.5 (24F74) on Apple silicon agree. Names, order,
/// and delivery match [`v154_windows_client_hints`]. The brand and version
/// values are Edge 153's, and the platform data is the Mac's:
/// `sec-ch-ua-platform` is `"macOS"`, `sec-ch-ua-platform-version` is
/// `"15.5.0"`, and `sec-ch-ua-arch` is `"arm"`, while `sec-ch-ua-bitness`
/// stays `"64"` and `sec-ch-ua-wow64` stays `?0`. The returned value is
/// owned and may be customized before client creation, for example to carry
/// another macOS or Edge version.
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

/// Returns navigation request fields observed from Edge 154.0.4258.37 on Windows 11.
///
/// Edge sends the fields of [`chromium::v154_windows_navigation_template`] in
/// the same order and with the same values on HTTP/1.1, HTTP/2, and HTTP/3,
/// except `User-Agent` and the brand-bearing client hints, which come from
/// [`v154_windows_client_hints`]. `User-Agent` is a required caller slot:
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
/// `--accept-lang=en-US`, which gives this template's `en-US,en;q=0.9`. For a
/// Mac with another language list, override `Accept-Language`.
#[must_use]
pub fn v154_windows_navigation_template() -> RequestTemplate {
    chromium::v154_navigation_template(None)
}

/// Returns same-origin no-store `fetch` request fields observed from Edge
/// 154.0.4258.37 on Windows 11.
///
/// The order and values match [`chromium::v154_windows_fetch_no_store_template`]
/// on HTTP/1.1 and HTTP/2, including the captured HTTP/2 HEADERS priority
/// weight 220 that differs from the navigation's 256, with `User-Agent` as a
/// required caller slot for the reason given in
/// [`v154_windows_navigation_template`].
/// No capture backs this request kind on HTTP/3. As with Chrome, no capture
/// shows where hints requested through `Accept-CH` go on a fetch, so a
/// requested hint cannot be sent with this template. The macOS 15.5 arm64
/// captures match it as well, as for [`v154_windows_navigation_template`].
#[must_use]
pub fn v154_windows_fetch_no_store_template() -> RequestTemplate {
    chromium::v154_fetch_no_store_template(None)
}

#[cfg(test)]
mod tests;
