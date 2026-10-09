//! Wire settings retained from Microsoft Edge browser observations.
//!
//! Edge 154.0.4258.37 on Windows 11 (build 26200) matches the retained
//! Chromium captures on the H2 startup, request pseudo-header order and
//! priority, extended CONNECT shape, WebSocket connection choice and opening
//! fields, QUIC transport parameters, and H3 SETTINGS and request order, so
//! the Edge captures are replayed against [`chrome::v154_http2`],
//! [`chrome::v154_websocket`], [`chrome::v154_quic`],
//! [`chrome::v154_http3`], and [`chrome::v154_http3_request`]. The TLS
//! offers, client hints, and `User-Agent` differ, so only they have Edge
//! recipes here.
//!
//! Edge 154 changed only the client hints from Edge 153.0.4234.48: the brand
//! list, its order, and the versions. The TCP and QUIC ClientHellos, the H2
//! startup, and the H3 SETTINGS are unchanged, on Windows and on macOS. The
//! Windows host then updated to Edge 154.0.4258.48, which differs from
//! 154.0.4258.37 only in the full version its client hints report, so
//! [`v154_windows_client_hints`] comes from 154.0.4258.48 captures and the
//! other Windows recipes from 154.0.4258.37 ones. Every macOS capture,
//! including the one behind [`v154_macos_client_hints`], is of 154.0.4258.48.
//!
//! Edge's network-stack source is not public, and no wire capture shows socket
//! options or cache lifetimes. Frida hook logs of Edge 154.0.4258.48's network
//! service, under `fixtures/socket-hooks/`, show the `TCP_NODELAY`, keepalive,
//! and `SO_RANDOMIZE_PORT` of [`chrome::v154_tcp`] on every origin socket,
//! the `SO_RANDOMIZE_PORT` of [`chrome::v154_udp`] on every UDP socket it
//! opens, QUIC sockets among them, its 300 ms IPv4 fallback, six connections to
//! one origin as in [`chrome::v154_http1`], and system-resolver answers kept
//! for the 60 s of [`chrome::v154_dns_cache`], as Chrome 154's logs do. Edge
//! profiles therefore use those recipes; Edge has no TCP, UDP, HTTP/1.1
//! connection, or address cache recipe of its own. Edge, like Chrome 154, fails
//! a refused loopback connect at once, so its unmodified run tried IPv4 3 ms
//! after the refused `[::1]` attempt; the 300 ms fallback shows in the run
//! whose hook kept that attempt pending.

//!
//! ## Android
//!
//! Wire settings retained from Microsoft Edge for Android observations.
//!
//! Edge 153.0.4234.49 for Android, the arm64 build the Google Play Store
//! serves, captured on an arm64 Android 17 emulator that reports a Pixel 7
//! on build `CP3A.260905.009`. Edge for Android reads Chrome's command-line
//! file, so the Chrome for Android launches and tools apply unchanged.
//!
//! The TLS and QUIC ClientHellos equal desktop Edge's, which Edge 153 and 154
//! send alike: the Chromium offers without trust-anchor IDs. The H2 startup,
//! QUIC transport parameters, H3 SETTINGS, and request field orders equal the
//! Chromium recipes. Only the client hints and `User-Agent` carry Edge for
//! Android data.
//!
//! There is no TCP, HTTP/1.1 connection, address-cache, proxy CONNECT,
//! WebSocket, or cookie-placement recipe: the emulator hides socket options,
//! as [`crate::browser::chrome`] explains, and only the `accept` and
//! `h1-accept` WebSocket scenarios were captured, for their page and `fetch`
//! requests.

use crate::{ClientProfile, Http3ClientSettings};

mod android;

pub use android::{
    v153_android_client_hints, v153_android_client_hints_for_model,
    v153_android_fetch_no_store_template, v153_android_http2, v153_android_http3,
    v153_android_http3_request, v153_android_navigation_template, v153_android_quic,
    v153_android_quic_tls, v153_android_tcp_tls,
};

use crate::{
    browser::chrome,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    request_template::RequestTemplate,
    tls::TlsSettings,
};

/// Returns TLS settings captured from Edge 154.0.4258.37 on Windows 11.
///
/// Edge 154.0.4258.37 (Windows 11 build 26200) sends the Chromium TCP
/// ClientHello without the trust-anchor IDs extension, as Edge 153 did across
/// 20 fresh processes, so this reuses [`chrome::v154_tcp_tls`] and removes the
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
pub fn v154_tcp_tls() -> TlsSettings {
    let mut settings = chrome::v154_tcp_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns TLS settings for the Edge 154.0.4258.37 HTTP/3 offer on Windows 11.
///
/// The QUIC ClientHello matches [`chrome::v154_quic_tls`] without the
/// trust-anchor IDs extension, so this reuses that recipe and removes only
/// the ID list. It inherits that recipe's ticket resumption.
///
/// It also keeps [`TlsSettings::ech_from_https_records`]. Given an HTTPS
/// record that lists `h3` and carries `ech`, Edge 153.0.4234.48 encrypted its
/// QUIC ClientHello with the record's configuration and did not repeat a
/// rejected QUIC connection, as Chrome 154 does, in three runs of each
/// scenario. No Edge 154 capture repeats those scenarios.
#[must_use]
pub fn v154_quic_tls() -> TlsSettings {
    let mut settings = chrome::v154_quic_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns client-hint fields observed from Edge 154 on Windows 11 x64.
///
/// Names, order, and delivery match the Chromium client-hint recipes. The
/// values carry Edge's brand list, the exact 154.0.4258.48 build, the
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
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.4258.48""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.58", "Microsoft Edge";v="154.0.4258.48", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

/// Returns client-hint fields observed from Edge 154 on macOS 15.5 arm64.
///
/// Names, order, delivery, the brand list, and the versions match
/// [`v154_windows_client_hints`]; three headless runs of the retained
/// navigation capture of Edge 154.0.4258.48 on macOS 15.5 (24F74) on Apple
/// silicon agree. Only the platform data differs: `sec-ch-ua-platform` is
/// `"macOS"`, `sec-ch-ua-platform-version` is `"15.5.0"`, and
/// `sec-ch-ua-arch` is `"arm"`, while `sec-ch-ua-bitness` stays `"64"` and
/// `sec-ch-ua-wow64` stays `?0`. The returned value is owned and may be
/// customized before client creation, for example to carry another macOS
/// version.
#[must_use]
pub fn v154_macos_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Microsoft Edge";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.4258.48""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""arm""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""macOS""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.5.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.58", "Microsoft Edge";v="154.0.4258.48", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

/// Returns navigation request fields observed from Edge 154.0.4258.37 on Windows 11.
///
/// Edge sends the fields of [`chrome::v154_windows_navigation_template`] in
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
/// The template also matches the Edge 154.0.4258.48 captures on macOS 15.5
/// arm64 on HTTP/1.1 and HTTP/2, with [`v154_macos_client_hints`], so there
/// is no separate macOS template. On macOS Edge takes `Accept-Language` from
/// the system language list and ignores `--lang`; those captures ran with
/// `--accept-lang=en-US`, which gives this template's `en-US,en;q=0.9`. For a
/// Mac with another language list, override `Accept-Language`.
#[must_use]
pub fn v154_windows_navigation_template() -> RequestTemplate {
    chrome::v154_navigation_template(None)
}

/// Returns same-origin no-store `fetch` request fields observed from Edge
/// 154.0.4258.37 on Windows 11.
///
/// The order and values match [`chrome::v154_windows_fetch_no_store_template`]
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
    chrome::v154_fetch_no_store_template(None)
}

/// Returns the Windows connection profile for Edge 154.
///
/// Includes TCP, HTTP/1.1 policy, address cache, HTTP/2, HTTP/3, WebSocket,
/// proxy CONNECT fields, and cookie placement. UDP socket settings and
/// client hints are included.
/// No request template is selected. Choose one for your request kind.
#[must_use]
pub fn v154_windows() -> ClientProfile {
    ClientProfile::new(v154_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_udp(chrome::v154_udp())
        .with_dns_cache(chrome::v154_dns_cache())
        .with_http1(chrome::v154_http1())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(v154_windows_client_hints())
        .with_websocket(chrome::v154_websocket())
        .with_proxy_connect(chrome::v154_proxy_connect())
        .with_cookie_placement(chrome::v154_cookie_placement())
}

/// Returns the captured Android layers for Edge 153.
///
/// Supplies TCP TLS, HTTP/2, HTTP/3, and client hints.
/// No WebSocket recipe is supplied.
/// TCP socket, UDP socket, HTTP/1.1 policy, address-cache, proxy CONNECT,
/// and cookie-placement recipes are absent. Their generic defaults remain.
/// No request template is selected. These captures came from emulators.
#[must_use]
pub fn v153_android() -> ClientProfile {
    ClientProfile::new(v153_android_tcp_tls())
        .with_http2(v153_android_http2())
        .with_http3(Http3ClientSettings::new(
            v153_android_quic_tls(),
            v153_android_quic(),
            v153_android_http3(),
            v153_android_http3_request(),
        ))
        .with_client_hints(v153_android_client_hints())
}

#[cfg(test)]
mod tests;
