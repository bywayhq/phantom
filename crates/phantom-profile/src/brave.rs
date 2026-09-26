//! Wire settings retained from Brave browser observations.
//!
//! Brave 154.1.96.59 on Windows 11 (build 26200) is built on Chromium 154. Its
//! captures match the retained Chrome 154 captures on the H2 startup, request
//! pseudo-header order and priority, extended CONNECT shape, WebSocket
//! connection choice and opening fields, proxy CONNECT fields, QUIC transport
//! parameters, and H3 SETTINGS, so they are replayed against
//! [`chromium::v154_http2`], [`chromium::v154_websocket`],
//! [`chromium::v154_proxy_connect`], [`chromium::v154_quic`],
//! [`chromium::v154_http3`], and [`chromium::v154_http3_request`]. The TLS
//! offers, client hints, and request fields differ, so only they have Brave
//! recipes here.
//!
//! There is no Brave TCP, HTTP/1.1 connection, address cache, or cookie
//! placement recipe. Socket options, connection counts, and caches are not
//! visible in these captures, and no Brave source at this tag has been read
//! for them.

use crate::{
    chromium,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    request_template::{RequestField, RequestTemplate},
    tls::TlsSettings,
};

/// Brave's navigation `Accept` value: Chrome's without the
/// `application/signed-exchange` entry.
const V154_NAVIGATION_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,\
image/avif,image/webp,image/apng,*/*;q=0.8";

/// Returns TLS settings captured from Brave 154.1.96.59 on Windows 11.
///
/// Brave 154.1.96.59 (Windows 11 build 26200) sends the Chrome 154 TCP
/// ClientHello without the trust-anchor IDs extension, across 20 fresh
/// processes, so this reuses [`chromium::v154_tls`] and removes the ID list;
/// the retained Brave ClientHello is replayed against the result.
///
/// It keeps [`TlsSettings::ech_from_https_records`] set. The retained
/// `ech-accept.txt` capture shows Brave encrypting its ClientHello with the
/// configuration from an HTTPS record: outer name `public.phantom.test`,
/// HKDF-SHA256 with AES-128-GCM, a 32-byte encapsulated key, and a 144-byte
/// payload, as Chrome 154 sends. In `ech-reject.txt` Brave connects once more
/// with the server's retry configuration, which the origin accepts.
#[must_use]
pub fn v154_tls() -> TlsSettings {
    let mut settings = chromium::v154_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns TLS settings for the Brave 154.1.96.59 HTTP/3 offer on Windows 11.
///
/// The QUIC ClientHellos of three fresh processes match
/// [`chromium::v154_http3_tls`] without the trust-anchor IDs extension, so
/// this reuses that recipe and removes only the ID list. It inherits that
/// recipe's ticket resumption, which the retained Brave resumption captures
/// show: a resumed connection offers early data.
///
/// It also keeps [`TlsSettings::ech_from_https_records`]. Given an HTTPS
/// record that lists `h3` and carries `ech`, Brave 154.1.96.59 encrypted its
/// QUIC ClientHello with the record's configuration and did not repeat a
/// rejected QUIC connection, as Chrome 154 does, in three runs of each
/// scenario.
#[must_use]
pub fn v154_http3_tls() -> TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns client-hint fields observed from Brave 154 on Windows 11 x64.
///
/// From the retained fresh-profile navigation capture of Brave 154.1.96.59,
/// three headless runs that agree. The names Brave sends keep the Chromium
/// order and delivery, but Brave sends two fewer: after `Accept-CH` it adds
/// no `sec-ch-ua-full-version` and no `sec-ch-ua-form-factors`. Its brand list
/// names `"Brave"` where Chrome names `"Google Chrome"`, and the full version
/// list reports every brand as `154.0.0.0` or `99.0.0.0` instead of an exact
/// build. The returned value is owned and may be customized before client
/// creation.
#[must_use]
pub fn v154_windows_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Brave";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.0.0", "Brave";v="154.0.0.0", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
    ])
}

/// Returns navigation request fields observed from Brave 154.1.96.59 on Windows 11.
///
/// Brave sends the fields of [`chromium::v154_windows_navigation_template`]
/// in the same order on HTTP/1.1, HTTP/2, and HTTP/3, with three
/// differences in the retained captures:
///
/// - `Accept` omits `application/signed-exchange;v=b3;q=0.7`.
/// - `Sec-GPC: 1` follows `Accept`, on every request, to potentially
///   trustworthy and plaintext origins alike.
/// - `Accept-Language` is a required caller slot. Brave draws the `q` value
///   of its second language per browser session: across the retained runs it
///   sent `en-US,en;q=` followed by each of `0.5`, `0.6`, `0.7`, `0.8`, and
///   `0.9`, one value per run. No single literal matches Brave, so the caller
///   chooses one and keeps it for the session.
///
/// `User-Agent` is a required caller slot for the reason given for
/// [`crate::edge::v153_windows_navigation_template`]: every retained Brave
/// capture ran headless and sent `HeadlessChrome`. The brand-bearing client
/// hints come from [`v154_windows_client_hints`]. The retained proxy route
/// captures show the Chromium change for a URL that is not potentially
/// trustworthy: to `origin.phantom.test` Brave sends no `Sec-Fetch-*` field,
/// no client hint, and `Accept-Encoding: gzip, deflate`, and still sends
/// `Sec-GPC`.
#[must_use]
pub fn v154_windows_navigation_template() -> RequestTemplate {
    with_brave_fields(
        chromium::v154_navigation_template(None),
        Some(V154_NAVIGATION_ACCEPT),
    )
}

/// Returns same-origin no-store `fetch` request fields observed from Brave
/// 154.1.96.59 on Windows 11.
///
/// The order and values match [`chromium::v154_windows_fetch_no_store_template`]
/// on HTTP/1.1 and HTTP/2, including the HTTP/2 HEADERS priority weight 220,
/// except that `Sec-GPC: 1` follows `Accept` and `User-Agent` and
/// `Accept-Language` are required caller slots, for the reasons given in
/// [`v154_windows_navigation_template`]. No capture backs this request kind on
/// HTTP/3, and none shows where hints requested through `Accept-CH` go on a
/// fetch.
#[must_use]
pub fn v154_windows_fetch_no_store_template() -> RequestTemplate {
    with_brave_fields(chromium::v154_fetch_no_store_template(None), None)
}

/// Applies Brave's request-field differences to a Chromium template: an
/// optional replacement `Accept` value, `Sec-GPC: 1` after `Accept`, and a
/// required caller `Accept-Language`.
fn with_brave_fields(mut template: RequestTemplate, accept: Option<&str>) -> RequestTemplate {
    let apply = |fields: Vec<RequestField>, gpc: &str| {
        let mut output = Vec::with_capacity(fields.len() + 1);
        for field in fields {
            match field.name() {
                Some(name) if name.eq_ignore_ascii_case("accept") => {
                    let field = match accept {
                        Some(value) => RequestField::literal(name, value),
                        None => field,
                    };
                    output.push(field);
                    output.push(RequestField::literal(gpc, "1"));
                }
                Some(name) if name.eq_ignore_ascii_case("accept-language") => {
                    output.push(RequestField::required_caller(name));
                }
                _ => output.push(field),
            }
        }
        output
    };
    template.http1_fields = apply(template.http1_fields, "Sec-GPC");
    template.http2_fields = apply(template.http2_fields, "sec-gpc");
    template.http3_fields = template.http3_fields.map(|fields| apply(fields, "sec-gpc"));
    template
}

#[cfg(test)]
mod tests;
