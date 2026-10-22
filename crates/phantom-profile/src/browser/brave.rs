//! Brave connection settings and request templates.
//!
//! Brave 154 uses Chromium connection settings with Brave TLS offers, client
//! hints and request fields. Use a separate client per top-level site to
//! isolate caches and connections as Brave does.
//!
//! Android recipes target Brave 1.95.104. Android TCP, HTTP/1.1 pool,
//! address-cache, proxy CONNECT and cookie-placement recipes are unavailable.

pub use crate::catalog::browser_profiles::brave::*;

mod android;

pub use android::{
    v153_android_client_hints, v153_android_fetch_no_store_template, v153_android_http2,
    v153_android_http3, v153_android_http3_request, v153_android_navigation_template,
    v153_android_quic, v153_android_quic_tls, v153_android_tcp_tls, v153_android_websocket,
};

use crate::{
    browser::chrome,
    client_hints::ClientHintSettings,
    request_template::{RequestField, RequestTemplate},
    tls::TlsSettings,
};

/// Brave's navigation `Accept` value: Chrome's without the
/// `application/signed-exchange` entry.
pub(crate) const V154_NAVIGATION_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,\
image/avif,image/webp,image/apng,*/*;q=0.8";

/// Returns Brave 154.1.96.59 TLS settings for Windows 11.
///
/// Uses [`chrome::v154_tcp_tls`] without trust-anchor IDs. Keeps its
/// HTTPS-record ECH and session-ticket policies.
#[must_use]
pub fn v154_tcp_tls() -> TlsSettings {
    crate::tls::components::brave_154_tcp_tls()
}

/// Returns Brave 154.1.96.59 TLS settings for HTTP/3.
///
/// Uses [`chrome::v154_quic_tls`] without trust-anchor IDs, including its
/// HTTPS-record ECH and session-ticket policies.
#[must_use]
pub fn v154_quic_tls() -> TlsSettings {
    crate::tls::components::brave_154_quic_tls()
}

/// Returns Brave 154 client hints for Windows 11 x64.
///
/// Uses Chromium field order with Brave's brand list and reduced full
/// versions. Omits `sec-ch-ua-full-version` and `sec-ch-ua-form-factors`.
#[must_use]
pub fn v154_windows_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::brave_windows_154_client_hints()
}

/// Returns Brave 154.1.96.59 navigation fields for Windows 11.
///
/// Uses [`chrome::v154_windows_navigation_template`]'s ordering, omits signed
/// exchanges from `Accept`, and puts `Sec-GPC: 1` after `Accept` on all URLs.
/// Supply `User-Agent` and `Accept-Language`. To follow Brave's session
/// language policy, choose a secondary-language quality from 0.5 through 0.9
/// and keep it for the session.
#[must_use]
pub fn v154_windows_navigation_template() -> RequestTemplate {
    with_brave_fields(
        chrome::v154_navigation_template(None),
        Some(V154_NAVIGATION_ACCEPT),
    )
}

/// Returns Brave 154.1.96.59 same-origin no-store GET fields for Windows 11.
///
/// Uses [`chrome::v154_windows_fetch_no_store_template`]'s ordering and
/// HTTP/2 weight 220, with `Sec-GPC: 1` after `Accept`. Supply `User-Agent`
/// and `Accept-Language`. HTTP/3 and requested client hints are unavailable.
#[must_use]
pub fn v154_windows_fetch_no_store_template() -> RequestTemplate {
    with_brave_fields(chrome::v154_fetch_no_store_template(None), None)
}

/// Adds Brave's optional `Accept` override, `Sec-GPC: 1` after `Accept`,
/// and a required `Accept-Language` slot.
///
/// On navigation restarts, `Sec-GPC` follows newly added client hints.
/// Brave appends it in `BraveProxyingURLLoaderFactory`'s start-transaction
/// callback (`browser/net/brave_request_handler_impl.cc` at `v1.96.59`).
pub(crate) fn with_brave_fields(
    mut template: RequestTemplate,
    accept: Option<&str>,
) -> RequestTemplate {
    let apply = |fields: Vec<RequestField>, gpc: &str| {
        let mut output = Vec::with_capacity(fields.len() + 1);
        let mut gpc_due = false;
        for field in fields {
            if gpc_due && field != RequestField::RestartClientHints {
                output.push(RequestField::literal(gpc, "1"));
                gpc_due = false;
            }
            match field.name() {
                Some(name) if name.eq_ignore_ascii_case("accept") => {
                    let field = match accept {
                        Some(value) => RequestField::literal(name, value),
                        None => field,
                    };
                    output.push(field);
                    gpc_due = true;
                }
                Some(name) if name.eq_ignore_ascii_case("accept-language") => {
                    output.push(RequestField::required_caller(name));
                }
                _ => output.push(field),
            }
        }
        if gpc_due {
            output.push(RequestField::literal(gpc, "1"));
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
