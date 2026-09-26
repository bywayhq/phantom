//! Wire settings retained from Opera for Android observations.
//!
//! Opera 102.1.5206.90382, built on Chromium 152.0.7977.82, as the Google
//! Play Store served it to the `phantom-api35-play` Android 15 emulator.
//! Opera for Android reads no command-line file, so no capture can map a test
//! name, trust a test certificate, force QUIC, or route through a proxy: it
//! reaches only the device's own loopback. The retained captures therefore
//! cover the TCP ClientHello, sent to `https://localhost`, and client hints
//! and plaintext HTTP/1.1 requests to `http://127.0.0.1`. Only the TLS and
//! client-hint layers have recipes here. With no HTTP/2 or HTTP/3 capture,
//! there are no request templates, and no H2, QUIC, H3, or WebSocket recipe.
//!
//! There is no TCP, HTTP/1.1 connection, address-cache, proxy CONNECT, or
//! cookie-placement recipe, for the reasons given in [`crate::opera`] and
//! [`crate::chrome_android`].

use crate::{
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    opera,
    tls::TlsSettings,
};

/// Returns TLS settings captured from Opera 102.1.5206.90382 for Android.
///
/// Every fresh-process ClientHello of the retained capture equals the desktop
/// Opera ClientHello of [`opera::v135_tls`] except in one field: Opera for
/// Android puts a GREASE value at the head of `signature_algorithms`, as
/// Chrome does, so this sets [`TlsSettings::grease_signature_algorithms`]
/// again. The result is [`crate::chromium::v154_tls`] without trust-anchor
/// IDs. The captures reached `localhost`, the only name Opera could resolve
/// to the listener, and a ClientHello to another name differs only in its
/// server name. [`TlsSettings::ech_from_https_records`] stays unset.
#[must_use]
pub fn v102_tls() -> TlsSettings {
    let mut settings = opera::v135_tls();
    settings.grease_signature_algorithms = true;
    settings
}

/// Returns client-hint fields observed from Opera 102.1.5206.90382 for
/// Android.
///
/// From the retained navigation capture, three fresh-profile runs that agree.
/// Names, order, and delivery equal the Chromium client-hint recipes. The
/// values carry Opera's four-brand list, which names `OperaMobile`, `Opera`
/// 137, and Chromium 152 and puts the greased brand last, `?1`, the
/// `"Android"` platform at version `"15"` (Opera sends no minor versions),
/// and an empty `sec-ch-ua-form-factors`.
///
/// `sec-ch-ua-model` is the `model` argument, for the reason given for
/// [`crate::chrome_android::v153_android_client_hints`]: the captured value
/// names the emulator, so the recipe sends no default model.
#[must_use]
pub fn v102_android_client_hints(model: &str) -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""OperaMobile";v="102", "Opera";v="137", "Chromium";v="152", " Not A;Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?1", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""102.1.5206.90382""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Android""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15""#, AcceptCh),
        ClientHint::new(
            "sec-ch-ua-model",
            crate::chrome_android::model_value(model),
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-bitness", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""OperaMobile";v="102.1.5206.90382", "Opera";v="137.0.6010.1", "Chromium";v="152.0.7977.82", " Not A;Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", "", AcceptCh),
    ])
}

#[cfg(test)]
mod tests;
