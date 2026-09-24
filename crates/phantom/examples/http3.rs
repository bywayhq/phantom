//! Sends one exact HTTP/3 GET with Chrome 154's QUIC transport parameters,
//! HTTP/3 settings, and H3 TLS handshake.
//!
//! This mirrors "Send a request over HTTP/3" in `docs/guides/http3.md`. It
//! needs no feature:
//!
//! ```console
//! cargo run -p phantom-http --example http3 -- https://example.com/
//! ```
//!
//! The URL defaults to `https://example.com/`. The server must accept QUIC on
//! UDP at the URL's port; the request never falls back to HTTP/2 or HTTP/1.1.

use std::env;

use phantom::{
    Client, HttpProtocol, PreparedRequestTemplate, ResponseInfo,
    profile::{ClientProfile, Http3ClientSettings, chromium},
};

const DEFAULT_URL: &str = "https://example.com/";

/// Largest body this example reads into memory.
const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args().nth(1).unwrap_or_else(|| DEFAULT_URL.to_owned());

    let http3 = Http3ClientSettings::new(
        chromium::v154_http3_tls(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        chromium::v154_http3_request(),
    );
    // The TLS recipe passed to `new` applies only to TCP connections; H3 uses
    // the TLS recipe inside `http3`.
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http3(http3)
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;
    let navigation = PreparedRequestTemplate::new(chromium::v154_windows_navigation_template())?;

    let response = client
        .get(HttpProtocol::Http3, &url)?
        .template(&navigation)
        .send()
        .await?;
    println!("status: {}", response.status());
    if let Some(info) = response.extensions().get::<ResponseInfo>() {
        println!("protocol: {:?}", info.protocol());
    }

    let body = response.into_body().collect_with_limit(BODY_LIMIT).await?;
    println!("body: {} bytes", body.len());
    Ok(())
}
