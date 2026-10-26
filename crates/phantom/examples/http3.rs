//! Sends one exact HTTP/3 GET with Chrome 154's QUIC transport parameters,
//! HTTP/3 settings, and H3 TLS handshake.
//!
//! This example needs no feature:
//!
//! ```console
//! cargo run -p phantom-http --example http3 -- https://example.com/
//! ```
//!
//! The URL defaults to `https://example.com/`. The server must accept QUIC on
//! UDP at the URL's port; the request never falls back to HTTP/2 or HTTP/1.1.

use std::env;

use phantom::{Client, HttpProtocol, ResponseInfo, profile::browser::chrome};

const DEFAULT_URL: &str = "https://example.com/";

/// Largest body this example reads into memory.
const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args().nth(1).unwrap_or_else(|| DEFAULT_URL.to_owned());

    let profile =
        chrome::v154_windows().with_request_template(chrome::v154_windows_navigation_template());
    let client = Client::builder(profile).build()?;

    let response = client.get(HttpProtocol::Http3, &url)?.send().await?;
    println!("status: {}", response.status());
    if let Some(info) = response.extensions().get::<ResponseInfo>() {
        println!("protocol: {:?}", info.protocol());
    }

    let body = response.into_body().collect_with_limit(BODY_LIMIT).await?;
    println!("body: {} bytes", body.len());
    Ok(())
}
