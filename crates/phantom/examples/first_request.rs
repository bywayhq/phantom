//! Sends one HTTP/2 GET with Chrome 154's TLS handshake, HTTP/2 settings, and
//! client hints, then prints the status, the response metadata, and the body
//! length.
//!
//! This is the program from `docs/getting-started.md`. It needs no feature:
//!
//! ```console
//! cargo run -p phantom-http --example first-request -- https://example.com/
//! ```
//!
//! The URL defaults to `https://example.com/`. The server must speak HTTP/2;
//! the request never falls back to another protocol.

use std::env;

use phantom::{
    Client, HttpProtocol, RequestHeader, ResponseInfo,
    profile::{ClientProfile, chromium},
};

const DEFAULT_URL: &str = "https://example.com/";

/// Largest body this example reads into memory.
const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args().nth(1).unwrap_or_else(|| DEFAULT_URL.to_owned());

    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;

    let response = client
        .get(HttpProtocol::Http2, &url)?
        .header(RequestHeader::new("accept", "*/*"))
        .send()
        .await?;
    println!("status: {}", response.status());

    if let Some(info) = response.extensions().get::<ResponseInfo>() {
        println!("protocol: {:?}", info.protocol());
        println!("effective URI: {}", info.effective_uri());
        println!("redirects followed: {}", info.redirects_followed());
    }

    let body = response.into_body().collect_with_limit(BODY_LIMIT).await?;
    println!("body: {} bytes", body.len());
    Ok(())
}
