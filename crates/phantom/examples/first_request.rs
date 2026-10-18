//! Sends one HTTP/2 request with Chrome 154's Windows connection settings,
//! then reads at most 1 MiB and prints the status and body length.
//! No optional features are needed:
//!
//! ```console
//! cargo run -p phantom-http --example first-request -- https://example.com/
//! ```
//!
//! The URL defaults to `https://example.com/`. The server must speak HTTP/2;
//! the request never falls back to another protocol.

use std::env;

use phantom::{Client, HttpProtocol, profile::browser::chrome};

const DEFAULT_URL: &str = "https://example.com/";

/// Largest body this example reads into memory.
const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args().nth(1).unwrap_or_else(|| DEFAULT_URL.to_owned());

    let client = Client::builder(chrome::v154_windows()).build()?;

    let response = client.get(HttpProtocol::Http2, &url)?.send().await?;
    println!("status: {}", response.status());

    let body = response.into_body().collect_with_limit(BODY_LIMIT).await?;
    println!("body: {} bytes", body.len());
    Ok(())
}
