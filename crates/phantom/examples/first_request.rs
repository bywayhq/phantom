//! Sends one request with Chrome 156's Windows connection settings,
//! then reads at most 1 MiB and prints the status and body length.
//! No optional features are needed:
//!
//! ```console
//! cargo run -p phantom-http --example first-request -- https://example.com/
//! ```
//!
//! The URL defaults to `https://example.com/`. TLS negotiates HTTP/1.1 or HTTP/2.

use std::env;

use phantom::{
    Client,
    profile::catalog::{RequestTemplateKind, profile_for},
};

const DEFAULT_URL: &str = "https://example.com/";

/// Largest body this example reads into memory.
const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args().nth(1).unwrap_or_else(|| DEFAULT_URL.to_owned());

    let profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    let client = Client::builder(profile).build()?;

    let response = client.get(&url)?.send().await?;
    println!("status: {}", response.status());

    let body = response.into_body().collect_with_limit(BODY_LIMIT).await?;
    println!("body: {} bytes", body.len());
    Ok(())
}
