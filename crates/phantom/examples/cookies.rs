//! Sends two HTTP/2 GETs to one URL through a client with a cookie jar, so
//! the second request carries the cookies the first response set.
//!
//! This mirrors "Keep cookies between requests" in
//! `docs/guides/connections-and-state.md`. It needs the `cookies` feature:
//!
//! ```console
//! cargo run -p phantom-http --example cookies --features cookies -- https://example.com/
//! ```
//!
//! The URL defaults to `https://example.com/`. Use a URL whose response sets a
//! cookie to see the jar fill.

use std::env;

use phantom::{
    Client, HttpProtocol, PreparedRequestTemplate,
    profile::{ClientProfile, chromium},
};

const DEFAULT_URL: &str = "https://example.com/";

/// Largest body this example reads into memory.
const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args().nth(1).unwrap_or_else(|| DEFAULT_URL.to_owned());

    // The cookie placement puts the jar's `cookie` field where Chrome does.
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints())
        .with_cookie_placement(chromium::v154_cookie_placement());
    let client = Client::builder(profile).cookies().build()?;
    // Validate the template once and reuse it for both requests.
    let navigation = PreparedRequestTemplate::new(chromium::v154_windows_navigation_template())?;

    for attempt in 1..=2 {
        if let Some(jar) = client.cookie_jar() {
            let sent = jar.request_value(&url)?.unwrap_or_default();
            println!("request {attempt} sends cookie: {sent:?}");
        }

        // Stores every `Set-Cookie` from the response in the shared jar.
        let response = client
            .get(HttpProtocol::Http2, &url)?
            .template(&navigation)
            .send()
            .await?;
        println!("request {attempt}: {}", response.status());
        response.into_body().collect_with_limit(BODY_LIMIT).await?;
    }

    if let Some(jar) = client.cookie_jar() {
        println!("jar holds {} cookies", jar.len());
    }
    Ok(())
}
