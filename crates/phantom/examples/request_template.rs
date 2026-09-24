//! Sends an address-bar navigation and then a same-origin `fetch` GET, each
//! with the request fields Chrome 154 sends, in Chrome's order.
//!
//! This mirrors "Apply a captured request template" in `docs/guides/profiles.md`.
//! It needs no feature:
//!
//! ```console
//! cargo run -p phantom-http --example request-template -- https://example.com/ /data.json
//! ```
//!
//! The first argument is the page URL (default `https://example.com/`). The
//! second is a same-origin path to fetch from that page (default: the page URL).

use std::env;

use phantom::{
    Client, HttpProtocol, PreparedRequestTemplate, RequestHeader,
    profile::{ClientProfile, chromium},
};
use url::Url;

const DEFAULT_URL: &str = "https://example.com/";

/// Largest page body this example reads into memory.
const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let page_url = args.next().unwrap_or_else(|| DEFAULT_URL.to_owned());
    let page_url = Url::parse(&page_url)?;
    let fetch_url = match args.next() {
        Some(target) => page_url.join(&target)?,
        None => page_url.clone(),
    };

    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;
    // Prepare each template once and reuse it for every request.
    let navigation = PreparedRequestTemplate::new(chromium::v154_windows_navigation_template())?;
    let fetch = PreparedRequestTemplate::new(chromium::v154_windows_fetch_no_store_template())?;

    let page = client
        .get(HttpProtocol::Http2, page_url.as_str())?
        .template(&navigation)
        .send()
        .await?;
    println!("navigation {page_url}: {}", page.status());
    let body = page.into_body().collect_with_limit(BODY_LIMIT).await?;
    println!("navigation body: {} bytes", body.len());

    // `Referer` is a caller slot in the fetch template: its value is the page URL.
    let data = client
        .get(HttpProtocol::Http2, fetch_url.as_str())?
        .template(&fetch)
        .header(RequestHeader::new("referer", page_url.as_str()))
        .send()
        .await?;
    println!("fetch {fetch_url}: {}", data.status());
    Ok(())
}
