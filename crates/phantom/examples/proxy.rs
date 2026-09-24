//! Sends one HTTP/2 GET through an HTTP or SOCKS5 proxy.
//!
//! This mirrors "Routes and proxies" in `docs/guides/routes-and-proxies.md`.
//! It needs no feature:
//!
//! ```console
//! cargo run -p phantom-http --example proxy -- socks5h://127.0.0.1:1080 https://example.com/
//! ```
//!
//! The first argument is the proxy URI; without it, the example reads
//! `PHANTOM_EXAMPLE_PROXY`. A `socks5://` or `socks5h://` URI selects a SOCKS5
//! proxy; any other URI is parsed as an HTTP proxy, which tunnels the request
//! with CONNECT. Phantom never reads the system proxy settings, and a failed
//! proxy fails the request instead of connecting directly.

use std::{env, process};

use phantom::{
    Client, HttpProtocol, HttpProxy, PreparedRequestTemplate, Route, Socks5Proxy,
    profile::{ClientProfile, chromium},
};

const PROXY_VARIABLE: &str = "PHANTOM_EXAMPLE_PROXY";
const DEFAULT_URL: &str = "https://example.com/";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let Some(proxy) = args.next().or_else(|| env::var(PROXY_VARIABLE).ok()) else {
        eprintln!("usage: proxy <proxy-uri> [url]");
        eprintln!("   or: {PROXY_VARIABLE}=<proxy-uri> proxy");
        eprintln!("example: socks5h://127.0.0.1:1080");
        process::exit(2);
    };
    let url = args.next().unwrap_or_else(|| DEFAULT_URL.to_owned());

    let route = if proxy.starts_with("socks5://") || proxy.starts_with("socks5h://") {
        Route::socks5(Socks5Proxy::new(&proxy)?)
    } else {
        Route::http_proxy(HttpProxy::new(&proxy)?)
    };

    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).route(route).build()?;
    let navigation = PreparedRequestTemplate::new(chromium::v154_windows_navigation_template())?;

    let response = client
        .get(HttpProtocol::Http2, &url)?
        .template(&navigation)
        .send()
        .await?;
    println!("{}", response.status());
    Ok(())
}
