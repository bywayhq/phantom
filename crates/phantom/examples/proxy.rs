//! Sends one HTTPS GET through an HTTP or SOCKS5 proxy and reads its response.
//!
//! See the proxy guide at `phantom::guide::proxies`. No feature is needed:
//!
//! ```console
//! cargo run -p phantom-http --example proxy -- socks5h://127.0.0.1:1080 https://example.com/
//! ```
//!
//! The first argument is the proxy URI; without it, the example reads
//! `PHANTOM_EXAMPLE_PROXY`. A `socks5://` or `socks5h://` URI selects a SOCKS5
//! proxy; any other URI is parsed as an HTTP proxy, which tunnels HTTPS
//! requests with CONNECT. Use a proxy URL without credentials. This example does not
//! enable environment proxy routing; a failed proxy fails the request instead
//! of connecting directly.

use std::{env, process};

use phantom::{
    Client, ContentDecoding, HttpProxy, Route, Socks5Proxy, profile::browser::chrome, response_text,
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

    let profile =
        chrome::v154_windows().with_request_template(chrome::v154_windows_navigation_template());
    let client = Client::builder(profile).route(route).build()?;

    let response = client
        .get_negotiated(&url)?
        .content_decoding(ContentDecoding::advertised(1 << 20))
        .send()
        .await?;
    let response = response_text(response, 1 << 20).await?;
    println!("{}\n{}", response.status(), response.body());
    Ok(())
}
