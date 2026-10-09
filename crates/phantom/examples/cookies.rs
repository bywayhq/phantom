//! Sends two HTTP/2 GETs to one URL through a client with a cookie jar, so
//! the second request carries the cookies the first response set.
//!
//! This mirrors "Keep cookies between requests" in
//! `docs/guides/cookies.md`. It needs the `cookies` feature:
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
    profile::{ClientProfile, browser::chrome},
};

const DEFAULT_URL: &str = "https://example.com/";

/// Largest body this example reads into memory.
const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args().nth(1).unwrap_or_else(|| DEFAULT_URL.to_owned());

    // The cookie placement puts the jar's `cookie` field where Chrome does.
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_client_hints(chrome::v154_windows_client_hints())
        .with_cookie_placement(chrome::v154_cookie_placement());
    let client = Client::builder(profile).cookies().build()?;
    // Validate the template once and reuse it for both requests.
    let navigation = PreparedRequestTemplate::new(chrome::v154_windows_navigation_template())?;

    for attempt in 1..=2 {
        if let Some(jar) = client.cookie_jar() {
            let has_cookie = jar.request_value(&url)?.is_some();
            println!("{}", cookie_diagnostic(attempt, has_cookie));
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

fn cookie_diagnostic(attempt: usize, has_cookie: bool) -> String {
    format!("request {attempt} sends cookie: {has_cookie}")
}

#[cfg(test)]
mod tests {
    use phantom::CookieJar;

    use super::cookie_diagnostic;

    #[test]
    fn cookie_diagnostics_report_presence_without_names_or_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let jar = CookieJar::default();
        let url = "https://example.test/";
        let has_cookie = jar.request_value(url)?.is_some();
        assert_eq!(
            cookie_diagnostic(1, has_cookie),
            "request 1 sends cookie: false"
        );

        jar.set_cookie(url, "private_session_name=secret_cookie_value; Path=/")?;
        let value = jar.request_value(url)?;
        assert_eq!(
            value.as_deref(),
            Some("private_session_name=secret_cookie_value")
        );
        let diagnostic = cookie_diagnostic(2, value.is_some());
        assert_eq!(diagnostic, "request 2 sends cookie: true");
        for secret in ["private_session_name", "secret_cookie_value"] {
            assert!(!diagnostic.contains(secret));
        }
        Ok(())
    }
}
