//! Sends an address-bar navigation and then a same-origin `fetch` GET, each
//! with the request fields Chrome 154 sends, in Chrome's order.
//!
//! This mirrors "Apply a captured request template" in
//! `docs/guides/request-templates.md`.
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
    Client, HttpProtocol, PreparedRequestTemplate, RequestHeader, StatusCode,
    profile::{ClientProfile, browser::chrome},
};
use url::Url;

const DEFAULT_URL: &str = "https://example.com/";

/// Largest page body this example reads into memory.
const BODY_LIMIT: usize = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let page_url = args.next().unwrap_or_else(|| DEFAULT_URL.to_owned());
    let target = args.next();
    let (page_url, fetch_url) = request_urls(&page_url, target.as_deref())?;

    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_client_hints(chrome::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;
    // Prepare each template once and reuse it for every request.
    let navigation = PreparedRequestTemplate::new(chrome::v154_windows_navigation_template())?;
    let fetch = PreparedRequestTemplate::new(chrome::v154_windows_fetch_no_store_template())?;

    let page = client
        .get(HttpProtocol::Http2, page_url.as_str())?
        .template(&navigation)
        .send()
        .await?;
    println!(
        "{}",
        request_diagnostic("navigation", &page_url, page.status())
    );
    let body = page.into_body().collect_with_limit(BODY_LIMIT).await?;
    println!("navigation body: {} bytes", body.len());

    // `Referer` is a caller slot in the fetch template: its value is the page URL.
    let data = client
        .get(HttpProtocol::Http2, fetch_url.as_str())?
        .template(&fetch)
        .header(RequestHeader::new("referer", page_url.as_str()))
        .send()
        .await?;
    println!("{}", request_diagnostic("fetch", &fetch_url, data.status()));
    Ok(())
}

fn request_urls(
    page: &str,
    target: Option<&str>,
) -> Result<(Url, Url), Box<dyn std::error::Error>> {
    let page = Url::parse(page)?;
    let fetch = match target {
        Some(target) => page.join(target)?,
        None => page.clone(),
    };

    if page.origin() != fetch.origin() {
        return Err("fetch URL must have the same origin as the page URL".into());
    }
    Ok((page, fetch))
}

fn request_diagnostic(operation: &str, url: &Url, status: StatusCode) -> String {
    format!(
        "{operation} {}: {status}",
        url.origin().ascii_serialization()
    )
}

#[cfg(test)]
mod tests {
    use phantom::StatusCode;
    use url::Url;

    use super::{request_diagnostic, request_urls};

    #[test]
    fn relative_and_same_origin_targets_keep_their_paths_and_queries()
    -> Result<(), Box<dyn std::error::Error>> {
        let page = "https://example.test/pages/home?session=page_secret";
        for (target, expected) in [
            (None, page),
            (
                Some("data.json?key=fetch_secret"),
                "https://example.test/pages/data.json?key=fetch_secret",
            ),
            (
                Some("/data.json?key=fetch_secret"),
                "https://example.test/data.json?key=fetch_secret",
            ),
            (
                Some("https://example.test/data.json"),
                "https://example.test/data.json",
            ),
            (
                Some("https://EXAMPLE.test:443/data.json"),
                "https://example.test/data.json",
            ),
            (
                Some("//example.test/data.json"),
                "https://example.test/data.json",
            ),
        ] {
            let (actual_page, fetch) = request_urls(page, target)?;
            assert_eq!(actual_page.as_str(), page);
            assert_eq!(fetch.as_str(), expected);
        }
        Ok(())
    }

    #[test]
    fn fetches_to_another_scheme_host_or_port_are_rejected() {
        for target in [
            "http://example.test/data.json",
            "https://other.test/data.json",
            "https://example.test:8443/data.json",
            "//other.test/data.json",
            "//example.test:8443/data.json",
            "https://other.test/private_path?token=private_query",
        ] {
            let error = request_urls("https://example.test/", Some(target))
                .expect_err("accepted a target outside the page origin");
            assert_eq!(
                error.to_string(),
                "fetch URL must have the same origin as the page URL"
            );
        }
    }

    #[test]
    fn request_diagnostics_keep_only_the_operation_origin_and_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let url = Url::parse("https://example.test:8443/private_path?token=private_query")?;
        for operation in ["navigation", "fetch"] {
            let diagnostic = request_diagnostic(operation, &url, StatusCode::OK);
            assert_eq!(
                diagnostic,
                format!("{operation} https://example.test:8443: 200 OK")
            );
            for secret in ["private_path", "private_query", "token"] {
                assert!(!diagnostic.contains(secret));
            }
        }
        assert_eq!(
            url.as_str(),
            "https://example.test:8443/private_path?token=private_query"
        );
        Ok(())
    }
}
