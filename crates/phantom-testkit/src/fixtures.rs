//! Retained browser observations available without a repository checkout.
//!
//! These documents keep their original formats and metadata. Inspect a format
//! before parsing it: navigation summaries are not raw HTTP request heads.
//! Exact browser builds and source hashes are listed in the package's fixture
//! provenance documents. A capture establishes only its recorded fields.

/// Chrome 154.0.8037.97 on Windows 11: first and Accept-CH follow-up
/// navigation field order and client-hint values, over HTTP/1.1.
///
/// Format: `phantom-client-hints-v2`. Three headless runs. This document does
/// not retain a raw request head or establish HTTP/2 or HTTP/3 ordering.
pub const CHROME_154_WINDOWS_NAVIGATION: &str =
    include_str!("../fixtures/client-hints/chrome-154-windows-navigation.txt");

/// Chrome 154.0.8037.58 on Windows 11: ordered HTTP/1 request heads for
/// a page, WebSocket opening, and result report across three headless runs.
///
/// Parse with [`crate::http1::expectation::RequestExpectation::from_retained`].
pub const CHROME_154_WINDOWS_HTTP1_ACCEPT: &str =
    include_str!("../fixtures/http1/chrome-154-windows-h1-accept.txt");

/// Firefox 157.0 on Windows 11: ordered HTTP/1 request heads for a page,
/// WebSocket opening, and result report across three headless runs.
///
/// Parse with [`crate::http1::expectation::RequestExpectation::from_retained`].
pub const FIREFOX_157_WINDOWS_HTTP1_ACCEPT: &str =
    include_str!("../fixtures/http1/firefox-157-windows-h1-accept.txt");
