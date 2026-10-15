//! Stored HTTP/2 values copied before component generation replaced literals.
//!
//! The controls below preserve factories at
//! 6f41054adce04a2a50ef8f1592490b365cd6bb71 independently of declarations.

use phantom_profile::{
    Http2CookieCrumbs, Http2FieldIndexing, Http2HpackSettings, Http2HuffmanCoding,
    Http2IdleTimeout, Http2IndexingLimit, Http2NameReference, Http2Priority, Http2PseudoHeader,
    Http2SensitiveProxyAuthorization, Http2Setting, Http2Settings, Http2StaticNameIndex,
    Http2StreamSettings, Http2TableSizeUpdates, Http2UnindexedMatch, browser,
};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn browser_http2_factories_preserve_every_stored_field() -> TestResult {
    let chromium = chromium_settings();
    let firefox = firefox_settings();
    chromium.validate()?;
    firefox.validate()?;
    assert_eq!(browser::chrome::v154_http2(), chromium);
    assert_eq!(browser::firefox::v157_http2(), firefox);
    for settings in [
        browser::chrome::v154_android_http2(),
        browser::edge::v153_android_http2(),
        browser::brave::v153_android_http2(),
    ] {
        assert_eq!(settings, chromium);
    }
    Ok(())
}

#[test]
fn composed_recipes_preserve_http2_policies_and_fresh_ownership() -> TestResult {
    for profile in [
        browser::chrome::v154_windows(),
        browser::chrome::v154_android(),
        browser::edge::v154_windows(),
        browser::edge::v153_android(),
        browser::brave::v154_windows(),
        browser::brave::v153_android(),
        browser::opera::v136_windows(),
    ] {
        assert_eq!(
            *profile.http2().ok_or("composed recipe lost HTTP/2")?,
            chromium_settings()
        );
    }
    let firefox = browser::firefox::v157_windows();
    assert_eq!(
        *firefox.http2().ok_or("Firefox recipe lost HTTP/2")?,
        firefox_settings()
    );
    let mut custom = browser::chrome::v154_http2();
    custom.initial_settings.clear();
    custom.hpack.literal_pseudo_headers.reverse();
    assert_eq!(browser::chrome::v154_http2(), chromium_settings());
    let mut custom_firefox = browser::firefox::v157_http2();
    custom_firefox.pseudo_header_order.reverse();
    custom_firefox.streams.first_stream_id = 1;
    assert_eq!(browser::firefox::v157_http2(), firefox_settings());
    Ok(())
}

fn chromium_settings() -> Http2Settings {
    Http2Settings {
        initial_settings: vec![
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(6_291_456),
            Http2Setting::MaxHeaderListSize(262_144),
        ],
        initial_connection_window_size: 15_728_640,
        initial_stream_window_target: None,
        pseudo_header_order: vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Path,
        ],
        extended_connect_pseudo_header_order: Some(vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Protocol,
        ]),
        extended_connect_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 147,
            exclusive: true,
        }),
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 256,
            exclusive: true,
        }),
        hpack: Http2HpackSettings {
            literal_pseudo_headers: vec![Http2PseudoHeader::Method, Http2PseudoHeader::Protocol],
            static_name_index: Http2StaticNameIndex::Lowest,
            huffman_coding: Http2HuffmanCoding::WhenShorter,
            cookie_crumbs: Http2CookieCrumbs::IndexAll,
            field_indexing: Http2FieldIndexing::All,
            name_reference: Http2NameReference::StaticThenNewest,
            unindexed_match: Http2UnindexedMatch::Index,
            indexing_limit: Http2IndexingLimit::Unlimited,
            table_size_updates: Http2TableSizeUpdates::WhenChanged,
            sensitive_proxy_authorization: Http2SensitiveProxyAuthorization::FieldIndexing,
        },
        streams: Http2StreamSettings {
            first_stream_id: 1,
            assumed_max_concurrent_streams: Some(100),
            max_concurrent_streams_cap: Some(256),
        },
        preface_ping_after: Some(Duration::from_secs(10)),
        ping_timeout: Some(Duration::from_secs(10)),
        ping_failure_retries: 2,
        idle_ping_after: None,
        idle_ping_timeout: None,
        idle_timeout: Http2IdleTimeout::Unlimited,
    }
}

fn firefox_settings() -> Http2Settings {
    Http2Settings {
        initial_settings: vec![
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(131_072),
            Http2Setting::MaxFrameSize(16_384),
        ],
        initial_connection_window_size: 12_582_912,
        initial_stream_window_target: Some(12_582_912),
        pseudo_header_order: vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
        ],
        extended_connect_pseudo_header_order: Some(vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Protocol,
        ]),
        extended_connect_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 22,
            exclusive: false,
        }),
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        }),
        hpack: Http2HpackSettings {
            literal_pseudo_headers: Vec::new(),
            static_name_index: Http2StaticNameIndex::Highest,
            huffman_coding: Http2HuffmanCoding::AlwaysIncludingEmpty,
            cookie_crumbs: Http2CookieCrumbs::NeverIndexShort,
            field_indexing: Http2FieldIndexing::NeverIndexAuthorization,
            name_reference: Http2NameReference::OldestDynamic,
            unindexed_match: Http2UnindexedMatch::Literal,
            indexing_limit: Http2IndexingLimit::Half,
            table_size_updates: Http2TableSizeUpdates::EverySetting,
            sensitive_proxy_authorization: Http2SensitiveProxyAuthorization::FieldIndexing,
        },
        streams: Http2StreamSettings {
            first_stream_id: 3,
            assumed_max_concurrent_streams: Some(100),
            max_concurrent_streams_cap: None,
        },
        preface_ping_after: None,
        ping_timeout: None,
        ping_failure_retries: 0,
        idle_ping_after: Some(Duration::from_secs(58)),
        idle_ping_timeout: Some(Duration::from_secs(8)),
        idle_timeout: Http2IdleTimeout::ClosedOnTimer(Duration::from_secs(170)),
    }
}
