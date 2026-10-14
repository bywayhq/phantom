use std::time::Duration;

use http::{HeaderMap, HeaderValue, header};
use phantom_net::dns::wire::{DnsWireQuery, DnsWireQueryKind};
use tokio::time::Instant;

use super::{Exchange, response_age, validate_content_encoding, validate_content_type};

#[test]
fn age_overflow_expires_data_and_conflicting_or_malformed_fields_fail()
-> Result<(), Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    assert_eq!(response_age(&headers)?, 0);
    headers.append(header::AGE, HeaderValue::from_static(" 0004 "));
    headers.append(header::AGE, HeaderValue::from_static("4"));
    assert_eq!(response_age(&headers)?, 4);
    headers.append(header::AGE, HeaderValue::from_static("5"));
    assert_eq!(
        response_age(&headers).err().map(|error| error.kind()),
        Some(std::io::ErrorKind::InvalidData)
    );
    for malformed in ["", "-1", "+1", "1,1", "1 1", "x"] {
        headers.insert(header::AGE, HeaderValue::from_static(malformed));
        assert!(response_age(&headers).is_err(), "{malformed}");
    }
    headers.insert(
        header::AGE,
        HeaderValue::from_static("99999999999999999999999999999"),
    );
    assert_eq!(response_age(&headers)?, u64::MAX);
    Ok(())
}

#[test]
fn media_parameters_are_validated_without_accepting_a_list_or_duplicate_type()
-> Result<(), Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    for accepted in [
        "APPLICATION/DNS-MESSAGE",
        " \t application/dns-message \t",
        "application/dns-message; x=token",
        "application/dns-message; x=\"quoted;value\\\"\" ",
    ] {
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(accepted));
        validate_content_type(&headers)?;
    }
    for rejected in [
        "application/json",
        "application/dns-message, application/dns-message",
        "application/dns-message;",
        "application/dns-message; x=",
        "application/dns-message; x=\"unterminated",
        "application/dns-message; x=\"bad\\",
    ] {
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(rejected));
        assert!(validate_content_type(&headers).is_err(), "{rejected}");
    }
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/dns-message"),
    );
    headers.append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/dns-message"),
    );
    assert!(validate_content_type(&headers).is_err());
    headers.remove(header::CONTENT_TYPE);
    assert!(validate_content_type(&headers).is_err());
    for encoding in ["gzip", "identity,gzip", ""] {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
        assert!(validate_content_encoding(&headers).is_err());
    }
    headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static(" IDENTITY "),
    );
    validate_content_encoding(&headers)?;
    Ok(())
}

#[test]
fn lifetime_charges_fractional_exchange_time_and_saturates_age()
-> Result<(), Box<dyn std::error::Error>> {
    let query = DnsWireQuery::new("example.test", DnsWireQueryKind::A, 0, None)?;
    // One matching A answer, encoded independently of the response parser.
    let mut bytes = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    bytes.extend_from_slice(&[7]);
    bytes.extend_from_slice(b"example");
    bytes.extend_from_slice(&[4]);
    bytes.extend_from_slice(b"test");
    bytes.extend_from_slice(&[0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1]);
    bytes.extend_from_slice(&120_u32.to_be_bytes());
    bytes.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
    let started = Instant::now();
    let received = started + Duration::from_millis(750);
    let mut response = Exchange {
        answer: query.parse_response(&bytes)?,
        started,
        received,
        age: 50,
    };
    assert_eq!(
        response.expiry(120).duration_since(received),
        Duration::from_millis(69_250)
    );
    response.age = u64::MAX;
    assert_eq!(response.expiry(120), received);
    Ok(())
}
