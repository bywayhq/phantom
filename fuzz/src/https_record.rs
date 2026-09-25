//! HTTPS DNS record extraction and RDATA parsing.
//!
//! The harness drives `phantom_net::dns::https_answers_from_message`, which
//! decodes a DNS response with hickory's message parser and then runs the
//! function `HttpsRecordResolver::lookup` runs on a resolver's answer
//! section: the CNAME-chain owner check, hickory's RDATA re-encoding, and
//! `HttpsRecord::from_rdata`. It also feeds the raw input to
//! `HttpsRecord::from_rdata` alone, the parser a caller's
//! `HttpsRecordResolver::from_fn` lookup uses.
//!
//! Every record that parses must satisfy the RFC 9460 rules the parser
//! promises, and every answer of one lookup must share one owner, the end of
//! the query's CNAME chain. The facade's selection of `h3` from these
//! records, and its TTL cap, are private to `phantom` and not reached here;
//! neither is the resolver's own response handling (ID and question
//! matching, truncation retry, and follow-up queries).

#[cfg(test)]
mod tests;

use phantom_net::dns::{
    HttpsLookupError, HttpsRecord, HttpsRecordLookup, ServiceRecord, TargetName,
};

use crate::seed;

/// The origin every response answers.
pub const HOST: &str = "origin.example.test";

/// `mandatory` through `ipv6hint` (RFC 9460 section 14.3.2).
const KEY_MANDATORY: u16 = 0;
const KEY_ALPN: u16 = 1;
const KEY_NO_DEFAULT_ALPN: u16 = 2;
const KEY_PORT: u16 = 3;
const KEY_IPV4_HINT: u16 = 4;
const KEY_ECH: u16 = 5;
const KEY_IPV6_HINT: u16 = 6;
/// The reserved "Invalid key" (RFC 9460 section 14.3.3).
const KEY_INVALID: u16 = 65535;

/// A response to an HTTPS query for [`HOST`] with ID 1: a CNAME from the
/// question name to `cdn.example.test`, then two ServiceMode records and one
/// AliasMode record there. The CNAME owner is a compression pointer to the
/// question, and the HTTPS owners point into the CNAME's RDATA, so hickory's
/// pointer handling is on the path.
#[rustfmt::skip]
pub const RESPONSE: &[u8] = &[
    // Header: ID 1, response with RD and RA, one question, four answers.
    0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    // Question at offset 12: origin.example.test HTTPS IN.
    6, b'o', b'r', b'i', b'g', b'i', b'n', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    4, b't', b'e', b's', b't', 0, 0x00, 0x41, 0x00, 0x01,
    // CNAME at the question name, TTL 300, to cdn.example.test (offset 49).
    0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x06,
    3, b'c', b'd', b'n', 0xC0, 0x13,
    // HTTPS at cdn.example.test, TTL 60: priority 1, target ".", every
    // interpreted key and one unknown key.
    0xC0, 0x31, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x53,
    0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x03,
    0x00, 0x01, 0x00, 0x06, 2, b'h', b'3', 2, b'h', b'2',
    0x00, 0x02, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x02, 0x01, 0xBB,
    0x00, 0x04, 0x00, 0x08, 192, 0, 2, 1, 192, 0, 2, 2,
    0x00, 0x05, 0x00, 0x0A, 0x00, 0x08, 0xFE, 0x0D, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
    0x00, 0x06, 0x00, 0x10, 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    0x00, 0x07, 0x00, 0x02, 0x09, 0x09,
    // HTTPS at cdn.example.test, TTL 60: priority 2, target
    // svc.example.net, alpn h3.
    0xC0, 0x31, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x1A,
    0x00, 0x02, 3, b's', b'v', b'c', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    3, b'n', b'e', b't', 0,
    0x00, 0x01, 0x00, 0x03, 2, b'h', b'3',
    // HTTPS at cdn.example.test, TTL 60: AliasMode to pool.example.net.
    0xC0, 0x31, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x14,
    0x00, 0x00, 4, b'p', b'o', b'o', b'l', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    3, b'n', b'e', b't', 0,
];

/// Extracts the HTTPS answers of `message` for [`HOST`] on port 443 and
/// checks every invariant a successful extraction promises.
pub fn drive(message: &[u8]) -> Result<HttpsRecordLookup, HttpsLookupError> {
    let lookup = phantom_net::dns::https_answers_from_message(HOST, 443, message)?;
    let answers = lookup.answers();
    if let Some(first) = answers.first() {
        assert!(
            answers
                .iter()
                .all(|answer| answer.owner().eq_ignore_ascii_case(first.owner())),
            "HTTPS answers of one lookup have different owners"
        );
    }
    for answer in answers {
        check_record(answer.record());
    }
    Ok(lookup)
}

/// Asserts the RFC 9460 rules `HttpsRecord::from_rdata` promises of a record
/// it accepted.
pub fn check_record(record: &HttpsRecord) {
    check_target(record.target());
    match record {
        HttpsRecord::Alias(_) => assert_eq!(record.priority(), 0),
        HttpsRecord::Service(service) => check_service(service),
    }
}

fn check_target(target: &TargetName) {
    let TargetName::Name(name) = target else {
        return;
    };
    // 255 wire bytes, less the root label and the first length octet.
    assert!(name.len() <= 253, "target name longer than 253 characters");
    for label in name.split('.') {
        assert!(
            (1..=63).contains(&label.len()),
            "target label of {} bytes",
            label.len()
        );
        assert!(
            label.bytes().all(|byte| byte.is_ascii_graphic()),
            "target label with a byte that is not printable ASCII"
        );
    }
}

fn check_service(service: &ServiceRecord) {
    assert_ne!(service.priority().get(), 0);
    assert!(
        service
            .alpn()
            .iter()
            .all(|id| (1..=255).contains(&id.len())),
        "alpn identifier outside 1..=255 bytes"
    );
    assert!(service.ech().is_none_or(|ech| !ech.as_bytes().is_empty()));
    let other = service.other_params();
    assert!(
        other.windows(2).all(|pair| pair[0].key() < pair[1].key()),
        "uninterpreted keys are not strictly increasing"
    );
    assert!(
        other
            .iter()
            .all(|param| param.key() > KEY_IPV6_HINT && param.key() != KEY_INVALID),
        "an interpreted or reserved key was kept uninterpreted"
    );
    let mandatory = service.mandatory();
    assert!(
        mandatory.windows(2).all(|pair| pair[0] < pair[1]),
        "mandatory keys are not strictly increasing"
    );
    for &key in mandatory {
        let present = match key {
            KEY_MANDATORY => false,
            KEY_ALPN => !service.alpn().is_empty(),
            KEY_NO_DEFAULT_ALPN => service.no_default_alpn(),
            KEY_PORT => service.port().is_some(),
            KEY_IPV4_HINT => !service.ipv4_hint().is_empty(),
            KEY_ECH => service.ech().is_some(),
            KEY_IPV6_HINT => !service.ipv6_hint().is_empty(),
            _ => other.iter().any(|param| param.key() == key),
        };
        assert!(present, "mandatory key {key} is absent");
    }
}

/// Drives the raw input as RDATA and as a message, then the perturbed seed
/// response.
pub fn exercise(input: &[u8]) {
    if let Ok(record) = HttpsRecord::from_rdata(input) {
        check_record(&record);
    }
    let _ = drive(input);
    let _ = drive(&seed::perturb(RESPONSE, input));
}
