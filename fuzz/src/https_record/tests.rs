//! Deterministic regressions for the HTTPS record harness.

use std::error::Error;
use std::time::{Duration, Instant};

use phantom::fuzz_https_selection;
use phantom_net::dns::{
    HttpsLookupErrorKind, HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup, TargetName,
};

use super::{HOST, RESPONSE, SERVICE_RESPONSE, drive, exercise};

const H3: &[u8] = b"\x00\x01\x00\x00\x01\x00\x03\x02h3";
const H2: &[u8] = b"\x00\x01\x00\x00\x01\x00\x03\x02h2";
const H3_A: &[u8] = b"\x00\x02\x00\x00\x01\x00\x03\x02h3\x00\x05\x00\x01A";
const H3_B: &[u8] = b"\x00\x01\x00\x00\x01\x00\x03\x02h3\x00\x05\x00\x01B";
const H3_C: &[u8] = b"\x00\x01\x00\x00\x01\x00\x03\x02h3\x00\x05\x00\x01C";

fn lookup(records: &[&[u8]], ttl: u32) -> Result<HttpsRecordLookup, Box<dyn Error>> {
    let answers = records
        .iter()
        .map(|rdata| {
            HttpsRecord::from_rdata(rdata).map(|record| HttpsRecordAnswer::new(HOST, ttl, record))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(HttpsRecordLookup::new(answers, None))
}

/// The embedded response must keep producing all three records at the end
/// of its CNAME chain. A seed that stopped decoding would leave the fuzz
/// target perturbing a message hickory rejects before any record is read.
#[test]
fn structural_seed_extracts_every_record() {
    let lookup = drive(RESPONSE).expect("the structural seed must decode");
    let answers = lookup.answers();
    assert_eq!(answers.len(), 3);
    assert!(
        answers
            .iter()
            .all(|answer| answer.owner() == "cdn.example.test")
    );
    assert!(answers.iter().all(|answer| answer.ttl() == 60));
    let HttpsRecord::Service(first) = answers[0].record() else {
        panic!("the first seed record must be in ServiceMode");
    };
    assert_eq!(first.mandatory(), [1, 3]);
    assert_eq!(first.port(), Some(443));
    assert_eq!(first.other_params().len(), 1);
    assert_eq!(
        answers[1].record().target(),
        &TargetName::Name("svc.example.net".into())
    );
    assert!(matches!(answers[2].record(), HttpsRecord::Alias(_)));
    assert!(!fuzz_https_selection(&lookup, HOST, 443).advertises_h3);
}

/// A record off the chain's end must make the response unusable rather than
/// hand back a record for another name. The seed's last record keeps its
/// data but its owner pointer moves from `cdn.example.test` to the question
/// name, which is an alias and not the chain's end.
#[test]
fn records_off_the_chain_end_are_rejected() {
    let mut message = RESPONSE.to_vec();
    let owner = message
        .windows(4)
        .rposition(|window| window == [0xC0, 0x31, 0x00, 0x41])
        .expect("the seed's last HTTPS record points at the CNAME target");
    message[owner + 1] = 0x0C;
    let error = drive(&message).expect_err("a record off the chain was accepted");
    assert_eq!(error.kind(), HttpsLookupErrorKind::Resolve);
}

/// Inputs that stop at every seed byte must neither panic nor break an
/// invariant.
#[test]
fn every_seed_prefix_is_handled() {
    for seed in [RESPONSE, SERVICE_RESPONSE] {
        for length in 0..=seed.len() {
            exercise(&seed[..length]);
        }
    }
}

#[test]
fn service_dns_seed_selects_lower_priority_ech() -> Result<(), Box<dyn Error>> {
    let lookup = drive(SERVICE_RESPONSE)?;
    assert_eq!(lookup.answers().len(), 2);
    assert_eq!(lookup.answers()[0].record().priority(), 2);
    assert_eq!(lookup.answers()[1].record().priority(), 1);
    let selected = fuzz_https_selection(&lookup, HOST, 443);
    assert!(selected.advertises_h3);
    assert_eq!(
        selected.ech.ok_or("missing selected ECH")?.as_bytes(),
        b"\x00\x08\xfe\x0d\x00\x04\xde\xad\xbe\xbb"
    );
    assert!(selected.cache_deadline.is_some());
    Ok(())
}

#[test]
fn h3_priority_and_equal_priority_response_order_select_ech() -> Result<(), Box<dyn Error>> {
    for (records, expected) in [
        ([H3_A, H3_B], b"B".as_slice()),
        ([H3_B, H3_C], b"B".as_slice()),
        ([H3_C, H3_B], b"C".as_slice()),
    ] {
        let selected = fuzz_https_selection(&lookup(&records, 60)?, HOST, 443);
        assert!(selected.advertises_h3);
        assert_eq!(
            selected.ech.ok_or("missing selected ECH")?.as_bytes(),
            expected
        );
    }
    Ok(())
}

#[test]
fn ech_belongs_to_first_h3_endpoint_even_when_absent() -> Result<(), Box<dyn Error>> {
    let selected = fuzz_https_selection(&lookup(&[H3, H3_B], 60)?, HOST, 443);
    assert!(selected.advertises_h3);
    assert_eq!(selected.ech, None);
    let selected = fuzz_https_selection(&lookup(&[H2, H3_A], 60)?, HOST, 443);
    assert_eq!(selected.ech.ok_or("missing H3 ECH")?.as_bytes(), b"A");
    Ok(())
}

#[test]
fn incompatible_services_cannot_advertise_origin_h3() -> Result<(), Box<dyn Error>> {
    for rdata in [
        // An ALPN prefix is not the h3 protocol identifier.
        b"\x00\x01\x00\x00\x01\x00\x06\x05h3-29".as_slice(),
        // Another target or port is not this origin's endpoint.
        b"\x00\x01\x05other\x04test\x00\x00\x01\x00\x03\x02h3",
        b"\x00\x01\x00\x00\x01\x00\x03\x02h3\x00\x03\x00\x02\x01\xbc",
        // Key 7 is present but unsupported when mandatory.
        b"\x00\x01\x00\x00\x00\x00\x02\x00\x07\x00\x01\x00\x03\x02h3\x00\x07\x00\x00",
        H2,
    ] {
        let selected = fuzz_https_selection(&lookup(&[rdata], 60)?, HOST, 443);
        assert!(!selected.advertises_h3);
        assert_eq!(selected.ech, None);
        let selected = fuzz_https_selection(&lookup(&[rdata, H3_B], 60)?, HOST, 443);
        assert!(selected.advertises_h3);
        assert_eq!(
            selected.ech.ok_or("valid H3 service excluded")?.as_bytes(),
            b"B"
        );
    }
    Ok(())
}

#[test]
fn named_target_matches_origin_or_answer_owner_case_insensitively() -> Result<(), Box<dyn Error>> {
    let record = HttpsRecord::from_rdata(b"\x00\x01\x03CDN\x04TEST\x00\x00\x01\x00\x03\x02h3")?;
    let owner_match = HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new("cdn.test", 60, record.clone())],
        None,
    );
    assert!(fuzz_https_selection(&owner_match, HOST, 443).advertises_h3);
    let origin_match = HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new("answer.test", 60, record)],
        None,
    );
    assert!(fuzz_https_selection(&origin_match, "cdn.test", 443).advertises_h3);
    Ok(())
}

#[test]
fn no_default_alpn_requires_a_usable_default_service() -> Result<(), Box<dyn Error>> {
    let no_default = b"\x00\x01\x00\x00\x01\x00\x03\x02h3\x00\x02\x00\x00".as_slice();
    assert!(!fuzz_https_selection(&lookup(&[no_default], 60)?, HOST, 443).advertises_h3);
    assert!(fuzz_https_selection(&lookup(&[no_default, H2], 60)?, HOST, 443).advertises_h3);
    let empty_alpn = b"\x00\x01\x00\x00\x02\x00\x00".as_slice();
    assert!(!fuzz_https_selection(&lookup(&[empty_alpn, H2], 60)?, HOST, 443).advertises_h3);
    Ok(())
}

#[test]
fn alias_excludes_services_and_malformed_parameters_stay_errors() -> Result<(), Box<dyn Error>> {
    let alias = b"\x00\x00\x04pool\x04test\x00".as_slice();
    assert!(!fuzz_https_selection(&lookup(&[H3, alias], 60)?, HOST, 443).advertises_h3);
    for rdata in [
        // Truncated ALPN value, duplicate key, missing mandatory key.
        b"\x00\x01\x00\x00\x01\x00\x03\x02h".as_slice(),
        b"\x00\x01\x00\x00\x01\x00\x03\x02h3\x00\x01\x00\x03\x02h2",
        b"\x00\x01\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x03\x02h3",
    ] {
        assert!(HttpsRecord::from_rdata(rdata).is_err());
    }
    Ok(())
}

#[test]
fn expiry_does_not_erase_current_selection_or_restart_ttl() -> Result<(), Box<dyn Error>> {
    let zero = fuzz_https_selection(&lookup(&[H3], 0)?, HOST, 443);
    assert!(zero.advertises_h3);
    assert_eq!(zero.cache_deadline, None);
    let expired = lookup(&[H3], 60)?.with_cache_deadline(Instant::now());
    assert_eq!(
        fuzz_https_selection(&expired, HOST, 443).cache_deadline,
        None
    );
    assert!(fuzz_https_selection(&expired, HOST, 443).advertises_h3);

    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or("clock overflow")?;
    let fresh = lookup(&[H3], 60)?.with_cache_deadline(deadline);
    for lookup in [&fresh, &fresh.clone()] {
        assert_eq!(
            fuzz_https_selection(lookup, HOST, 443).cache_deadline,
            Some(deadline)
        );
    }
    Ok(())
}

#[test]
fn reusable_deadline_is_capped_from_lookup_creation() -> Result<(), Box<dyn Error>> {
    let before = Instant::now();
    let lookup = lookup(&[H3], u32::MAX)?;
    let after = Instant::now();
    let deadline = fuzz_https_selection(&lookup, HOST, 443)
        .cache_deadline
        .ok_or("missing deadline")?;
    let day = Duration::from_secs(86_400);
    assert!(deadline >= before.checked_add(day).ok_or("clock overflow")?);
    assert!(deadline <= after.checked_add(day).ok_or("clock overflow")?);
    for ttl in [None, Some(0)] {
        let empty = HttpsRecordLookup::new(Vec::new(), ttl);
        let selected = fuzz_https_selection(&empty, HOST, 443);
        assert!(!selected.advertises_h3);
        assert_eq!(selected.cache_deadline, None);
    }
    Ok(())
}
