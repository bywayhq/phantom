use phantom_net::dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup};

use super::{DestinationError, select};

mod cache;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const HOST: &str = "alt.test";
const PORT: u16 = 8443;
const OWNER: &str = "_8443._https.alt.test";
const H3: (u16, &[u8]) = (1, b"\x02h3");
const H2: (u16, &[u8]) = (1, b"\x02h2");
const ECH_A: (u16, &[u8]) = (5, b"\x00\x01\xaa");
const ECH_B: (u16, &[u8]) = (5, b"\x00\x01\xbb");

fn record(priority: u16, target: &[&str], parameters: &[(u16, &[u8])]) -> TestResult<HttpsRecord> {
    let mut bytes = priority.to_be_bytes().to_vec();
    for label in target {
        bytes.push(u8::try_from(label.len())?);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    for (key, value) in parameters {
        bytes.extend_from_slice(&key.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(value.len())?.to_be_bytes());
        bytes.extend_from_slice(value);
    }
    Ok(HttpsRecord::from_rdata(&bytes)?)
}

fn lookup(records: impl IntoIterator<Item = HttpsRecord>) -> HttpsRecordLookup {
    HttpsRecordLookup::new(
        records
            .into_iter()
            .map(|record| HttpsRecordAnswer::new(HOST, 300, record))
            .collect(),
        None,
    )
}

#[test]
fn empty_answer_permits_the_selected_destination_without_ech() -> TestResult {
    let empty = HttpsRecordLookup::new(Vec::new(), Some(30));
    assert!(select(&empty, HOST, PORT)?.ech.is_none());
    Ok(())
}

#[test]
fn explicit_h3_with_no_default_alpn_keeps_its_ech() -> TestResult {
    let records = lookup([record(1, &[], &[H3, (2, b""), ECH_A])?]);
    assert_eq!(
        select(&records, HOST, PORT)?
            .ech
            .map(|ech| ech.as_bytes().to_vec()),
        Some(ECH_A.1.to_vec())
    );
    Ok(())
}

#[test]
fn priority_then_response_order_choose_exactly_one_ech_record() -> TestResult {
    for records in [
        vec![record(2, &[], &[H3, ECH_B])?, record(1, &[], &[H3, ECH_A])?],
        vec![record(1, &[], &[H3, ECH_A])?, record(1, &[], &[H3, ECH_B])?],
    ] {
        assert_eq!(
            select(&lookup(records), HOST, PORT)?
                .ech
                .map(|ech| ech.as_bytes().to_vec()),
            Some(ECH_A.1.to_vec())
        );
    }
    Ok(())
}

#[test]
fn selected_record_without_ech_does_not_borrow_a_later_records_ech() -> TestResult {
    let records = lookup([record(1, &[], &[H3])?, record(2, &[], &[H3, ECH_A])?]);
    assert!(select(&records, HOST, PORT)?.ech.is_none());
    Ok(())
}

#[test]
fn incompatible_nonempty_answers_cannot_become_empty_permission() -> TestResult {
    for record in [
        record(1, &[], &[H2, ECH_A])?,
        record(1, &[], &[(2, b""), ECH_A])?,
        record(1, &["different", "test"], &[H3, ECH_A])?,
        record(1, &[], &[H3, (3, &443_u16.to_be_bytes()), ECH_A])?,
        record(
            1,
            &[],
            &[(0, &7_u16.to_be_bytes()), H3, ECH_A, (7, b"unknown")],
        )?,
    ] {
        assert!(matches!(
            select(&lookup([record]), HOST, PORT),
            Err(DestinationError::UnsupportedRecords)
        ));
    }
    Ok(())
}

#[test]
fn alias_mode_cannot_authorize_a_service_even_in_a_mixed_answer() -> TestResult {
    let records = lookup([
        record(0, &["alias", "test"], &[])?,
        record(1, &[], &[H3, ECH_A])?,
    ]);
    assert!(matches!(
        select(&records, HOST, PORT),
        Err(DestinationError::UnsupportedRecords)
    ));
    Ok(())
}

#[test]
fn explicit_selected_host_is_usable_under_a_prefixed_or_cname_owner() -> TestResult {
    for owner in [OWNER, "canonical.test"] {
        let records = HttpsRecordLookup::new(
            vec![
                HttpsRecordAnswer::new(
                    owner,
                    300,
                    record(1, &["elsewhere", "test"], &[H3, ECH_B])?,
                ),
                HttpsRecordAnswer::new(owner, 300, record(2, &["ALT", "test"], &[H3, ECH_A])?),
            ],
            None,
        );
        assert_eq!(
            select(&records, HOST, PORT)?
                .ech
                .map(|ech| ech.as_bytes().to_vec()),
            Some(ECH_A.1.to_vec())
        );
    }
    Ok(())
}

#[test]
fn prefixed_or_cname_owner_cannot_relocate_the_selected_destination() -> TestResult {
    for (owner, target) in [
        (OWNER, vec![]),
        ("canonical.test", vec![]),
        (OWNER, vec!["_8443", "_https", "alt", "test"]),
        ("canonical.test", vec!["canonical", "test"]),
    ] {
        let records = HttpsRecordLookup::new(
            vec![HttpsRecordAnswer::new(
                owner,
                300,
                record(1, &target, &[H3, ECH_A])?,
            )],
            None,
        );
        assert!(matches!(
            select(&records, HOST, PORT),
            Err(DestinationError::UnsupportedRecords)
        ));
    }
    Ok(())
}

#[test]
fn bare_owner_target_keeps_the_selected_destination() -> TestResult {
    let records = lookup([record(1, &[], &[H3, ECH_A])?]);
    assert_eq!(
        select(&records, HOST, PORT)?
            .ech
            .map(|ech| ech.as_bytes().to_vec()),
        Some(ECH_A.1.to_vec())
    );
    Ok(())
}
