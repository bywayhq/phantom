//! Deterministic regressions for the HTTPS record harness.

use phantom_net::dns::{HttpsLookupErrorKind, HttpsRecord, TargetName};

use super::{RESPONSE, drive, exercise};

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
    for length in 0..=RESPONSE.len() {
        exercise(&RESPONSE[..length]);
    }
}
