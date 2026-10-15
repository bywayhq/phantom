use super::*;

const AB: &[u8] = &[0, 0, 0, 2, 0, 0, 0, 1, b'a', 0, 0, 0, 1, b'b'];
const BA: &[u8] = &[0, 0, 0, 2, 0, 0, 0, 1, b'b', 0, 0, 0, 1, b'a'];

fn framed(tcp: Option<&[u8]>, quic: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for value in [tcp, quic] {
        match value {
            None => out.push(0),
            Some(bytes) => {
                out.push(1);
                out.extend_from_slice(
                    &u32::try_from(bytes.len())
                        .unwrap_or_else(|error| panic!("fixture length exceeds u32: {error}"))
                        .to_be_bytes(),
                );
                out.extend_from_slice(bytes);
            }
        }
    }
    out
}

fn prepare(
    configured: &ClientProfile,
    tcp: u64,
    quic: u64,
) -> Result<super::super::PreparedTicketPolicy, Box<dyn Error>> {
    let plan = BindingPlan::capture(configured)?;
    let mut actual = configured.clone();
    let mut calls = 0;
    actual.draw_per_client(|| {
        calls += 1;
        Ok::<_, PreparationError>(if calls == 1 { tcp } else { quic })
    })?;
    Ok(plan.complete(&actual)?)
}

#[test]
fn source_draws_may_differ_from_both_recipient_draws_without_changing_bytes() -> TestResult {
    let configured = drawn_profile(TrustAnchorIds::PerClient(candidates()?));
    let recipient = prepare(&configured, 0, u64::MAX)?;
    let source = prepare(&configured, u64::MAX, 0)?;
    assert!(recipient.canonical == source.canonical);
    assert_eq!(recipient.tcp_draw.as_ref().map(|v| v.as_slice()), Some(AB));
    assert_eq!(recipient.quic_draw.as_ref().map(|v| v.as_slice()), Some(BA));
    assert_eq!(source.tcp_draw.as_ref().map(|v| v.as_slice()), Some(BA));
    assert_eq!(source.quic_draw.as_ref().map(|v| v.as_slice()), Some(AB));
    for tcp in [AB, BA] {
        for quic in [AB, BA] {
            recipient.validate_source_witness(&framed(Some(tcp), Some(quic)))?;
        }
    }
    assert_eq!(recipient.tcp_draw.as_ref().map(|v| v.as_slice()), Some(AB));
    assert_eq!(recipient.quic_draw.as_ref().map(|v| v.as_slice()), Some(BA));
    Ok(())
}

#[test]
fn absent_fixed_and_per_connection_policies_require_absent_source_frames() -> TestResult {
    for configured in [
        chrome::v154_windows(),
        drawn_profile(TrustAnchorIds::Fixed(candidates()?.as_slice()[0].clone())),
        drawn_profile(TrustAnchorIds::PerConnection(candidates()?)),
    ] {
        let recipient = prepare(&configured, 0, 0)?;
        recipient.validate_source_witness(&[0, 0])?;
        for witness in [
            framed(Some(AB), None),
            framed(None, Some(BA)),
            framed(Some(AB), Some(BA)),
        ] {
            assert_eq!(
                recipient.validate_source_witness(&witness),
                Err(PreparationError::DrawMismatch)
            );
        }
    }
    let recipient = prepare(
        &drawn_profile(TrustAnchorIds::PerClient(candidates()?)),
        0,
        0,
    )?;
    for witness in [vec![0, 0], framed(Some(AB), None), framed(None, Some(AB))] {
        assert_eq!(
            recipient.validate_source_witness(&witness),
            Err(PreparationError::DrawMismatch)
        );
    }
    Ok(())
}

#[test]
fn each_leg_checks_its_own_policy_and_presence() -> TestResult {
    let configured = drawn_profile(TrustAnchorIds::PerClient(candidates()?));
    let mut quic = configured.http3().ok_or("missing H3")?.tls().clone();
    quic.requested_trust_anchor_ids =
        Some(TrustAnchorIds::PerClient(TrustAnchorOrders::new(vec![
            TrustAnchorOrder::new(vec![Box::from(&b"c"[..]), Box::from(&b"d"[..])])?,
        ])?));
    let with_quic = |tcp| {
        ClientProfile::new(tcp).with_http3(Http3ClientSettings::new(
            quic.clone(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
    };
    let cd = [0, 0, 0, 2, 0, 0, 0, 1, b'c', 0, 0, 0, 1, b'd'];
    let recipient = prepare(&with_quic(configured.tls().clone()), 0, 0)?;
    recipient.validate_source_witness(&framed(Some(AB), Some(&cd)))?;
    assert_eq!(
        recipient.validate_source_witness(&framed(Some(&cd), Some(AB))),
        Err(PreparationError::DrawMismatch)
    );
    let tcp_only = ClientProfile::new(configured.tls().clone());
    prepare(&tcp_only, 0, 0)?.validate_source_witness(&framed(Some(BA), None))?;
    let mut no_tcp_draw = configured.tls().clone();
    no_tcp_draw.requested_trust_anchor_ids = None;
    let quic_only = prepare(&with_quic(no_tcp_draw), 0, 0)?;
    quic_only.validate_source_witness(&framed(None, Some(&cd)))?;
    assert_eq!(
        quic_only.validate_source_witness(&framed(Some(&cd), None)),
        Err(PreparationError::DrawMismatch)
    );
    Ok(())
}

#[test]
fn malformed_outer_frames_are_rejected_including_truncation_unknown_tags_and_trailing_data()
-> TestResult {
    let recipient = prepare(
        &drawn_profile(TrustAnchorIds::PerClient(candidates()?)),
        0,
        0,
    )?;
    let valid = framed(Some(AB), Some(BA));
    for end in 0..valid.len() {
        assert_eq!(
            recipient.validate_source_witness(&valid[..end]),
            Err(PreparationError::DrawMismatch)
        );
    }
    for bad in [
        vec![2, 0],
        vec![0, 255],
        vec![1, 255, 255, 255, 255, 0],
        framed(Some(&[]), Some(BA)),
    ] {
        assert_eq!(
            recipient.validate_source_witness(&bad),
            Err(PreparationError::DrawMismatch)
        );
    }
    let mut unknown_quic_tag = framed(Some(AB), None);
    *unknown_quic_tag.last_mut().ok_or("fixture tag absent")? = 2;
    assert_eq!(
        recipient.validate_source_witness(&unknown_quic_tag),
        Err(PreparationError::DrawMismatch)
    );
    let mut oversized_quic_frame = framed(Some(AB), None);
    oversized_quic_frame.pop();
    oversized_quic_frame.extend_from_slice(&[1, 255, 255, 255, 255]);
    assert_eq!(
        recipient.validate_source_witness(&oversized_quic_frame),
        Err(PreparationError::DrawMismatch)
    );
    let mut trailing = valid;
    trailing.push(0);
    assert_eq!(
        recipient.validate_source_witness(&trailing),
        Err(PreparationError::DrawMismatch)
    );
    Ok(())
}

#[test]
fn malformed_order_counts_lengths_ids_and_trailing_bytes_are_rejected() -> TestResult {
    let recipient = prepare(
        &drawn_profile(TrustAnchorIds::PerClient(candidates()?)),
        0,
        0,
    )?;
    let mut bad_orders = vec![vec![], vec![0, 0, 0, 0], vec![255; 4]];
    let mut bad_count = AB.to_vec();
    bad_count[3] = 3;
    bad_orders.push(bad_count);
    let mut oversized_id = AB.to_vec();
    oversized_id[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    bad_orders.push(oversized_id);
    let mut foreign_id = AB.to_vec();
    foreign_id[8] = b'z';
    bad_orders.push(foreign_id);
    let mut trailing = AB.to_vec();
    trailing.push(0);
    bad_orders.push(trailing);
    bad_orders.push(AB[..AB.len() - 1].to_vec());
    for bad in bad_orders {
        for witness in [framed(Some(&bad), Some(AB)), framed(Some(AB), Some(&bad))] {
            assert_eq!(
                recipient.validate_source_witness(&witness),
                Err(PreparationError::DrawMismatch)
            );
        }
    }
    Ok(())
}

#[test]
fn same_multiset_in_an_unlisted_order_is_not_an_allowed_source_draw() -> TestResult {
    let order =
        |ids: &[u8]| TrustAnchorOrder::new(ids.iter().map(|id| Box::from(&[*id][..])).collect());
    let configured = drawn_profile(TrustAnchorIds::PerClient(TrustAnchorOrders::new(vec![
        order(b"abc")?,
        order(b"cba")?,
    ])?));
    let recipient = prepare(&configured, 0, 0)?;
    let unlisted = [
        0, 0, 0, 3, 0, 0, 0, 1, b'b', 0, 0, 0, 1, b'a', 0, 0, 0, 1, b'c',
    ];
    assert_eq!(
        recipient.validate_source_witness(&framed(Some(&unlisted), Some(&unlisted))),
        Err(PreparationError::DrawMismatch)
    );
    Ok(())
}

#[test]
fn an_allowed_empty_order_is_present_and_duplicate_candidate_slots_are_preserved() -> TestResult {
    let empty = TrustAnchorOrder::empty();
    let configured = drawn_profile(TrustAnchorIds::PerClient(TrustAnchorOrders::new(vec![
        empty.clone(),
        empty,
    ])?));
    let recipient = prepare(&configured, 0, u64::MAX)?;
    recipient.validate_source_witness(&framed(Some(&[0; 4]), Some(&[0; 4])))?;
    assert_eq!(
        recipient.validate_source_witness(&[0, 0]),
        Err(PreparationError::DrawMismatch)
    );
    match recipient.tcp_draw_policy.as_ref() {
        Some(TrustAnchorIds::PerClient(orders)) => assert_eq!(orders.as_slice().len(), 2),
        _ => return Err("allowed typed orders were not retained".into()),
    }
    Ok(())
}

#[test]
fn source_witness_bytes_respect_the_preparation_ceiling() -> TestResult {
    let recipient = prepare(&chrome::v154_windows(), 0, 0)?;
    assert_eq!(
        recipient.validate_source_witness(&vec![0; MAX_POLICY_BYTES + 1]),
        Err(PreparationError::TooLarge)
    );
    assert_eq!(
        recipient.validate_source_witness(&vec![0; MAX_POLICY_BYTES]),
        Err(PreparationError::DrawMismatch)
    );
    Ok(())
}
