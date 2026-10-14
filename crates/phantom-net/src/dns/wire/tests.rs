use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_resolver::proto::rr::{
    Record,
    rdata::{A, AAAA, CNAME, NS, SOA},
};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn query(kind: DnsWireQueryKind) -> Result<DnsWireQuery, DnsWireError> {
    DnsWireQuery::new("www.example.test", kind, 0x1234, None)
}

fn response(query: &DnsWireQuery) -> Message {
    let mut message = Message::response(query.id, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.recursion_available = true;
    message.add_query(Query::query(query.name.clone(), query.kind.record_type()));
    message
}

fn record(owner: &str, ttl: u32, data: RData) -> TestResult<Record> {
    Ok(Record::from_rdata(Name::from_ascii(owner)?, ttl, data))
}

fn alias(owner: &str, target: &str, ttl: u32) -> TestResult<Record> {
    record(owner, ttl, RData::CNAME(CNAME(Name::from_ascii(target)?)))
}

fn soa(owner: &str, ttl: u32, minimum: u32) -> TestResult<Record> {
    record(
        owner,
        ttl,
        RData::SOA(SOA::new(
            Name::from_ascii("ns.example.test.")?,
            Name::from_ascii("hostmaster.example.test.")?,
            1,
            60,
            60,
            3600,
            minimum,
        )),
    )
}

fn error(query: &DnsWireQuery, message: &Message, kind: DnsWireErrorKind) -> TestResult {
    assert_eq!(
        query
            .parse_response(&message.to_vec()?)
            .err()
            .map(|e| e.kind()),
        Some(kind)
    );
    Ok(())
}

fn addresses(query: &DnsWireQuery, message: &Message) -> TestResult<DnsAddressRecords> {
    match query.parse_response(&message.to_vec()?)? {
        DnsWireResult::Addresses(answer) => Ok(answer),
        other => Err(format!("expected address records, got {other:?}").into()),
    }
}

fn follow_up(query: &DnsWireQuery, message: &Message) -> TestResult<DnsWireFollowUp> {
    match query.parse_response(&message.to_vec()?)? {
        DnsWireResult::Cname(answer) => Ok(answer),
        other => Err(format!("expected CNAME follow-up, got {other:?}").into()),
    }
}

fn negative(query: &DnsWireQuery, message: &Message) -> TestResult<DnsNegativeAnswer> {
    match query.parse_response(&message.to_vec()?)? {
        DnsWireResult::Negative(answer) => Ok(answer),
        other => Err(format!("expected negative answer, got {other:?}").into()),
    }
}

// Start with a real question, then append original HTTPS RDATA unchanged.
fn https_response(query: &DnsWireQuery, records: &[(u32, &[u8])]) -> TestResult<Vec<u8>> {
    let mut bytes = response(query).to_vec()?;
    bytes[6..8].copy_from_slice(&u16::try_from(records.len())?.to_be_bytes());
    for (ttl, data) in records {
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 65, 0, 1]);
        bytes.extend_from_slice(&ttl.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(data.len())?.to_be_bytes());
        bytes.extend_from_slice(data);
    }
    Ok(bytes)
}

#[test]
fn query_has_exact_canonical_question_id_and_recursion_flag() -> TestResult {
    let query = DnsWireQuery::new("WWW.Example.TEST", DnsWireQueryKind::A, 0x1234, None)?;
    assert_eq!(query.name(), "www.example.test.");
    assert_eq!(query.as_bytes(), b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x04test\x00\x00\x01\x00\x01");
    for (kind, number) in [(DnsWireQueryKind::Aaaa, 28), (DnsWireQueryKind::Https, 65)] {
        let query = DnsWireQuery::new("_8443._https.example.test.", kind, 7, None)?;
        let message = Message::read(&mut BinDecoder::new(query.as_bytes()))?;
        assert_eq!(message.metadata.id, 7);
        assert_eq!(u16::from(message.queries[0].query_type), number);
        assert_eq!(message.queries[0].query_class, DNSClass::IN);
        assert!(message.metadata.recursion_desired);
        assert!(message.edns.is_none());
    }
    Ok(())
}

#[test]
fn padding_is_one_zero_filled_option_and_covers_the_whole_message() -> TestResult {
    let query = DnsWireQuery::new(
        "www.example.test",
        DnsWireQueryKind::Https,
        0,
        NonZeroU16::new(128),
    )?;
    assert_eq!(query.as_bytes().len(), 128);
    let message = Message::read(&mut BinDecoder::new(query.as_bytes()))?;
    assert_eq!(message.metadata.id, 0);
    let edns = message.edns.ok_or("missing EDNS")?;
    assert_eq!(edns.max_payload(), 4096);
    let options = edns.options().get_all(EdnsCode::Padding);
    assert_eq!(options.len(), 1);
    match options[0] {
        EdnsOption::Unknown(12, padding) => {
            assert_eq!(padding.len(), 79);
            assert!(padding.iter().all(|byte| *byte == 0));
        }
        other => return Err(format!("unexpected padding {other:?}").into()),
    }
    for block in [1, 49, 128, 65535] {
        let query = DnsWireQuery::new(
            "www.example.test",
            DnsWireQueryKind::A,
            9,
            NonZeroU16::new(block),
        )?;
        assert_eq!(query.as_bytes().len() % usize::from(block), 0);
        assert!(query.as_bytes().len() <= MAX_MESSAGE_BYTES);
    }
    Ok(())
}

#[test]
fn invalid_names_fail_before_any_message_is_created() {
    for name in ["", ".", "例.test", "a..test"] {
        assert_eq!(
            DnsWireQuery::new(name, DnsWireQueryKind::A, 0, None)
                .err()
                .map(|e| e.kind()),
            Some(DnsWireErrorKind::InvalidQuery)
        );
    }
    let long_label = format!("{}.test", "a".repeat(64));
    assert!(DnsWireQuery::new(&long_label, DnsWireQueryKind::A, 0, None).is_err());
}

#[test]
fn ipv4_answers_keep_wire_order_and_duplicates_with_minimum_ttl() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut message = response(&query);
    for (last, ttl) in [(2, 70), (1, 20), (2, 50)] {
        message.answers.push(record(
            "www.example.test.",
            ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, last))),
        )?);
    }
    let answer = addresses(&query, &message)?;
    assert_eq!(
        answer.addresses(),
        &[
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))
        ]
    );
    assert_eq!(answer.ttl(), 20);
    Ok(())
}

#[test]
fn ipv6_answers_are_selected_without_accepting_non_in_answers() -> TestResult {
    let query = query(DnsWireQueryKind::Aaaa)?;
    let mut message = response(&query);
    let first = Ipv6Addr::LOCALHOST;
    let second = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let mut foreign = record("unrelated.test.", 0, RData::AAAA(AAAA(second)))?;
    foreign.dns_class = DNSClass::CH;
    message.answers.push(foreign);
    message
        .answers
        .push(record("www.example.test.", 30, RData::AAAA(AAAA(first)))?);
    message
        .answers
        .push(record("www.example.test.", 10, RData::AAAA(AAAA(second)))?);
    let answer = addresses(&query, &message)?;
    assert_eq!(answer.addresses(), &[IpAddr::V6(first), IpAddr::V6(second)]);
    assert_eq!(answer.ttl(), 10);
    Ok(())
}

#[test]
fn every_response_identity_field_is_checked() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let original = response(&query);
    let mut message = original.clone();
    message.metadata.id += 1;
    error(&query, &message, DnsWireErrorKind::Mismatched)?;
    let mut message = original.clone();
    message.metadata.message_type = MessageType::Query;
    error(&query, &message, DnsWireErrorKind::Mismatched)?;
    let mut message = original.clone();
    message.metadata.op_code = OpCode::Status;
    error(&query, &message, DnsWireErrorKind::Mismatched)?;
    let mut message = original.clone();
    message.queries[0].name = Name::from_ascii("other.test.")?;
    error(&query, &message, DnsWireErrorKind::Mismatched)?;
    let mut message = original.clone();
    message.queries[0].query_type = RecordType::AAAA;
    error(&query, &message, DnsWireErrorKind::Mismatched)?;
    let mut message = original.clone();
    message.queries[0].query_class = DNSClass::CH;
    error(&query, &message, DnsWireErrorKind::Mismatched)?;
    let mut message = original.clone();
    message.queries.clear();
    error(&query, &message, DnsWireErrorKind::Mismatched)?;
    let mut message = original.clone();
    message.queries.push(message.queries[0].clone());
    error(&query, &message, DnsWireErrorKind::Mismatched)?;
    let mut message = original;
    message.queries[0].name = Name::from_ascii("WWW.EXAMPLE.TEST.")?;
    assert_eq!(negative(&query, &message)?.kind(), DnsNegativeKind::NoData);
    Ok(())
}

#[test]
fn truncation_and_server_errors_stay_distinct_from_negative_answers() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut message = response(&query);
    message.metadata.truncation = true;
    error(&query, &message, DnsWireErrorKind::Truncated)?;
    message.metadata.truncation = false;
    for code in [
        ResponseCode::ServFail,
        ResponseCode::Refused,
        ResponseCode::BADVERS,
    ] {
        message.metadata.response_code = code;
        if u16::from(code) > 15 {
            message.edns = Some(Edns::new());
        }
        let error = query
            .parse_response(&message.to_vec()?)
            .err()
            .ok_or("accepted server error")?;
        assert_eq!(error.kind(), DnsWireErrorKind::Server);
        assert_eq!(error.response_code(), Some(u16::from(code)));
    }
    Ok(())
}

#[test]
fn all_truncated_prefixes_trailing_bytes_and_impossible_counts_are_rejected() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let bytes = response(&query).to_vec()?;
    for end in 0..bytes.len() {
        assert!(query.parse_response(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        query.parse_response(&trailing).err().map(|e| e.kind()),
        Some(DnsWireErrorKind::Malformed)
    );
    let mut impossible = bytes.clone();
    impossible[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        query.parse_response(&impossible).err().map(|e| e.kind()),
        Some(DnsWireErrorKind::Malformed)
    );
    let mut reserved = bytes;
    reserved[3] |= 0x40;
    assert_eq!(
        query.parse_response(&reserved).err().map(|e| e.kind()),
        Some(DnsWireErrorKind::Malformed)
    );
    Ok(())
}

#[test]
fn compression_cycles_forward_and_out_of_range_pointers_are_rejected() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    for pointer in [[0xc0, 0x0c], [0xc0, 0x0e], [0xff, 0xff]] {
        let mut bytes = response(&query).to_vec()?[..12].to_vec();
        bytes.extend_from_slice(&pointer);
        bytes.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(
            query.parse_response(&bytes).err().map(|e| e.kind()),
            Some(DnsWireErrorKind::Malformed)
        );
    }
    Ok(())
}

#[test]
fn zero_answer_and_chain_ttls_remain_zero() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    for (alias_ttl, address_ttl) in [(0, 80), (60, 0)] {
        let mut message = response(&query);
        message.answers.push(alias(
            "www.example.test.",
            "target.example.test.",
            alias_ttl,
        )?);
        message.answers.push(record(
            "target.example.test.",
            address_ttl,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        )?);
        assert_eq!(addresses(&query, &message)?.ttl(), 0);
    }
    Ok(())
}

#[test]
fn unordered_alias_chain_caps_terminal_ttl_and_duplicate_alias_ttl() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut message = response(&query);
    message.answers.push(record(
        "target.example.test.",
        90,
        RData::A(A(Ipv4Addr::LOCALHOST)),
    )?);
    message
        .answers
        .push(alias("middle.example.test.", "target.example.test.", 40)?);
    message
        .answers
        .push(alias("www.example.test.", "middle.example.test.", 60)?);
    message
        .answers
        .push(alias("www.example.test.", "middle.example.test.", 10)?);
    assert_eq!(addresses(&query, &message)?.ttl(), 10);
    Ok(())
}

#[test]
fn follow_up_retains_type_id_padding_chain_ttl_and_loop_history() -> TestResult {
    let query = DnsWireQuery::new(
        "www.example.test",
        DnsWireQueryKind::Aaaa,
        31,
        NonZeroU16::new(128),
    )?;
    let mut message = response(&query);
    message
        .answers
        .push(alias("www.example.test.", "target.example.test.", 7)?);
    let next = follow_up(&query, &message)?;
    assert_eq!(next.chain_ttl(), Some(7));
    let next = next.into_query();
    assert_eq!(next.name(), "target.example.test.");
    assert_eq!(next.kind(), DnsWireQueryKind::Aaaa);
    assert_eq!(next.id, 31);
    assert_eq!(next.cname_hops(), 1);
    assert_eq!(next.as_bytes().len(), 128);
    let mut terminal = response(&next);
    terminal.answers.push(record(
        "target.example.test.",
        100,
        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
    )?);
    assert_eq!(addresses(&next, &terminal)?.ttl(), 7);
    let mut looped = response(&next);
    looped
        .answers
        .push(alias("target.example.test.", "www.example.test.", 10)?);
    error(&next, &looped, DnsWireErrorKind::AliasLoop)
}

#[test]
fn cname_budget_is_sixteen_hops_across_independent_responses() -> TestResult {
    let mut query = DnsWireQuery::new("n0.example.test", DnsWireQueryKind::A, 0, None)?;
    for hop in 1..=MAX_CNAME_HOPS {
        let mut message = response(&query);
        message
            .answers
            .push(alias(&query.name(), &format!("n{hop}.example.test."), 60)?);
        query = follow_up(&query, &message)?.into_query();
        assert_eq!(query.cname_hops(), hop);
    }
    let mut terminal = response(&query);
    terminal
        .answers
        .push(record(&query.name(), 60, RData::A(A(Ipv4Addr::LOCALHOST)))?);
    assert_eq!(addresses(&query, &terminal)?.ttl(), 60);
    let mut excess = response(&query);
    excess
        .answers
        .push(alias(&query.name(), "n17.example.test.", 60)?);
    error(&query, &excess, DnsWireErrorKind::AliasLimit)
}

#[test]
fn conflicting_looping_and_unrelated_aliases_are_rejected() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut message = response(&query);
    message
        .answers
        .push(alias(&query.name(), "one.example.test.", 1)?);
    message
        .answers
        .push(alias(&query.name(), "two.example.test.", 1)?);
    error(&query, &message, DnsWireErrorKind::ConflictingAlias)?;
    let mut message = response(&query);
    message
        .answers
        .push(alias(&query.name(), "one.example.test.", 1)?);
    message
        .answers
        .push(alias("one.example.test.", &query.name(), 1)?);
    error(&query, &message, DnsWireErrorKind::AliasLoop)?;
    let mut message = response(&query);
    message
        .answers
        .push(alias("unrelated.test.", "target.test.", 1)?);
    error(&query, &message, DnsWireErrorKind::UnexpectedOwner)
}

#[test]
fn requested_answers_must_belong_to_the_terminal_owner() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut message = response(&query);
    message.answers.push(record(
        "unrelated.test.",
        60,
        RData::A(A(Ipv4Addr::LOCALHOST)),
    )?);
    error(&query, &message, DnsWireErrorKind::UnexpectedOwner)?;
    message.answers.clear();
    message
        .answers
        .push(alias(&query.name(), "target.example.test.", 60)?);
    message
        .answers
        .push(record(&query.name(), 60, RData::A(A(Ipv4Addr::LOCALHOST)))?);
    error(&query, &message, DnsWireErrorKind::UnexpectedOwner)
}

#[test]
fn negative_lifetime_uses_soa_ttl_minimum_and_chain_ttl() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
        for (soa_ttl, minimum, expected) in [(90, 20, 20), (10, 30, 10), (90, 0, 0)] {
            let mut message = response(&query);
            message.metadata.response_code = code;
            message
                .authorities
                .push(soa("example.test.", soa_ttl, minimum)?);
            let answer = negative(&query, &message)?;
            assert_eq!(answer.ttl(), Some(expected));
            assert_eq!(
                answer.kind(),
                if code == ResponseCode::NXDomain {
                    DnsNegativeKind::NxDomain
                } else {
                    DnsNegativeKind::NoData
                }
            );
        }
    }
    let mut message = response(&query);
    message
        .answers
        .push(alias(&query.name(), "target.other.test.", 7)?);
    message.authorities.push(soa("other.test.", 80, 60)?);
    message.authorities.push(soa("example.test.", 0, 0)?);
    assert_eq!(negative(&query, &message)?.ttl(), Some(7));
    Ok(())
}

#[test]
fn unrelated_or_absent_soa_never_supplies_negative_lifetime() -> TestResult {
    let query = query(DnsWireQueryKind::Https)?;
    let mut message = response(&query);
    message.metadata.response_code = ResponseCode::NXDomain;
    message.authorities.push(soa("unrelated.test.", 80, 60)?);
    assert_eq!(negative(&query, &message)?.ttl(), None);
    message.authorities.clear();
    assert_eq!(negative(&query, &message)?.ttl(), None);
    message.metadata.response_code = ResponseCode::NoError;
    assert_eq!(negative(&query, &message)?.ttl(), None);
    Ok(())
}

#[test]
fn referral_is_not_negative_and_nxdomain_cannot_carry_positive_answers() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut message = response(&query);
    message.authorities.push(record(
        "example.test.",
        60,
        RData::NS(NS(Name::from_ascii("ns.example.test.")?)),
    )?);
    error(&query, &message, DnsWireErrorKind::Referral)?;
    message.authorities.clear();
    message.metadata.response_code = ResponseCode::NXDomain;
    message
        .answers
        .push(record(&query.name(), 60, RData::A(A(Ipv4Addr::LOCALHOST)))?);
    error(&query, &message, DnsWireErrorKind::Malformed)
}

#[test]
fn https_order_and_individual_ttls_survive_without_following_targets() -> TestResult {
    let query = query(DnsWireQueryKind::Https)?;
    let alias = b"\x00\x00\x03alt\x04test\x00";
    let service = b"\x00\x01\x00\x00\x01\x00\x03\x02h3";
    let bytes = https_response(&query, &[(50, service), (0, alias), (70, service)])?;
    let DnsWireResult::Https(answer) = query.parse_response(&bytes)? else {
        return Err("HTTPS records were followed or lost".into());
    };
    assert_eq!(answer.answers().len(), 3);
    assert_eq!(
        answer
            .answers()
            .iter()
            .map(|a| a.record().priority())
            .collect::<Vec<_>>(),
        [1, 0, 1]
    );
    assert_eq!(
        answer.answers().iter().map(|a| a.ttl()).collect::<Vec<_>>(),
        [50, 0, 70]
    );
    assert!(
        answer
            .answers()
            .iter()
            .all(|a| a.owner() == "www.example.test")
    );
    assert_eq!(answer.negative_ttl(), None);
    Ok(())
}

#[test]
fn original_https_rdata_rejects_compressed_targets_and_out_of_order_keys() -> TestResult {
    let query = query(DnsWireQueryKind::Https)?;
    for rdata in [
        b"\x00\x01\xc0\x0c".as_slice(),
        b"\x00\x01\x00\x00\x03\x00\x02\x01\xbb\x00\x01\x00\x03\x02h3".as_slice(),
        b"\x00\x01\x00\x00\x01\x00\x03\x02h3\x00\x01\x00\x03\x02h2".as_slice(),
    ] {
        let bytes = https_response(&query, &[(60, rdata)])?;
        assert_eq!(
            query.parse_response(&bytes).err().map(|e| e.kind()),
            Some(DnsWireErrorKind::Malformed)
        );
    }
    Ok(())
}

#[test]
fn alias_mode_ignores_parameters_without_following_its_target() -> TestResult {
    let query = query(DnsWireQueryKind::Https)?;
    // RFC 9460 section 2.4.2: even malformed SvcParams are ignored here.
    let bytes = https_response(
        &query,
        &[(60, b"\x00\x00\x03alt\x04test\x00\x00\x01\xff\xff")],
    )?;
    let DnsWireResult::Https(answer) = query.parse_response(&bytes)? else {
        return Err("AliasMode was followed".into());
    };
    assert_eq!(answer.answers().len(), 1);
    assert!(matches!(
        answer.answers()[0].record(),
        HttpsRecord::Alias(_)
    ));
    Ok(())
}

#[test]
fn https_follow_up_caps_each_answer_ttl_by_the_preceding_aliases() -> TestResult {
    let query = query(DnsWireQueryKind::Https)?;
    let mut message = response(&query);
    message
        .answers
        .push(alias(&query.name(), "target.example.test.", 20)?);
    let next = follow_up(&query, &message)?.into_query();
    let bytes = https_response(&next, &[(60, b"\x00\x01\x00"), (10, b"\x00\x02\x00")])?;
    let DnsWireResult::Https(answer) = next.parse_response(&bytes)? else {
        return Err("missing HTTPS records".into());
    };
    assert_eq!(
        answer.answers().iter().map(|a| a.ttl()).collect::<Vec<_>>(),
        [20, 10]
    );
    assert!(
        answer
            .answers()
            .iter()
            .all(|a| a.owner() == "target.example.test")
    );
    Ok(())
}

#[test]
fn negative_follow_up_keeps_the_preceding_alias_ttl() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut message = response(&query);
    message
        .answers
        .push(alias(&query.name(), "target.other.test.", 7)?);
    let next = follow_up(&query, &message)?.into_query();
    let mut terminal = response(&next);
    terminal.metadata.response_code = ResponseCode::NXDomain;
    terminal.authorities.push(soa("other.test.", 90, 60)?);
    assert_eq!(negative(&next, &terminal)?.ttl(), Some(7));
    Ok(())
}

#[test]
fn one_response_cannot_exceed_the_shared_cname_budget() -> TestResult {
    let query = DnsWireQuery::new("n0.example.test", DnsWireQueryKind::A, 0, None)?;
    let mut message = response(&query);
    for hop in 0..=MAX_CNAME_HOPS {
        message.answers.push(alias(
            &format!("n{hop}.example.test."),
            &format!("n{}.example.test.", hop + 1),
            60,
        )?);
    }
    error(&query, &message, DnsWireErrorKind::AliasLimit)
}

#[test]
fn duplicate_or_misplaced_edns_and_empty_address_records_are_malformed() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut message = response(&query);
    message.edns = Some(Edns::new());
    let mut bytes = message.to_vec()?;
    bytes[10..12].copy_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        query.parse_response(&bytes).err().map(|e| e.kind()),
        Some(DnsWireErrorKind::Malformed)
    );
    let mut bytes = message.to_vec()?;
    bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
    bytes[10..12].copy_from_slice(&0_u16.to_be_bytes());
    assert_eq!(
        query.parse_response(&bytes).err().map(|e| e.kind()),
        Some(DnsWireErrorKind::Malformed)
    );
    let mut bytes = response(&query).to_vec()?;
    bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 0]);
    assert_eq!(
        query.parse_response(&bytes).err().map(|e| e.kind()),
        Some(DnsWireErrorKind::Malformed)
    );
    Ok(())
}

#[test]
fn response_padding_accepts_nonzero_bytes_but_not_duplicate_options() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut message = response(&query);
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(12, vec![7, 9]));
    message.edns = Some(edns);
    assert_eq!(negative(&query, &message)?.kind(), DnsNegativeKind::NoData);
    if let Some(edns) = &mut message.edns {
        edns.options_mut()
            .insert(EdnsOption::Unknown(12, Vec::new()));
    }
    assert_eq!(
        message.to_vec()?.as_slice(),
        b"\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x01\x03www\x07example\x04test\x00\x00\x01\x00\x01\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x0a\x00\x0c\x00\x02\x07\x09\x00\x0c\x00\x00"
    );
    error(&query, &message, DnsWireErrorKind::Malformed)
}

#[test]
fn exactly_65535_bytes_are_allowed_but_one_more_is_rejected() -> TestResult {
    let query = query(DnsWireQueryKind::A)?;
    let mut bytes = response(&query).to_vec()?;
    bytes[10..12].copy_from_slice(&1_u16.to_be_bytes());
    let data_len = MAX_MESSAGE_BYTES - bytes.len() - 11;
    // Unknown additional RR: root owner, private-use type, IN, zero TTL.
    bytes.extend_from_slice(&[0, 0xff, 0x00, 0, 1, 0, 0, 0, 0]);
    bytes.extend_from_slice(&u16::try_from(data_len)?.to_be_bytes());
    bytes.resize(MAX_MESSAGE_BYTES, 0);
    assert!(matches!(
        query.parse_response(&bytes)?,
        DnsWireResult::Negative(_)
    ));
    bytes.push(0);
    assert_eq!(
        query.parse_response(&bytes).err().map(|e| e.kind()),
        Some(DnsWireErrorKind::TooLarge)
    );
    Ok(())
}
