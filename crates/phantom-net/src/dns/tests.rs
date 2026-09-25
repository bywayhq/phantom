use std::net::{Ipv4Addr, Ipv6Addr};

use phantom_testkit::dns::{DnsAnswer, DnsReply, DnsServer};

use super::{
    HttpsLookupErrorKind, HttpsRecord, HttpsRecordErrorKind, HttpsRecordResolver, TargetName,
    https_answers_from_message, query_name,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn rdata(priority: u16, target: &[&[u8]], params: &[(u16, &[u8])]) -> Vec<u8> {
    let mut bytes = priority.to_be_bytes().to_vec();
    for label in target {
        bytes.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        bytes.extend_from_slice(label);
    }
    bytes.push(0);
    for (key, value) in params {
        bytes.extend_from_slice(&key.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}

const ECH: &[u8] = &[0x00, 0x08, 0xFE, 0x0D, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];

fn every_parameter() -> Vec<u8> {
    let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
    rdata(
        1,
        &[],
        &[
            (0, &[0, 1, 0, 3]),
            (1, b"\x02h3\x02h2"),
            (2, b""),
            (3, &8443_u16.to_be_bytes()),
            (4, &[192, 0, 2, 1, 192, 0, 2, 2]),
            (5, ECH),
            (6, &ipv6),
            (7, &[9, 9]),
        ],
    )
}

#[test]
fn service_record_exposes_every_parameter() -> TestResult<()> {
    let HttpsRecord::Service(record) = HttpsRecord::from_rdata(&every_parameter())? else {
        return Err("expected a ServiceMode record".into());
    };
    assert_eq!(record.priority().get(), 1);
    assert_eq!(record.target(), &TargetName::Owner);
    assert_eq!(record.mandatory(), [1, 3]);
    assert_eq!(
        record.alpn().iter().map(AsRef::as_ref).collect::<Vec<_>>(),
        [b"h3".as_slice(), b"h2"]
    );
    assert!(record.no_default_alpn());
    assert_eq!(record.port(), Some(8443));
    assert_eq!(
        record.ipv4_hint(),
        [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
    );
    assert_eq!(
        record.ipv6_hint(),
        [Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)]
    );
    assert_eq!(record.ech().map(|ech| ech.as_bytes()), Some(ECH));
    let other = record.other_params();
    assert_eq!(other.len(), 1);
    assert_eq!((other[0].key(), other[0].value()), (7, [9, 9].as_slice()));
    Ok(())
}

#[test]
fn service_record_without_parameters_has_empty_defaults() -> TestResult<()> {
    let record = HttpsRecord::from_rdata(&rdata(3, &[b"Svc", b"Example", b"net"], &[]))?;
    assert_eq!(record.priority(), 3);
    assert_eq!(record.target(), &TargetName::Name("Svc.Example.net".into()));
    let HttpsRecord::Service(record) = record else {
        return Err("expected a ServiceMode record".into());
    };
    assert!(record.mandatory().is_empty());
    assert!(record.alpn().is_empty());
    assert!(!record.no_default_alpn());
    assert_eq!(record.port(), None);
    assert!(record.ipv4_hint().is_empty() && record.ipv6_hint().is_empty());
    assert!(record.ech().is_none() && record.other_params().is_empty());
    Ok(())
}

#[test]
fn alias_record_ignores_its_parameters_unparsed() -> TestResult<()> {
    // The parameter bytes are malformed (a key with no length); AliasMode
    // recipients must ignore SvcParams, so they are never parsed.
    let mut bytes = rdata(0, &[b"pool", b"example", b"net"], &[]);
    bytes.extend_from_slice(&[0xFF]);
    let HttpsRecord::Alias(alias) = HttpsRecord::from_rdata(&bytes)? else {
        return Err("expected an AliasMode record".into());
    };
    assert_eq!(alias.target(), &TargetName::Name("pool.example.net".into()));

    let unavailable = HttpsRecord::from_rdata(&rdata(0, &[], &[]))?;
    assert_eq!(unavailable.priority(), 0);
    assert_eq!(unavailable.target(), &TargetName::Owner);
    Ok(())
}

#[test]
fn ech_config_list_debug_omits_its_bytes() -> TestResult<()> {
    let HttpsRecord::Service(record) = HttpsRecord::from_rdata(&every_parameter())? else {
        return Err("expected a ServiceMode record".into());
    };
    let ech = record.ech().ok_or("missing ech")?;
    assert_eq!(format!("{ech:?}"), "EchConfigList { len: 10 }");
    Ok(())
}

/// An error kind and the key it concerns.
type Failure = (HttpsRecordErrorKind, Option<u16>);

fn error_of(bytes: &[u8]) -> TestResult<Failure> {
    match HttpsRecord::from_rdata(bytes) {
        Ok(record) => Err(format!("malformed RDATA parsed as {record:?}").into()),
        Err(error) => Ok((error.kind(), error.key())),
    }
}

#[test]
fn malformed_records_are_typed_errors() -> TestResult<()> {
    use HttpsRecordErrorKind::{
        InvalidParameter, KeyOrder, MissingMandatoryKey, ReservedKey, TargetName, Truncated,
    };
    let long_label = [b'a'; 64];
    let label = [b'a'; 63];
    let long_name = [label.as_slice(); 4];
    let cases: Vec<(&str, Vec<u8>, Failure)> = vec![
        ("empty", Vec::new(), (Truncated, None)),
        ("priority only", vec![0, 1], (Truncated, None)),
        (
            "unterminated target",
            vec![0, 1, 3, b'a'],
            (Truncated, None),
        ),
        (
            "compressed target",
            vec![0, 1, 0xC0, 0x0C],
            (TargetName, None),
        ),
        (
            "label over 63",
            rdata(1, &[&long_label], &[]),
            (TargetName, None),
        ),
        (
            "name over 255",
            rdata(1, &long_name, &[]),
            (TargetName, None),
        ),
        ("dot in label", rdata(1, &[b"a.b"], &[]), (TargetName, None)),
        (
            "control byte in label",
            rdata(1, &[b"a\x00b"], &[]),
            (TargetName, None),
        ),
        (
            "key without length",
            [rdata(1, &[], &[]), vec![0, 1]].concat(),
            (Truncated, None),
        ),
        (
            "value past the end",
            [rdata(1, &[], &[]), vec![0, 3, 0, 2, 0x20]].concat(),
            (Truncated, None),
        ),
        (
            "keys out of order",
            rdata(1, &[], &[(3, &[1, 187]), (1, b"\x02h3")]),
            (KeyOrder, Some(1)),
        ),
        (
            "duplicate key",
            rdata(1, &[], &[(1, b"\x02h3"), (1, b"\x02h2")]),
            (KeyOrder, Some(1)),
        ),
        (
            "reserved key",
            rdata(1, &[], &[(65535, b"")]),
            (ReservedKey, Some(65535)),
        ),
        (
            "empty mandatory",
            rdata(1, &[], &[(0, b"")]),
            (InvalidParameter, Some(0)),
        ),
        (
            "odd mandatory",
            rdata(1, &[], &[(0, &[0, 1, 0])]),
            (InvalidParameter, Some(0)),
        ),
        (
            "unsorted mandatory",
            rdata(
                1,
                &[],
                &[(0, &[0, 3, 0, 1]), (1, b"\x02h3"), (3, &[1, 187])],
            ),
            (InvalidParameter, Some(0)),
        ),
        (
            "mandatory lists itself",
            rdata(1, &[], &[(0, &[0, 0])]),
            (InvalidParameter, Some(0)),
        ),
        (
            "mandatory key absent",
            rdata(1, &[], &[(0, &[0, 1, 0, 3]), (1, b"\x02h3")]),
            (MissingMandatoryKey, Some(3)),
        ),
        (
            "empty alpn",
            rdata(1, &[], &[(1, b"")]),
            (InvalidParameter, Some(1)),
        ),
        (
            "empty alpn id",
            rdata(1, &[], &[(1, b"\x02h3\x00")]),
            (InvalidParameter, Some(1)),
        ),
        (
            "alpn id overrun",
            rdata(1, &[], &[(1, b"\x03h3")]),
            (InvalidParameter, Some(1)),
        ),
        (
            "no-default-alpn with a value",
            rdata(1, &[], &[(1, b"\x02h3"), (2, b"x")]),
            (InvalidParameter, Some(2)),
        ),
        (
            "short port",
            rdata(1, &[], &[(3, &[1])]),
            (InvalidParameter, Some(3)),
        ),
        (
            "long port",
            rdata(1, &[], &[(3, &[0, 1, 187])]),
            (InvalidParameter, Some(3)),
        ),
        (
            "empty ipv4hint",
            rdata(1, &[], &[(4, b"")]),
            (InvalidParameter, Some(4)),
        ),
        (
            "ragged ipv4hint",
            rdata(1, &[], &[(4, &[1, 2, 3, 4, 5])]),
            (InvalidParameter, Some(4)),
        ),
        (
            "empty ech",
            rdata(1, &[], &[(5, b"")]),
            (InvalidParameter, Some(5)),
        ),
        (
            "empty ipv6hint",
            rdata(1, &[], &[(6, b"")]),
            (InvalidParameter, Some(6)),
        ),
        (
            "ragged ipv6hint",
            rdata(1, &[], &[(6, &[0; 15])]),
            (InvalidParameter, Some(6)),
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(error_of(&bytes)?, expected, "{name}");
    }
    Ok(())
}

#[test]
fn truncation_parses_only_at_parameter_boundaries() {
    let bytes = every_parameter();
    // Priority and the root target, then each parameter's key, length, and value.
    let mut boundaries = vec![3];
    let mut offset = 3;
    while offset < bytes.len() {
        offset += 4 + usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
        boundaries.push(offset);
    }
    for length in 0..bytes.len() {
        if HttpsRecord::from_rdata(&bytes[..length]).is_ok() {
            // A cut between parameters is itself a well-formed record when
            // it keeps no parameter at all, or keeps both mandatory keys,
            // alpn and port.
            assert!(
                boundaries.contains(&length),
                "prefix of {length} bytes parsed"
            );
            assert!(
                length == boundaries[0] || length >= boundaries[4],
                "prefix of {length} bytes lacks a mandatory key"
            );
        }
    }
}

#[test]
fn arbitrary_rdata_never_panics() {
    // A fixed linear congruential sequence keeps the inputs reproducible.
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state.to_be_bytes()[0]
    };
    let seed = every_parameter();
    for round in 0..20_000_usize {
        let mut bytes = seed.clone();
        for _ in 0..=round % 4 {
            let position = usize::from(next()) % bytes.len();
            bytes[position] = next();
        }
        bytes.truncate(usize::from(next()) % (bytes.len() + 1));
        let _ = HttpsRecord::from_rdata(&bytes);
    }
}

#[test]
fn query_name_prefixes_non_default_ports() {
    assert_eq!(query_name("example.com", 443), "example.com.");
    assert_eq!(query_name("example.com", 8443), "_8443._https.example.com.");
    assert_eq!(query_name("example.com.", 443), "example.com.");
}

#[test]
fn resolver_needs_a_nameserver() {
    let error = HttpsRecordResolver::with_nameservers([]).err();
    assert_eq!(
        error.map(|error| error.kind()),
        Some(HttpsLookupErrorKind::Configuration)
    );
}

#[tokio::test]
async fn lookup_sends_one_plain_recursive_question_and_parses_answers() -> TestResult<()> {
    let records = vec![
        rdata(2, &[], &[(1, b"\x02h3")]),
        rdata(
            1,
            &[b"edge", b"example", b"test"],
            &[(3, &8443_u16.to_be_bytes())],
        ),
    ];
    let server = DnsServer::spawn(move |_| {
        DnsReply::new(DnsAnswer::Records {
            ttl: 120,
            rdata: records.clone(),
        })
    })
    .await?;
    let resolver = HttpsRecordResolver::with_nameservers([server.address()])?;

    let lookup = resolver.lookup("Origin.Example.test", 8443).await?;
    let queries = server.queries();
    assert_eq!(queries.len(), 1);
    let query = &queries[0];
    assert_eq!(query.name(), "_8443._https.origin.example.test");
    assert_eq!(query.record_type(), 65);
    // RD only, one question, and no OPT pseudo-record in the additional section.
    assert_eq!(query.flags(), 0x0100);
    assert_eq!(query.counts(), [1, 0, 0, 0]);

    let answers = lookup.answers();
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0].owner(), "_8443._https.Origin.Example.test");
    assert_eq!(answers[0].ttl(), 120);
    assert_eq!(answers[0].record().priority(), 2);
    assert_eq!(
        answers[1].record().target(),
        &TargetName::Name("edge.example.test".into())
    );
    assert_eq!(lookup.negative_ttl(), None);

    resolver.lookup("origin.example.test", 443).await?;
    assert_eq!(server.queries()[1].name(), "origin.example.test");
    Ok(())
}

#[tokio::test]
async fn lookup_without_records_is_empty_with_the_negative_ttl() -> TestResult<()> {
    let server = DnsServer::spawn(|_| {
        DnsReply::new(DnsAnswer::NoData {
            soa_minimum: Some(90),
        })
    })
    .await?;
    let resolver = HttpsRecordResolver::with_nameservers([server.address()])?;
    let lookup = resolver.lookup("origin.example.test", 443).await?;
    assert!(lookup.answers().is_empty());
    assert_eq!(lookup.negative_ttl(), Some(90));
    Ok(())
}

#[tokio::test]
async fn special_use_names_are_answered_without_a_query() -> TestResult<()> {
    let server = DnsServer::spawn(|_| {
        DnsReply::new(DnsAnswer::Records {
            ttl: 60,
            rdata: vec![rdata(1, &[], &[(1, b"\x02h3")])],
        })
    })
    .await?;
    let resolver = HttpsRecordResolver::with_nameservers([server.address()])?;
    for host in [
        "localhost",
        "app.localhost",
        "name.invalid",
        "service.onion",
    ] {
        let lookup = resolver.lookup(host, 443).await?;
        assert!(lookup.answers().is_empty(), "{host}");
    }
    assert!(server.queries().is_empty());
    Ok(())
}

#[tokio::test]
async fn function_resolver_answers_through_the_caller() -> TestResult<()> {
    let resolver = HttpsRecordResolver::from_fn(|host, port| async move {
        let record = HttpsRecord::from_rdata(&rdata(1, &[], &[(1, b"\x02h3")]))
            .map_err(super::HttpsLookupError::other)?;
        Ok(super::HttpsRecordLookup::new(
            vec![super::HttpsRecordAnswer::new(
                format!("{host}:{port}"),
                30,
                record,
            )],
            None,
        ))
    });
    let lookup = resolver.lookup("localhost", 8443).await?;
    assert_eq!(lookup.answers()[0].owner(), "localhost:8443");
    assert_eq!(lookup.answers()[0].ttl(), 30);
    assert_eq!(
        format!("{resolver:?}"),
        "HttpsRecordResolver { backend: \"function\", .. }"
    );
    Ok(())
}

#[tokio::test]
async fn server_failure_is_a_resolve_error() -> TestResult<()> {
    let server = DnsServer::spawn(|_| DnsReply::new(DnsAnswer::ServerFailure)).await?;
    let resolver = HttpsRecordResolver::with_nameservers([server.address()])?;
    let error = resolver
        .lookup("origin.example.test", 443)
        .await
        .err()
        .ok_or("SERVFAIL produced records")?;
    assert_eq!(error.kind(), HttpsLookupErrorKind::Resolve);
    Ok(())
}

#[tokio::test]
async fn malformed_answer_record_is_a_typed_error() -> TestResult<()> {
    // hickory decodes this record, but RFC 9460 section 8 makes a missing
    // mandatory key malformed.
    let record = rdata(1, &[], &[(0, &[0, 3]), (1, b"\x02h3")]);
    let server = DnsServer::spawn(move |_| {
        DnsReply::new(DnsAnswer::Records {
            ttl: 60,
            rdata: vec![record.clone()],
        })
    })
    .await?;
    let resolver = HttpsRecordResolver::with_nameservers([server.address()])?;
    let error = resolver
        .lookup("origin.example.test", 443)
        .await
        .err()
        .ok_or("malformed record parsed")?;
    assert_eq!(error.kind(), HttpsLookupErrorKind::MalformedRecord);
    Ok(())
}

const TYPE_CNAME: u16 = 5;
const TYPE_HTTPS: u16 = 65;
const CLASS_IN: u16 = 1;
const CLASS_CH: u16 = 3;

/// One answer record: owner, type, class, and RDATA.
type RawRecord<'a> = (&'a str, u16, u16, Vec<u8>);

fn wire_name(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in name.split('.').filter(|label| !label.is_empty()) {
        bytes.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes
}

/// Appends uncompressed answer records with a 300-second TTL.
fn push_answers(message: &mut Vec<u8>, answers: &[RawRecord<'_>]) {
    for (owner, record_type, class, rdata) in answers {
        message.extend_from_slice(&wire_name(owner));
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&class.to_be_bytes());
        message.extend_from_slice(&300_u32.to_be_bytes());
        message.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(u16::MAX).to_be_bytes());
        message.extend_from_slice(rdata);
    }
}

/// A NOERROR response to an HTTPS query for `question`.
fn response(question: &str, answers: &[RawRecord<'_>]) -> Vec<u8> {
    let mut message = vec![0, 1, 0x81, 0x80, 0, 1];
    message.extend_from_slice(
        &u16::try_from(answers.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    message.extend_from_slice(&[0, 0, 0, 0]);
    message.extend_from_slice(&wire_name(question));
    message.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    push_answers(&mut message, answers);
    message
}

fn h3_record() -> Vec<u8> {
    rdata(1, &[], &[(1, b"h3")])
}

fn owners(message: &[u8]) -> TestResult<Vec<String>> {
    let lookup = https_answers_from_message("origin.example.test", 443, message)?;
    Ok(lookup
        .answers()
        .iter()
        .map(|answer| answer.owner().to_owned())
        .collect())
}

fn lookup_error(message: &[u8]) -> TestResult<HttpsLookupErrorKind> {
    match https_answers_from_message("origin.example.test", 443, message) {
        Ok(lookup) => Err(format!("unusable response produced {lookup:?}").into()),
        Err(error) => Ok(error.kind()),
    }
}

#[test]
fn answers_at_the_end_of_the_cname_chain_are_kept_in_any_record_order() -> TestResult<()> {
    let cname_a = (
        "origin.example.test",
        TYPE_CNAME,
        CLASS_IN,
        wire_name("a.example.test"),
    );
    let cname_b = (
        "a.example.test",
        TYPE_CNAME,
        CLASS_IN,
        wire_name("b.example.test"),
    );
    let https = ("B.Example.test", TYPE_HTTPS, CLASS_IN, h3_record());
    for answers in [
        [cname_a.clone(), cname_b.clone(), https.clone()],
        [https.clone(), cname_b.clone(), cname_a.clone()],
    ] {
        let message = response("origin.example.test", &answers);
        assert_eq!(owners(&message)?, ["B.Example.test"]);
    }
    Ok(())
}

#[test]
fn an_answer_owned_by_another_name_makes_the_response_unusable() -> TestResult<()> {
    let direct = ("origin.example.test", TYPE_HTTPS, CLASS_IN, h3_record());
    let stray = ("other.example.test", TYPE_HTTPS, CLASS_IN, h3_record());
    let message = response("origin.example.test", &[direct.clone(), stray]);
    assert_eq!(lookup_error(&message)?, HttpsLookupErrorKind::Resolve);

    // A record at an intermediate alias is not at the end of the chain.
    let cname = (
        "origin.example.test",
        TYPE_CNAME,
        CLASS_IN,
        wire_name("a.example.test"),
    );
    let message = response("origin.example.test", &[cname, direct]);
    assert_eq!(lookup_error(&message)?, HttpsLookupErrorKind::Resolve);
    Ok(())
}

#[test]
fn other_classes_and_types_are_ignored() -> TestResult<()> {
    let answers = [
        ("other.example.test", TYPE_HTTPS, CLASS_CH, h3_record()),
        (
            "origin.example.test",
            TYPE_CNAME,
            CLASS_CH,
            wire_name("x.example.test"),
        ),
        ("other.example.test", 1, CLASS_IN, vec![192, 0, 2, 1]),
        ("origin.example.test", TYPE_HTTPS, CLASS_IN, h3_record()),
    ];
    let message = response("origin.example.test", &answers);
    assert_eq!(owners(&message)?, ["origin.example.test"]);
    Ok(())
}

#[test]
fn a_cname_loop_ends() -> TestResult<()> {
    let answers = [
        (
            "origin.example.test",
            TYPE_CNAME,
            CLASS_IN,
            wire_name("a.example.test"),
        ),
        (
            "a.example.test",
            TYPE_CNAME,
            CLASS_IN,
            wire_name("origin.example.test"),
        ),
        ("origin.example.test", TYPE_HTTPS, CLASS_IN, h3_record()),
    ];
    // Both aliases are consumed and the chain stops back at the query name.
    let message = response("origin.example.test", &answers);
    assert_eq!(owners(&message)?, ["origin.example.test"]);
    Ok(())
}

#[test]
fn an_undecodable_message_is_a_resolve_error() -> TestResult<()> {
    let mut message = response(
        "origin.example.test",
        &[("origin.example.test", TYPE_HTTPS, CLASS_IN, h3_record())],
    );
    message.truncate(message.len() - 1);
    assert_eq!(lookup_error(&message)?, HttpsLookupErrorKind::Resolve);
    Ok(())
}

/// Answers every query with its own question and `answers`, byte for byte.
async fn raw_dns_server(answers: Vec<RawRecord<'static>>) -> TestResult<std::net::SocketAddr> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = vec![0; 512];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            // The query carries one question and nothing after it.
            let Some(question) = buffer.get(12..length) else {
                continue;
            };
            let mut message = buffer[..2].to_vec();
            message.extend_from_slice(&[0x81, 0x80, 0, 1]);
            message.extend_from_slice(&u16::try_from(answers.len()).unwrap_or(0).to_be_bytes());
            message.extend_from_slice(&[0, 0, 0, 0]);
            message.extend_from_slice(question);
            push_answers(&mut message, &answers);
            let _ = socket.send_to(&message, peer).await;
        }
    });
    Ok(address)
}

#[tokio::test]
async fn resolver_rejects_an_answer_owned_by_another_name() -> TestResult<()> {
    // hickory accepts this response: one record answers the question, so it
    // hands back the whole answer section, stray record included.
    let address = raw_dns_server(vec![
        (
            "origin.example.test",
            TYPE_HTTPS,
            CLASS_IN,
            rdata(1, &[], &[(1, b"h2")]),
        ),
        ("other.example.test", TYPE_HTTPS, CLASS_IN, h3_record()),
    ])
    .await?;
    let resolver = HttpsRecordResolver::with_nameservers([address])?;
    let error = resolver
        .lookup("origin.example.test", 443)
        .await
        .err()
        .ok_or("a stray answer was accepted")?;
    assert_eq!(error.kind(), HttpsLookupErrorKind::Resolve);
    Ok(())
}
