use super::*;

fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let length = (body.len() as u32).to_be_bytes();
    [vec![kind], length[1..].to_vec(), body.to_vec()].concat()
}

fn ticket() -> Vec<u8> {
    // RFC 8446 4.6.1: lifetime, age_add, nonce, ticket, extensions.
    handshake(
        4,
        &[
            0, 0, 0, 60, 0, 0, 0, 1, 0, 0, 3, b'a', b'b', b'c', 0, 8, 0, 42, 0, 4, 0, 1, 0, 0,
        ],
    )
}

fn inner(early: bool, identities: &[u8], binders: &[u8]) -> Vec<u8> {
    let mut extensions = vec![0xfe, 0x0d, 0, 1, 1]; // ECH inner indication.
    if early {
        extensions.extend_from_slice(&[0, 42, 0, 0]);
    }
    let psk = [
        (identities.len() as u16).to_be_bytes().as_slice(),
        identities,
        (binders.len() as u16).to_be_bytes().as_slice(),
        binders,
    ]
    .concat();
    extensions.extend_from_slice(&[0, 41]);
    extensions.extend_from_slice(&(psk.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&psk);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    handshake(1, &body)
}

#[test]
fn inner_psk_identity_matches_the_issued_ticket_without_exposing_it() -> CaptureResult<()> {
    let issued = parse_ticket(&ticket())?;
    assert_eq!(
        issued.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(issued.max_early_data, Some(65_536));
    let identities = [0, 3, b'a', b'b', b'c', 0, 0, 0, 2];
    let binders = [vec![32], vec![0x5a; 32]].concat();
    let offered = parse_offer(&inner(true, &identities, &binders))?;
    assert!(offered.early_data);
    assert_eq!(offered.tickets, [issued.sha256]);
    let ordinary = handshake(
        1,
        &[
            vec![3, 3],
            vec![0; 32],
            vec![0, 0, 2, 0x13, 1, 1, 0, 0, 5, 0xfe, 0x0d, 0, 1, 1],
        ]
        .concat(),
    );
    assert_eq!(
        parse_offer(&ordinary)?,
        Offer {
            early_data: false,
            tickets: Vec::new()
        }
    );
    Ok(())
}

#[test]
fn malformed_ticket_and_psk_vectors_fail_instead_of_creating_a_link() {
    let valid = ticket();
    for end in 0..valid.len() {
        assert!(
            parse_ticket(&valid[..end]).is_err(),
            "accepted ticket prefix {end}"
        );
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(parse_ticket(&trailing).is_err());
    let duplicate = handshake(
        4,
        &[
            0, 0, 0, 60, 0, 0, 0, 1, 0, 0, 1, b'x', 0, 16, 0, 42, 0, 4, 0, 1, 0, 0, 0, 42, 0, 4, 0,
            1, 0, 0,
        ],
    );
    assert!(parse_ticket(&duplicate).is_err());
    let identity = [0, 3, b'a', b'b', b'c', 0, 0, 0, 2];
    for binder in [Vec::new(), vec![1, 0], [vec![32], vec![0; 31]].concat()] {
        assert!(parse_offer(&inner(true, &identity, &binder)).is_err());
    }
    assert!(parse_offer(&inner(true, &[], &[])).is_err());
    let too_many = identity.repeat(9);
    let binders = [vec![32], vec![0; 32]].concat().repeat(9);
    assert!(parse_offer(&inner(true, &too_many, &binders)).is_err());
    assert!(Cursor::message(&vec![0; 128 * 1024 + 1], 4).is_err());
}

#[test]
fn callback_messages_remain_with_their_actual_ssl_owner_and_stay_bounded() -> CaptureResult<()> {
    let run = Run::new(Mode::EarlyAccept)?;
    let context = SslContextBuilder::new(SslMethod::tls())?.build();
    let mut first = Ssl::new(&context)?;
    let mut second = Ssl::new(&context)?;
    run.configure(&mut first, 4, b"first outer records");
    run.configure(&mut second, 9, b"second outer records");
    let issued = ticket();
    let event = SslMessage {
        direction: SslMessageDirection::Write,
        version: 0x304,
        content_type: SslMessageContentType::HANDSHAKE,
        data: &issued,
    };
    run.message(
        *first
            .ex_data(run.index)
            .ok_or("first SSL identity missing")?,
        event,
    );
    {
        let state = run.lock();
        assert_eq!(state.connections[&4].tickets.len(), 1);
        assert!(state.connections[&9].tickets.is_empty());
    }
    for _ in 0..MAX_MESSAGES {
        run.message(
            *first
                .ex_data(run.index)
                .ok_or("first SSL identity missing")?,
            event,
        );
    }
    assert_eq!(run.lock().connections[&4].tickets.len(), MAX_MESSAGES);
    assert!(run.write(&mut Vec::new()).is_err());
    Ok(())
}

#[test]
fn a_probe_without_early_data_is_recorded_without_promoting_it_to_an_offer() -> CaptureResult<()> {
    let run = Run::new(Mode::EarlyAccept)?;
    let context = SslContextBuilder::new(SslMethod::tls())?.build();
    run.configure(&mut Ssl::new(&context)?, 7, b"outer");
    let mut bytes = Vec::new();
    run.write(&mut bytes)?;
    let output = String::from_utf8(bytes)?;
    assert!(output.contains("resumption_seed_slot=none\n"));
    assert!(output.contains("resumption_served_probe_gets=0\n"));
    assert!(output.contains("resumption_slot_7_early_plaintext_bytes=0\n"));
    assert!(!output.contains("early_data_offered=true"));
    assert!(!output.contains("outer\n"));
    Ok(())
}

#[test]
fn resumption_arguments_preserve_first_contact_and_reject_other_transports() -> CaptureResult<()> {
    let metadata = [
        "accept",
        "127.0.0.1:0",
        "Firefox",
        "158",
        "Windows",
        "DoH",
        "headful",
        "firefox",
    ];
    let parse = |values: Vec<&str>| Arguments::parse(values.into_iter().map(str::to_owned));
    assert!(parse(metadata.to_vec())?.resumption.is_none());
    for name in ["early-accept", "early-reject", "ech-retry"] {
        let args = [vec!["--resumption", name], metadata.to_vec()].concat();
        assert_eq!(parse(args)?.resumption, Some(name.parse()?));
    }
    assert!(
        parse(
            [
                vec!["--quic", "--resumption", "early-accept"],
                metadata.to_vec()
            ]
            .concat()
        )
        .is_err()
    );
    let mut rejected = metadata;
    rejected[0] = "reject";
    assert!(parse([vec!["--resumption", "early-accept"], rejected.to_vec()].concat()).is_err());
    assert!(parse(vec!["--resumption", "unknown"]).is_err());
    assert!(request_path(b"GET /seed HTTP/1.1\r\n\r\n").is_ok());
    assert!(request_path(b"POST /seed HTTP/1.1\r\n\r\n").is_err());
    assert!(request_path(b"GET /resume?secret=x HTTP/1.1\r\n\r\n").is_err());
    Ok(())
}

#[path = "tests/native.rs"]
mod native;
