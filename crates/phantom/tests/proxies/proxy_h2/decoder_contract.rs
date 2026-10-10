use std::panic::{AssertUnwindSafe, catch_unwind};

use http::Response;
use tokio::{
    io::AsyncWriteExt,
    time::{Duration, timeout},
};

use super::{
    TestResult, assert_proxy_authorization_indexed, captured_h2_blocks, header_blocks,
    hpack_integer, pseudo_names,
};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const CREDENTIAL: &[u8] = b"Basic YWxpY2U6c2VjcmV0";
const CREDENTIAL_LENGTH: u8 = 22;

type DecodedFields = Vec<(String, Vec<u8>)>;

fn malformed_hex(hex: &str) -> TestResult<()> {
    let fixture = format!(
        "run_0_connection_0_headers_0_field_count=1\nrun_0_connection_0_headers_0_field_0=repr:literal,name_hex:{hex},value_hex:none\n"
    );
    let outcome = catch_unwind(AssertUnwindSafe(|| captured_h2_blocks(&fixture)));
    let decoded = outcome.map_err(|_| "capture decoder panicked on malformed hex")?;
    assert!(decoded.is_err(), "capture decoder accepted malformed hex");
    Ok(())
}

#[test]
fn odd_hex_is_a_recoverable_error() -> TestResult<()> {
    malformed_hex("6")
}

#[test]
fn non_ascii_hex_is_a_recoverable_error() -> TestResult<()> {
    malformed_hex("aéa")
}

#[test]
fn signed_hex_is_a_recoverable_error() -> TestResult<()> {
    malformed_hex("+1")
}

#[test]
fn short_priority_payload_is_a_recoverable_error() -> TestResult<()> {
    let mut wire = PREFACE.to_vec();
    wire.extend_from_slice(&[0, 0, 0, 1, 0x24, 0, 0, 0, 1]);
    let outcome = catch_unwind(|| header_blocks(&wire));
    assert!(outcome.is_ok(), "short priority frame panicked");
    assert!(
        outcome
            .map_err(|_| "short priority frame panicked")?
            .is_err(),
        "short priority frame was accepted"
    );
    Ok(())
}

#[test]
fn a_partial_frame_header_is_rejected() -> TestResult<()> {
    let mut wire = PREFACE.to_vec();
    wire.extend_from_slice(&[0, 0, 0, 1]);
    assert!(
        header_blocks(&wire).is_err(),
        "partial frame header was accepted as complete"
    );
    Ok(())
}

#[test]
fn overflowing_hpack_integer_is_a_recoverable_error() -> TestResult<()> {
    let mut block = vec![0x7f];
    block.extend_from_slice(&[0xff; 12]);
    block.push(0);
    let outcome = catch_unwind(|| hpack_integer(&block, &mut 0, 7));
    assert!(outcome.is_ok(), "overflowing HPACK integer panicked");
    assert!(
        outcome
            .map_err(|_| "overflowing HPACK integer panicked")?
            .is_err(),
        "overflowing HPACK integer was accepted"
    );
    Ok(())
}

#[test]
fn a_truncated_pseudo_value_is_rejected() -> TestResult<()> {
    assert!(
        pseudo_names(&[0x01, 5, b'a']).is_err(),
        "truncated pseudo value appeared complete"
    );
    Ok(())
}

#[test]
fn valid_capture_and_frame_inputs_are_kept() -> TestResult<()> {
    let fixture = "run_0_connection_0_headers_0_field_count=1\nrun_0_connection_0_headers_0_field_0=repr:literal,name_hex:3a6d6574686f64,value_hex:474554\n";
    let blocks = captured_h2_blocks(fixture)?;
    assert_eq!(blocks.len(), 1);
    assert_eq!(
        blocks[0].pseudo.get(":method").map(String::as_str),
        Some("GET")
    );

    let mut wire = PREFACE.to_vec();
    wire.extend_from_slice(&[0, 0, 3, 1, 4, 0, 0, 0, 1, 0x82, 0x86, 0x84]);
    assert_eq!(header_blocks(&wire)?, [&[0x82, 0x86, 0x84][..]]);
    assert_eq!(
        pseudo_names(&[0x82, 0x86, 0x84])?,
        [":method", ":scheme", ":path"]
    );
    assert_eq!(hpack_integer(&[0x7f, 1], &mut 0, 7)?, 128);
    Ok(())
}

fn replay() -> Vec<u8> {
    let mut block = vec![0x71, CREDENTIAL_LENGTH];
    block.extend_from_slice(CREDENTIAL);
    block
}

fn literal_remembered() -> Vec<u8> {
    let mut block = vec![0, 19];
    block.extend_from_slice(b"proxy-authorization");
    block.push(CREDENTIAL_LENGTH);
    block.extend_from_slice(CREDENTIAL);
    block
}

// The actual resolved server decodes both blocks in one connection/table.
async fn decoded_credentials(replay: &[u8], remembered: &[u8]) -> TestResult<Vec<DecodedFields>> {
    let (mut writer, reader) = tokio::io::duplex(4096);
    let mut server = crate::support::tunnel_proxy::ConnectionPeer::spawn(async move {
        let mut connection = ::http2::server::handshake(reader).await?;
        let mut values = Vec::new();
        let mut ordinary = Vec::new();
        for _ in 0..2 {
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("HPACK peer missed request")??;
            assert_eq!(request.method(), "GET");
            ordinary.push(
                request
                    .extensions()
                    .get::<::http2::ext::OrderedHeaders>()
                    .ok_or("actual decoder omitted ordered fields")?
                    .as_slice()
                    .iter()
                    .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                    .collect::<Vec<_>>(),
            );
            values.push(
                request
                    .headers()
                    .get("proxy-authorization")
                    .ok_or("HPACK peer missed credential")?
                    .as_bytes()
                    .to_vec(),
            );
            respond.send_response(Response::new(()), true)?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((values, ordinary))
    });
    let mut wire = PREFACE.to_vec();
    wire.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    for (stream, credential) in [(1, replay), (3, remembered)] {
        let mut block = vec![0x82, 0x86, 0x84, 0x01, 11];
        block.extend_from_slice(b"origin.test");
        block.extend_from_slice(credential);
        let length = u16::try_from(block.len())?.to_be_bytes();
        wire.extend_from_slice(&[0, length[0], length[1], 1, 5, 0, 0, 0, stream]);
        wire.extend_from_slice(&block);
    }
    writer.write_all(&wire).await?;
    let result = timeout(Duration::from_secs(5), &mut server).await;
    let (values, ordinary) = match result {
        Ok(joined) => joined??,
        Err(elapsed) => {
            return crate::support::tunnel_proxy::finish_with_cleanup(
                Err(elapsed.into()),
                server.stop().await,
            );
        }
    };
    assert_eq!(values, [CREDENTIAL.to_vec(), CREDENTIAL.to_vec()]);
    assert_eq!(ordinary.len(), 2);
    Ok(ordinary)
}

#[tokio::test]
async fn literal_remembered_authorization_does_not_prove_dynamic_indexing() -> TestResult<()> {
    let replay = replay();
    let remembered = literal_remembered();
    let ordinary = decoded_credentials(&replay, &remembered).await?;

    assert!(
        assert_proxy_authorization_indexed(
            &[&[], &replay, &remembered],
            "literal counterexample",
            &ordinary[1]
        )
        .is_err(),
        "remembered literal without indexing satisfied the dynamic-table oracle"
    );
    Ok(())
}

#[tokio::test]
async fn actual_dynamic_entry_is_accepted_after_its_replay() -> TestResult<()> {
    let replay = replay();
    let remembered = [0xbe];
    let ordinary = decoded_credentials(&replay, &remembered).await?;

    assert_proxy_authorization_indexed(
        &[&[], &replay, &remembered],
        "dynamic positive",
        &ordinary[1],
    )
}

#[tokio::test]
async fn an_unrelated_dynamic_entry_does_not_prove_credential_indexing() -> TestResult<()> {
    let mut replay = replay();
    replay.extend_from_slice(&[0x40, 9]);
    replay.extend_from_slice(b"x-control");
    replay.push(5);
    replay.extend_from_slice(b"other");
    let mut remembered = literal_remembered();
    remembered.push(0xbe);
    let ordinary = decoded_credentials(&replay, &remembered).await?;
    let expected = vec![
        ("proxy-authorization".to_owned(), CREDENTIAL.to_vec()),
        ("x-control".to_owned(), b"other".to_vec()),
    ];
    assert_eq!(ordinary[0], expected);
    assert_eq!(ordinary[1], expected);
    assert!(
        super::hpack_representations(&remembered)?.contains(&(super::Representation::Indexed, 62)),
        "the actual remembered block lacked its unrelated dynamic entry"
    );
    assert!(
        assert_proxy_authorization_indexed(
            &[&[], &replay, &remembered],
            "unrelated dynamic counterexample",
            &ordinary[1]
        )
        .is_err(),
        "a literal credential plus an unrelated dynamic entry satisfied the credential oracle"
    );
    Ok(())
}
