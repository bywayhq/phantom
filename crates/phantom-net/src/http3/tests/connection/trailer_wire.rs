use phantom_profile::Http3QpackEncoding;

use crate::request::{RequestBody, RequestHeader, RequestTrailerName};

use super::{
    Bytes, Frame, HeaderMap, HeaderValue, Request, TEST_SERVER_NAME, TEST_TIMEOUT, TestBody,
    TestIdentity, TestResult, client_config, collect_body, join_server, oneshot, server_endpoint,
    test_settings, timeout,
};

#[tokio::test(flavor = "current_thread")]
async fn stateless_trailers_preserve_cross_name_order_and_never_indexed_wire_marker()
-> TestResult<()> {
    for body_produced in [false, true] {
        timeout(
            TEST_TIMEOUT,
            check_trailer_wire(Http3QpackEncoding::Stateless, body_produced),
        )
        .await
        .map_err(|_| "stateless trailer wire test timed out")??;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn dynamic_qpack_trailers_preserve_order_sensitivity_and_connection_encoder_state()
-> TestResult<()> {
    for body_produced in [false, true] {
        timeout(
            TEST_TIMEOUT,
            check_trailer_wire(Http3QpackEncoding::Dynamic, body_produced),
        )
        .await
        .map_err(|_| "dynamic QPACK trailer wire test timed out")??;
    }
    Ok(())
}

async fn check_trailer_wire(encoding: Http3QpackEncoding, body_produced: bool) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let connection = incoming.await?;
        let mut control = connection.open_uni().await?;
        // SETTINGS: QPACK capacity 4096, blocked streams 16 (RFC 9114/9204).
        control.write_all(&[0, 4, 5, 1, 0x50, 0, 7, 16]).await?;
        let mut server_encoder = connection.open_uni().await?;
        server_encoder.write_all(&[2]).await?;
        let mut server_decoder = connection.open_uni().await?;
        server_decoder.write_all(&[3]).await?;

        let mut client_control = None;
        let mut client_encoder = None;
        let mut client_decoder = None;
        for _ in 0..3 {
            let mut stream = connection.accept_uni().await?;
            match read_varint(&mut stream).await? {
                0 => assert!(client_control.replace(stream).is_none()),
                2 => assert!(client_encoder.replace(stream).is_none()),
                3 => assert!(client_decoder.replace(stream).is_none()),
                _ => return Err("unexpected client unidirectional stream".into()),
            }
        }
        let mut client_encoder = client_encoder.ok_or("client encoder stream missing")?;
        assert!(client_control.is_some() && client_decoder.is_some());
        let (mut response, mut request) = connection.accept_bi().await?;
        let initial = read_frame(&mut request, 1).await?;
        assert_eq!(read_frame(&mut request, 0).await?, b"data");
        let trailers = read_frame(&mut request, 1).await?;
        assert_eq!(request.read_chunk(1, true).await?, None);

        if encoding == Http3QpackEncoding::Dynamic {
            // Initial :authority a is insertion 1. Trailers insert a:1 and
            // a:3 as entries 2/3, while sensitive b:2 never enters the table.
            // Required insert count 3 is encoded as 4, Base 3 as delta 0.
            assert_eq!(initial, [2, 0, 0xd4, 0xd7, 0x80, 0xc1]);
            assert_eq!(trailers, [4, 0, 0x81, 0x39, 0x8f, 0x81, 0x17, 0x80]);
            let mut instructions = [0; 13];
            client_encoder.read_exact(&mut instructions).await?;
            assert_eq!(
                instructions,
                [
                    0x3f, 0xe1, 0x1f, // Set capacity 4096.
                    0xc0, 1, b'a', // Insert :authority a using static name 0.
                    0x41, b'a', 1, b'1', // Insert a:1 with literal name.
                    0x80, 1, b'3', // Insert a:3 using dynamic name 0.
                ]
            );
        } else {
            assert_eq!(encoding, Http3QpackEncoding::Stateless);
            // RFC 9204 section 4.5.6: literal a:1, never-indexed literal
            // b:2 (N=1), literal a:3. RFC 7541 appendix B gives the strings:
            // a=1f, b=8f, 1=0f, 2=17, 3=67, with EOS padding.
            assert_eq!(
                trailers,
                [
                    0, 0, 0x29, 0x1f, 0x81, 0x0f, 0x39, 0x8f, 0x81, 0x17, 0x29, 0x1f, 0x81, 0x67,
                ]
            );
        }
        // Stateless :status 200 response, followed by FIN.
        response.write_all(&[1, 3, 0, 0, 0xd9]).await?;
        response.finish()?;
        let _ = done_received.await;
        connection.close(quinn::VarInt::from_u32(0), b"");
        drop((
            control,
            server_encoder,
            server_decoder,
            client_control,
            client_encoder,
            client_decoder,
        ));
        Ok(())
    });

    // Eager critical streams and a fixed stream order keep the raw peer bounded.
    // Stateless is the normal test profile; Dynamic selects the shared encoder.
    let mut settings = test_settings();
    settings.qpack_encoding = encoding;
    let connection =
        crate::http3::connect_direct(address, TEST_SERVER_NAME, client, &settings).await?;
    let (body, trailers) = wire_input(body_produced);
    let prepared = crate::http3::request::prepare_request_body_with_trailers(
        Request::post("https://a/").body(())?,
        Some(body),
        trailers,
    )?;
    let response = connection.send_prepared_request(prepared).await?;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(collect_body(response.into_body()).await?.is_empty());
    let _ = client_done.send(());
    join_server(server).await
}

fn wire_input(body_produced: bool) -> (RequestBody, Vec<RequestHeader>) {
    if !body_produced {
        return (
            RequestBody::streaming(TestBody::data([Bytes::from_static(b"data")])),
            vec![
                RequestHeader::new("a", "1"),
                RequestHeader::new("b", "2").sensitive(),
                RequestHeader::new("a", "3"),
            ],
        );
    }
    let mut trailers = HeaderMap::new();
    let mut sensitive = HeaderValue::from_static("2");
    sensitive.set_sensitive(true);
    trailers.append("a", HeaderValue::from_static("1"));
    trailers.insert("b", sensitive);
    trailers.append("a", HeaderValue::from_static("3"));
    (
        RequestBody::streaming_with_trailers(
            TestBody {
                frames: [
                    Ok(Frame::data(Bytes::from_static(b"data"))),
                    Ok(Frame::trailers(trailers)),
                ]
                .into(),
                exact_length: None,
            },
            vec![
                RequestTrailerName::new("a"),
                RequestTrailerName::new("b"),
                RequestTrailerName::new("a"),
            ],
        ),
        Vec::new(),
    )
}

async fn read_frame(stream: &mut quinn::RecvStream, expected_type: u64) -> TestResult<Vec<u8>> {
    assert_eq!(read_varint(stream).await?, expected_type);
    let length = usize::try_from(read_varint(stream).await?)?;
    assert!(length <= 1024, "unexpected oversized test frame");
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn read_varint(stream: &mut quinn::RecvStream) -> TestResult<u64> {
    let mut first = [0];
    stream.read_exact(&mut first).await?;
    let width = 1 << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    for _ in 1..width {
        let mut next = [0];
        stream.read_exact(&mut next).await?;
        value = (value << 8) | u64::from(next[0]);
    }
    Ok(value)
}
