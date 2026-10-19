use super::*;
use phantom::profile::{RequestField, RequestTemplate};
use phantom::{RequestErrorKind, StreamingMultipartBody, StreamingMultipartPart};

#[tokio::test]
async fn multipart_reader_reaches_http1_and_http2_with_matching_type_and_no_length()
-> TestResult<()> {
    for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
        timeout(BUDGET, async {
            let identity = TestIdentity::generate()?;
            let client = Client::builder(
                ClientProfile::new(tls_settings())
                    .with_http1(chrome::v154_http1())
                    .with_http2(chrome::v154_http2()),
            )
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
            let body = StreamingMultipartBody::new(
                "upload-boundary",
                [
                    StreamingMultipartPart::text("na\"me\n", "line1\nline2", 1024)?,
                    StreamingMultipartPart::reader("file", std::io::Cursor::new(b"\x00\xff"))?
                        .with_filename("file.txt")?
                        .with_content_type("text/plain")?,
                ],
                4096,
            )?;
            let expected = PreparedRequestBody::multipart(
                "upload-boundary",
                [
                    MultipartPart::text("na\"me\n", "line1\nline2")?,
                    MultipartPart::bytes("file", b"\x00\xff")?
                        .with_filename("file.txt")?
                        .with_content_type("text/plain")?,
                ],
                4096,
            )?;
            let fields = vec![
                RequestField::caller("content-type"),
                RequestField::caller("content-length"),
                RequestField::literal("x-after", "last"),
            ];
            let template = PreparedRequestTemplate::new(RequestTemplate {
                http1_fields: fields.clone(),
                http2_fields: fields,
                http3_fields: None,
                http2_priority: None,
                requested_client_hint_placement: false,
                restarts_for_connection_accept_ch: false,
            })?;
            let (url, stop, server) = serve_upload(&identity, protocol).await?;
            let observed = collect_upload(
                async {
                    let response = client
                        .request(protocol, Method::POST, &url)?
                        .template(&template)
                        .multipart_body(body)
                        .send()
                        .await?;
                    assert_eq!(response.status(), StatusCode::NO_CONTENT);
                    response.into_body().collect_with_limit(0).await?;
                    Ok(())
                },
                stop,
                server,
            )
            .await?;
            assert_eq!(observed.method, b"POST");
            assert_eq!(observed.value("content-length"), None);
            assert_eq!(
                observed.value("content-type"),
                Some(expected.content_type().as_bytes())
            );
            assert_eq!(observed.body.as_slice(), expected.bytes().as_ref());
            let names: Vec<_> = observed
                .fields
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            assert!(names.windows(2).any(|pair| pair == ["content-type", "x-after"]));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn multipart_requires_content_type_placement_before_connecting() -> TestResult<()> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/upload", listener.local_addr()?);
        let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
        let body = StreamingMultipartBody::new("boundary", [], 1024)?;
        let error = client
            .request(HttpProtocol::Http1, Method::POST, &url)?
            .multipart_body(body)
            .send()
            .await
            .err()
            .ok_or("missing content-type placement was accepted")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
        assert!(
            timeout(std::time::Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn multipart_does_not_replay_a_consumed_reader_on_307() -> TestResult<()> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/upload", listener.local_addr()?);
        let location = format!("http://{}/second", destination.local_addr()?);
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let body = StreamingMultipartBody::new(
            "boundary",
            [StreamingMultipartPart::reader("file", std::io::Cursor::new(b"contents"))?],
            1024,
        )?;
        let server = ConnectionPeer::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = BufReader::new(stream);
            let observed = read_upload(&mut stream).await?;
            stream.get_mut().write_all(format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ).as_bytes()).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });
        let operation = async {
            let error = client
                .request(HttpProtocol::Http1, Method::POST, &url)?
                .header(RequestHeader::new("content-type", body.content_type()))
                .multipart_body(body)
                .send()
                .await
                .err()
                .ok_or("consumed multipart reader was replayed")?;
            assert_eq!(error.kind(), RequestErrorKind::RequestBody);
            assert!(
                timeout(std::time::Duration::from_millis(30), destination.accept())
                    .await
                    .is_err()
            );
            Ok(())
        }.await;
        let observed = finish_prepared_peer(operation, server).await?;
        assert!(observed.body.ends_with(b"contents\r\n--boundary--\r\n"));
        Ok(())
    })
    .await?
}
