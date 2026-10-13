//! Prepared bytes keep HTTP/1.1 trailer framing without an implicit length.

use std::{error::Error, net::Ipv4Addr};

use phantom::{
    RequestHeader, StatusCode,
    profile::{RequestField, RequestTemplate},
};
use phantom_net::http1::{Http1Error, Http1TlsError};

use super::*;

fn upload_template() -> Result<PreparedRequestTemplate, phantom::profile::InvalidRequestTemplate> {
    PreparedRequestTemplate::new(RequestTemplate {
        http1_fields: vec![
            RequestField::caller("Content-Type"),
            RequestField::caller("Content-Length"),
        ],
        http2_fields: vec![
            RequestField::caller("content-type"),
            RequestField::caller("content-length"),
        ],
        http3_fields: None,
        http2_priority: None,
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    })
}

#[tokio::test]
async fn prepared_bytes_with_trailers_use_chunked_framing_without_length() -> TestResult {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let deadline = Instant::now() + BUDGET;
        let client = Client::builder(profile()).build()?;
        let prepared = upload_template()?;
        let body = PreparedRequestBody::form([("a", "b")], 128)?;

        let peer = ConnectionPeer::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = BufReader::new(stream);
            let head =
                capture_request_head(&mut stream, deadline, CaptureLimits::new(8192, 4096, 64))
                    .await?;
            assert!(
                !head
                    .headers()
                    .iter()
                    .any(|field| field.name().eq_ignore_ascii_case(b"content-length"))
            );

            let transfer = head
                .headers()
                .iter()
                .find(|field| field.name().eq_ignore_ascii_case(b"transfer-encoding"))
                .ok_or("chunked framing absent")?;
            assert_eq!(
                std::str::from_utf8(transfer.value_bytes())?.trim(),
                "chunked"
            );

            let expected = b"3\r\na=b\r\n0\r\nx-upload-check: done\r\n\r\n";
            let mut body = vec![0; expected.len()];
            stream.read_exact(&mut body).await?;
            assert_eq!(body, expected);

            stream
                .get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let operation = async {
            let response = client
                .request(
                    HttpProtocol::Http1,
                    Method::POST,
                    &format!("http://{address}/upload"),
                )?
                .template(&prepared)
                .prepared_body(body)
                .trailers(vec![RequestHeader::new("x-upload-check", "done")])
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            Ok(())
        }
        .await;

        finish_prepared_peer(operation, peer).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await?
}

#[tokio::test]
async fn explicit_length_with_trailers_keeps_the_typed_framing_error() -> TestResult {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let client = Client::builder(profile()).build()?;
        let error = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("http://{address}/upload"),
            )?
            .template(&upload_template()?)
            .header(RequestHeader::new("Content-Length", "3"))
            .prepared_body(PreparedRequestBody::form([("a", "b")], 128)?)
            .trailers(vec![RequestHeader::new("x-upload-check", "done")])
            .send()
            .await
            .err()
            .ok_or("conflicting length and trailers succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Http1);
        let transport = error
            .source()
            .and_then(|cause| cause.downcast_ref::<Http1TlsError>())
            .ok_or("typed HTTP/1.1 source missing")?;
        assert!(matches!(
            transport,
            Http1TlsError::Http1(Http1Error::RequestTrailersWithContentLength { .. })
        ));
        assert!(
            timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await?
}
