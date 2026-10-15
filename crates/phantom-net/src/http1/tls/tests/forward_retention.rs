//! Real plaintext proxy sockets remain request-free until the caller sends.
use super::{
    TEST_TIMEOUT, TestIdentity, TestResult, loopback_listener, read_plaintext_head, test_connector,
};
use crate::{
    http1::Http1TlsError,
    request::{AbsoluteForm, RequestHeader},
    route::Endpoint,
    tcp::{AddressFamily, AddressFamilyMemory},
};
use http::Method;
use http_body_util::BodyExt;
use std::io;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

#[tokio::test]
async fn a_forward_opening_is_quiet_learns_proxy_family_and_sends_current_ordered_fields()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?.with_tcp_settings(&phantom_profile::browser::firefox::v157_tcp());
        let (address, listener) = loopback_listener().await?;
        let family = AddressFamilyMemory::default();
        let (connection, slower) = connector.connect_forward_retaining(Endpoint { host: "127.0.0.1", port: address.port() }, &family).await?;
        assert!(slower.is_none());
        let (mut peer, _) = listener.accept().await?;
        let mut byte = [0];
        assert!(matches!(peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(family.family(), Some(AddressFamily::Ipv4));
        let request = async {
            let response = connection.send_forward_request(Method::GET, AbsoluteForm::parse("http://target.invalid/current")?, vec![
                RequestHeader::new("Host", "target.invalid"),
                RequestHeader::new("X-Claim", "current"),
                RequestHeader::new("Proxy-Authorization", "Basic dXNlcjpzZWNyZXQ="),
            ], None).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            TestResult::Ok(())
        };
        let proxy = async {
            assert_eq!(read_plaintext_head(&mut peer).await?, b"GET http://target.invalid/current HTTP/1.1\r\nHost: target.invalid\r\nX-Claim: current\r\nProxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n");
            peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(request, proxy)?;
        drop(connection);
        assert_eq!(peer.read(&mut byte).await?, 0);
        Ok(())
    }).await?
}

#[tokio::test]
async fn dropping_a_forward_opening_sends_no_request_or_credentials() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?
            .with_tcp_settings(&phantom_profile::browser::firefox::v157_tcp());
        let (address, listener) = loopback_listener().await?;
        let family = AddressFamilyMemory::default();
        let (connection, slower) = connector
            .connect_forward_retaining(
                Endpoint {
                    host: "127.0.0.1",
                    port: address.port(),
                },
                &family,
            )
            .await?;
        let (mut peer, _) = listener.accept().await?;
        drop(slower);
        drop(connection);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_failed_forward_opening_preserves_the_forward_proxy_error_category() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        drop(listener);
        let result = connector
            .connect_forward_retaining(
                Endpoint {
                    host: "127.0.0.1",
                    port: address.port(),
                },
                &AddressFamilyMemory::default(),
            )
            .await;
        assert!(matches!(result, Err(Http1TlsError::ForwardProxyConnect(_))));
        Ok(())
    })
    .await?
}
