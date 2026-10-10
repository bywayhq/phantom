use super::*;

/// The raw peer keeps its control stream open so a quiet observation cannot
/// be satisfied by accidentally closing that critical stream.
struct RawPeer {
    _client_endpoint: quinn::Endpoint,
    _server_endpoint: quinn::Endpoint,
    client: quinn::Connection,
    server: h3::server::Connection<h3_quinn::Connection, Bytes>,
    control: quinn::SendStream,
}

impl RawPeer {
    async fn connect() -> TestResult<Self> {
        Self::connect_with_control(&[0x00, 0x04, 0x00]).await
    }

    async fn connect_with_control(bytes: &[u8]) -> TestResult<Self> {
        let identity = TestIdentity::generate()?;
        let server_endpoint = h3_support::quic_server(
            server_config(&identity, false)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(identity.root_der.clone()))?;
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut client_endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            phantom_testkit::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?,
            Arc::new(quinn::TokioRuntime),
        )?;
        client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        let connecting = client_endpoint.connect(server_endpoint.local_addr()?, "127.0.0.1")?;
        let (client, server_quic) = tokio::try_join!(
            async { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connecting.await?) },
            async {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    server_endpoint
                        .accept()
                        .await
                        .ok_or("server closed")?
                        .await?,
                )
            }
        )?;
        let server = h3::server::Connection::new(h3_quinn::Connection::new(server_quic)).await?;
        let mut control = client.open_uni().await?;
        // Control stream type, SETTINGS type, empty SETTINGS payload.
        control.write_all(bytes).await?;
        Ok(Self {
            _client_endpoint: client_endpoint,
            _server_endpoint: server_endpoint,
            client,
            server,
            control,
        })
    }
}

#[tokio::test]
async fn an_open_connection_without_another_request_passes_the_quiet_window() -> TestResult<()> {
    bounded(async {
        let mut peer = RawPeer::connect().await?;
        expect_no_second_request(&mut peer.server).await?;
        // This proves only the fixture's finite window, not future absence.
        assert!(peer.client.close_reason().is_none());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_explicit_h3_no_error_close_passes_the_absence_check() -> TestResult<()> {
    bounded(async {
        let mut peer = RawPeer::connect().await?;
        peer.client.close(
            quinn::VarInt::from_u32(0x100),
            b"intentional clean HTTP/3 close",
        );
        expect_no_second_request(&mut peer.server).await
    })
    .await
}

#[tokio::test]
async fn an_unexpected_application_close_fails_the_absence_check() -> TestResult<()> {
    bounded(async {
        let mut peer = RawPeer::connect().await?;
        peer.client
            .close(quinn::VarInt::from_u32(0x102), b"injected internal error");
        let error = expect_no_second_request(&mut peer.server)
            .await
            .err()
            .ok_or("an HTTP/3 internal error satisfied the absence check")?;
        let error = error.downcast::<h3::error::ConnectionError>()?;
        assert!(matches!(
            *error,
            h3::error::ConnectionError::Remote(
                h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code },
                ..
            ) if error_code == 0x102
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_forbidden_control_frame_fails_the_absence_check() -> TestResult<()> {
    bounded(async {
        let mut peer = RawPeer::connect().await?;
        // An empty DATA frame is forbidden on the HTTP/3 control stream.
        peer.control.write_all(&[0x00, 0x00]).await?;
        let error = expect_no_second_request(&mut peer.server)
            .await
            .err()
            .ok_or("a forbidden control frame satisfied the absence check")?;
        let error = error.downcast::<h3::error::ConnectionError>()?;
        assert!(matches!(
            *error,
            h3::error::ConnectionError::Local {
                error: h3::error::LocalError::Application { code, .. },
                ..
            } if code == h3::error::Code::H3_FRAME_UNEXPECTED
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_invalid_settings_payload_fails_the_absence_check() -> TestResult<()> {
    bounded(async {
        // HTTP/2's reserved SETTINGS identifier 0x02 is forbidden in HTTP/3.
        let mut peer = RawPeer::connect_with_control(&[0x00, 0x04, 0x02, 0x02, 0x00]).await?;
        let error = expect_no_second_request(&mut peer.server)
            .await
            .err()
            .ok_or("an invalid SETTINGS payload satisfied the absence check")?;
        let error = error.downcast::<h3::error::ConnectionError>()?;
        assert!(matches!(
            *error,
            h3::error::ConnectionError::Local {
                error: h3::error::LocalError::Application { code, .. },
                ..
            } if code == h3::error::Code::H3_SETTINGS_ERROR
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_quic_zero_close_is_not_an_h3_clean_close() -> TestResult<()> {
    bounded(async {
        let mut peer = RawPeer::connect().await?;
        peer.client
            .close(quinn::VarInt::from_u32(0), b"QUIC zero is not H3_NO_ERROR");
        let error = expect_no_second_request(&mut peer.server)
            .await
            .err()
            .ok_or("a QUIC zero close satisfied the HTTP/3 absence check")?;
        let error = error.downcast::<h3::error::ConnectionError>()?;
        assert!(matches!(
            *error,
            h3::error::ConnectionError::Remote(
                h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code: 0 },
                ..
            )
        ));
        Ok(())
    })
    .await
}
