use super::*;

#[tokio::test]
async fn low_level_socket_policies_and_proxy_openings_cannot_bypass_the_callback() -> TestResult<()>
{
    use phantom_net::{
        SourceBinding,
        host_resolver::HostResolver,
        http1::{Http1TlsConnector, Http1TlsError},
        route::{Endpoint, Http1Route, HttpConnectRoute, OriginRoute, ProxyTransport, TcpRoute},
        tcp::AddressFamilyMemory,
    };

    let (connector, _peers, calls) = connector();
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_tcp_connector(connector);
    let endpoint = Endpoint {
        host: "unresolved.invalid",
        port: 4321,
    };
    for connector in [
        connector.clone().with_source_binding(SourceBinding::new()),
        connector.clone().with_host_resolver(HostResolver::new()),
    ] {
        let error = connector
            .connect(Http1Route::Origin(OriginRoute::Plaintext {
                tcp: TcpRoute::Direct(endpoint),
                family: None,
            }))
            .await
            .err()
            .ok_or("conflicting socket policy was accepted")?;
        let Http1TlsError::Connect(source) = error else {
            return Err("socket-policy conflict lost its I/O cause".into());
        };
        assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
    }
    let family = AddressFamilyMemory::default();
    let error = connector
        .open_http_connect_retaining(
            HttpConnectRoute {
                proxy: ProxyTransport::Tcp(endpoint),
                authority: "example.com:443",
                headers: &[],
                credentials: None,
                speculative_tls: false,
            },
            "example.com",
            &family,
        )
        .await
        .err()
        .ok_or("proxy opening was accepted")?;
    let Http1TlsError::Connect(source) = error else {
        return Err("proxy rejection lost its I/O cause".into());
    };
    assert_eq!(source.kind(), io::ErrorKind::Unsupported);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn ticket_snapshots_cannot_cross_an_unidentified_custom_route() -> TestResult<()> {
    let (connector, _peers, calls) = connector();
    let custom = builder(connector).build()?;
    let native = Client::builder(ClientProfile::new(chrome::v154_tcp_tls())).build()?;
    let key = [7; 32];
    let empty = native.export_session_tickets(&key)?;
    assert_eq!(
        custom
            .export_session_tickets(&key)
            .err()
            .ok_or("export accepted")?
            .kind(),
        phantom::SessionTicketErrorKind::Unsupported
    );
    assert_eq!(
        custom
            .import_session_tickets(&empty, &key, &[])
            .err()
            .ok_or("import accepted")?
            .kind(),
        phantom::SessionTicketErrorKind::Unsupported
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn connector_io_errors_keep_their_original_kind() -> TestResult<()> {
    let client = builder(TcpConnector::from_fn(|_| async {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "caller connector denied",
        ))
    }))
    .build()?;
    let error = client
        .get(HttpProtocol::Http1, URL)?
        .send()
        .await
        .err()
        .ok_or("failed connector succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::Connect);
    let mut cause = error.source();
    let mut original = None;
    while let Some(error) = cause {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            original = Some(error.kind());
        }
        cause = error.source();
    }
    assert_eq!(original, Some(io::ErrorKind::PermissionDenied));
    Ok(())
}

#[tokio::test]
async fn explicit_http3_cannot_bypass_the_tcp_connector() -> TestResult<()> {
    let (connector, _peers, calls) = connector();
    let client = Client::builder(chrome::v154_windows())
        .tcp_connector(connector)
        .build()?;
    let error = client
        .get(HttpProtocol::Http3, "https://127.0.0.1:4321/")
        .err()
        .ok_or("HTTP/3 request was accepted")?;
    assert_eq!(error.kind(), RequestErrorKind::ProtocolUnavailable);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn custom_stream_carries_explicit_cleartext_http2() -> TestResult<()> {
    timeout(LIMIT, async {
        let (connector, mut peers, calls) = connector();
        let client = builder(connector).build()?;
        let caller = async {
            let response = client.get(HttpProtocol::Http2, URL)?.send().await?;
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let peer = async {
            let mut stream = peers
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            h2::accept_client_preface(&mut stream).await?;
            h2::read_request_headers(&mut stream, 1).await?;
            h2::write_frame(&mut stream, 1, 5, 1, &[0x88]).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    })
    .await?
}
