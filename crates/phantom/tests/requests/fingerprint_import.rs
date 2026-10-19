use std::{net::Ipv4Addr, time::Duration};

use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol,
    fingerprint::{import_akamai_profile, import_client_hello_profile},
    profile::{ClientProfile, browser::chrome},
};

#[tokio::test]
async fn imported_client_hello_fields_reach_the_public_clients_tcp_peer() -> TestResult<()> {
    use phantom_testkit::tls::{
        CaptureLimits, ClientHelloSummary, capture_client_hello, is_grease,
    };

    fn ids(values: &[u16]) -> Vec<u16> {
        values
            .iter()
            .copied()
            .filter(|id| !is_grease(*id))
            .collect()
    }

    let base = chrome::v154_windows();
    let mut desired = base.tls().clone();
    desired.cipher_suites.swap(0, 1);
    let bytes = phantom_net::preview_client_hello(&desired, "import.invalid")?;
    let expected = ClientHelloSummary::from_handshake_bytes(&bytes)?;
    let imported = import_client_hello_profile(&bytes, &base)?.into_profile();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let client = Client::builder(imported)
        .resolve("import.invalid", [Ipv4Addr::LOCALHOST.into()])
        .build()?;
    let request = client.get_negotiated(&format!("https://import.invalid:{}/", address.port()))?;
    timeout(Duration::from_secs(10), async {
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let capture = capture_client_hello(
                &mut stream,
                tokio::time::Instant::now() + Duration::from_secs(5),
                CaptureLimits::new(64 * 1024, 64 * 1024, 8),
            )
            .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(capture.summary()?)
        };
        let (response, captured) = tokio::join!(request.send(), peer);
        assert!(response.is_err(), "capture peer closes before ServerHello");
        let actual = captured?;
        assert_eq!(ids(actual.cipher_suites()), ids(expected.cipher_suites()));
        assert_eq!(
            ids(actual.extension_types()),
            ids(expected.extension_types())
        );
        assert_eq!(
            ids(actual.supported_groups()),
            ids(expected.supported_groups())
        );
        assert_eq!(
            ids(actual.key_share_groups()),
            ids(expected.key_share_groups())
        );
        assert_eq!(
            ids(actual.signature_algorithms()),
            ids(expected.signature_algorithms())
        );
        assert_eq!(actual.alpn_protocols(), expected.alpn_protocols());
        Ok(())
    })
    .await?
}
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use crate::support::{
    deadline::FixtureDeadline,
    h2::{read_frame, write_frame},
    tls::{H2_ALPN, TestIdentity, TestResult, accept_tls_stream, tls_settings},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

#[tokio::test]
async fn akamai_import_reaches_the_peer_as_ordered_settings_windows_and_pseudo_headers()
-> TestResult<()> {
    for increment in [0_u32, 32767, 16711681] {
        check_wire(increment).await?;
    }
    Ok(())
}

async fn check_wire(increment: u32) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let mut peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = accept_tls_stream(tcp, acceptor).await?;
        let mut preface = [0; 24];
        stream.read_exact(&mut preface).await?;
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let settings = read_frame(&mut stream).await?;
        assert_eq!(
            (settings.kind, settings.flags, settings.stream_id),
            (4, 0, 0)
        );
        assert_eq!(
            settings.payload,
            [
                0, 6, 0, 2, 0, 0, // MAX_HEADER_LIST_SIZE = 131072
                0, 4, 0, 16, 0, 0, // INITIAL_WINDOW_SIZE = 1048576
                0, 2, 0, 0, 0, 0, // ENABLE_PUSH = 0
                0, 1, 0, 1, 0, 0, // HEADER_TABLE_SIZE = 65536
            ]
        );
        write_frame(&mut stream, 4, 0, 0, &[]).await?;
        write_frame(&mut stream, 4, 1, 0, &[]).await?;
        stream.flush().await?;
        let mut update = None;
        for _ in 0..8 {
            let frame = read_frame(&mut stream).await?;
            match frame.kind {
                4 => {
                    assert_eq!((frame.flags, frame.stream_id), (1, 0));
                    assert!(frame.payload.is_empty());
                }
                8 => {
                    assert_eq!(frame.stream_id, 0);
                    assert!(update.is_none());
                    let bytes: [u8; 4] = frame.payload.try_into().map_err(|_| "invalid update")?;
                    update = Some(u32::from_be_bytes(bytes));
                }
                1 => {
                    assert_eq!(frame.stream_id, 1);
                    assert_eq!(frame.flags & (4 | 0x20), 4);
                    assert_eq!(update, (increment != 0).then_some(increment));
                    // First request: indexed path '/', method GET and scheme
                    // https, then an incremental literal named ':authority'.
                    assert!(frame.payload.starts_with(&[0x84, 0x82, 0x87, 0x41]));
                    write_frame(&mut stream, 1, 5, frame.stream_id, &[0x89]).await?;
                    stream.flush().await?;
                    return Ok(());
                }
                _ => return Err("unexpected frame before request headers".into()),
            }
        }
        Err("request headers absent".into())
    });
    let primary = timeout(Duration::from_secs(10), async {
        let mut http2 = chrome::v154_http2();
        http2.headers_priority = None;
        http2.initial_stream_window_target = None;
        let base = ClientProfile::new(tls_settings()).with_http2(http2);
        let description = format!("6:131072;4:1048576;2:0;1:65536|{increment}|0|p,m,s,a");
        let profile = import_akamai_profile(&description, &base)?.into_profile();
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let response = client
            .get(HttpProtocol::Http2, &format!("https://{address}/"))?
            .send()
            .await?;
        assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);
        peer.join().await??;
        Ok(())
    })
    .await
    .map_err(|elapsed| FixtureDeadline::new("Akamai wire test exceeded its deadline", elapsed))
    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
    .and_then(|result| result);
    let cleanup = peer.shutdown().await;
    finish_with_cleanup(primary, cleanup)
}
