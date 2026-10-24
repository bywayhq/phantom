//! Real dedicated dials, plus the raw-socket boundary shared by both finalizers.

use super::*;
use crate::{
    proxy::https_connect::{ProxyTarget, TunnelConnection},
    request::{OriginForm, RequestHeader},
    tcp::{AddressFamily, AddressFamilyMemory},
};
use std::sync::OnceLock;

fn extended_connector(identity: &TestIdentity) -> TestResult<HttpsProxyConnector> {
    use phantom_profile::Http2PseudoHeader as H;
    let mut settings = firefox::v157_http2();
    settings.extended_connect_pseudo_header_order = Some(vec![
        H::Method,
        H::Protocol,
        H::Scheme,
        H::Path,
        H::Authority,
    ]);
    Ok(connector(identity)?.with_http2_settings(&settings))
}

async fn exchange(connection: &crate::http2::Http2Connection, extended: bool) -> TestResult<()> {
    let mut tunnel = if extended {
        let request = crate::http2::prepare_connect_udp(
            "proxy.test",
            OriginForm::parse("/current")?,
            vec![RequestHeader::new("x-current", "marker")],
        )?;
        match connection.send_connect_udp(request).await? {
            crate::http2::Http2ExtendedConnectOutcome::Accepted { stream, .. } => {
                stream.into_connect_stream()
            }
            _ => return Err("extended CONNECT rejected".into()),
        }
    } else {
        let request = PreparedHttp2Connect::new(
            "origin.invalid:443",
            &[
                HttpConnectHeader::authority("Host"),
                HttpConnectHeader::field(RequestHeader::new("x-current", "marker")),
            ],
        )?;
        http2_connect::establish(connection, &request, Http2RejectedConnect::EndStream).await?
    };
    let mut prefix = [0; 2];
    tunnel.read_exact(&mut prefix).await?;
    assert_eq!(&prefix, b"ok");
    Ok(())
}

async fn peer(server: SslStream<TcpStream>, extended: bool) -> TestResult<()> {
    let mut builder = ::http2::server::Builder::new();
    if extended {
        builder.enable_connect_protocol();
    }
    let mut connection = builder.handshake::<_, Bytes>(server).await?;
    let (request, mut respond) = connection.accept().await.ok_or("no CONNECT")??;
    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.headers()["x-current"], "marker");
    assert!(!request.headers().contains_key("proxy-authorization"));
    if extended {
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().path(), "/current");
        assert_eq!(
            request.uri().authority().map(|v| v.as_str()),
            Some("proxy.test")
        );
        assert_eq!(
            request
                .extensions()
                .get::<::http2::ext::Protocol>()
                .map(|v| v.as_str()),
            Some("connect-udp")
        );
    } else {
        assert_eq!(
            request.uri().authority().map(|v| v.as_str()),
            Some("origin.invalid:443")
        );
        assert!(request.uri().scheme().is_none());
        assert!(
            request
                .extensions()
                .get::<::http2::ext::Protocol>()
                .is_none()
        );
    }
    let mut send = respond.send_response(Response::new(()), false)?;
    send.send_data(Bytes::from_static(b"ok"), true)?;
    drop((send, request));
    assert!(
        connection.accept().await.is_none(),
        "unexpected second request"
    );
    Ok(())
}

#[tokio::test]
async fn nonpooled_ordinary_h2_resets_its_operation_proxy_family() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = connector(&identity)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = ProxyTarget {
            host: "127.0.0.1",
            port: listener.local_addr()?.port(),
            server_name: TEST_SERVER_NAME,
            credentials: None,
            family: OnceLock::new(),
        };
        let unrelated = OnceLock::<AddressFamilyMemory>::new();
        let client = async {
            let connection = connector.http2_connection(&target).await?;
            assert!(matches!(&connection, TunnelConnection::Dedicated(_)));
            assert_eq!(
                target.family.get().and_then(AddressFamilyMemory::family),
                None
            );
            assert!(unrelated.get().is_none());
            exchange(connection.connection(), false).await
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            peer(tls(stream, &identity, TestServerAlpn::H2).await?, false).await
        };
        tokio::try_join!(client, server)?;
        Ok(())
    })
    .await
    .map_err(|_| "dedicated ordinary H2 exceeded its deadline")?
}

#[tokio::test]
async fn dedicated_extended_h2_learns_the_supplied_proxy_family_and_keeps_its_protocol()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = extended_connector(&identity)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let family = AddressFamilyMemory::default();
        let client = async {
            let connection = connector
                .connect_http2_extended_proxy("127.0.0.1", port, TEST_SERVER_NAME, &family)
                .await?;
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            exchange(&connection, true).await
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            peer(tls(stream, &identity, TestServerAlpn::H2).await?, true).await
        };
        tokio::try_join!(client, server)?;
        Ok(())
    })
    .await
    .map_err(|_| "dedicated extended H2 exceeded its deadline")?
}

#[tokio::test]
async fn extended_h2_closes_the_raw_backup_before_settings_or_connect() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = extended_connector(&identity)?;
        let (first, server) = sockets().await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let slower = SlowerAttempt::scripted(TcpStream::connect(address), Duration::ZERO, None);
        let client = async {
            let stream = connector.finish_http2_proxy_tls(first, Some(slower), TEST_SERVER_NAME).await?;
            let connection = crate::http2::connect_selected_extended(stream, connector.http2_extended_builder()?).await?;
            exchange(&connection, true).await
        };
        let server = async {
            let (mut backup, _) = listener.accept().await?;
            assert!(matches!(backup.try_read(&mut [0]), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
            let server = tls(server, &identity, TestServerAlpn::H2).await?;
            // The server has sent no SETTINGS, challenge or application response.
            closed_without_bytes(&mut backup).await?;
            peer(server, true).await
        };
        tokio::try_join!(client, server)?;
        Ok(())
    }).await.map_err(|_| "extended H2 backup retirement exceeded its deadline")?
}

#[tokio::test]
async fn single_path_tcp_does_not_start_family_retention_for_extended_h2() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = extended_connector(&identity)?
            .with_tcp_settings(&phantom_profile::browser::chrome::v154_tcp());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let family = AddressFamilyMemory::default();
        let client = async {
            let connection = connector
                .connect_http2_extended_proxy("127.0.0.1", port, TEST_SERVER_NAME, &family)
                .await?;
            assert_eq!(family.family(), None);
            exchange(&connection, true).await
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            peer(tls(stream, &identity, TestServerAlpn::H2).await?, true).await
        };
        tokio::try_join!(client, server)?;
        Ok(())
    })
    .await
    .map_err(|_| "single-path extended H2 exceeded its deadline")?
}
