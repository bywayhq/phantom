//! Complete SOCKS attempts keep the origin TLS and application stages distinct.
use super::{read_plaintext_head, test_connector};
use crate::{
    http1::Http1Connection,
    proxy::Socks5Auth,
    request::{OriginForm, RequestHeader},
    route::{DirectTlsSetup, Endpoint, OriginRoute, Socks5Target, TcpRoute},
    tcp::{AddressFamily, AddressFamilyMemory},
    tls::test_support::{TEST_SERVER_NAME, TestIdentity, TestResult, TestServerAlpn},
};
use btls::ssl::{Ssl, SslAcceptor};
use http_body_util::BodyExt;
use std::{future::Future, io, net::Ipv4Addr, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;
const WAIT: Duration = Duration::from_secs(5);
fn settings() -> phantom_profile::TcpSettings {
    let mut settings = phantom_profile::browser::firefox::v157_tcp();
    settings.address_selection =
        phantom_profile::TcpAddressSelection::Backup(phantom_profile::TcpBackupConnection {
            delay: Duration::from_millis(1),
            known_family_backup_timeout: Some(Duration::from_secs(1)),
            socks_proxy_dns_feedback: phantom_profile::SocksProxyDnsFeedback::AllConnectFailures,
        });
    settings
}
fn early_data_connector(identity: &TestIdentity) -> TestResult<super::Http1TlsConnector> {
    let mut tls = phantom_profile::browser::firefox::v157_tcp_tls();
    assert!(tls.tcp_early_data);
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let connector = super::Http1TlsConnector::new_with_roots(&tls, [identity.root_der()])?
        .with_tcp_settings(&settings());
    assert!(connector.tls.offers_early_data());
    Ok(connector)
}
async fn negotiate(listener: &TcpListener) -> TestResult<TcpStream> {
    let (mut stream, _) = listener.accept().await?;
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await?;
    let mut request = [0; 10];
    stream.read_exact(&mut request).await?;
    assert_eq!(request, [5, 1, 0, 1, 127, 0, 0, 1, 1, 187]);
    Ok(stream)
}
async fn reply(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await
}
async fn tls(stream: TcpStream, acceptor: &SslAcceptor) -> TestResult<SslStream<TcpStream>> {
    let mut stream = SslStream::new(Ssl::new(acceptor.context())?, stream)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}
async fn bounded(future: impl Future<Output = TestResult<()>>) -> TestResult<()> {
    timeout(WAIT, future).await?
}
fn origin(proxy_host: &str, port: u16) -> OriginRoute<'_> {
    OriginRoute::Tls {
        tcp: TcpRoute::Socks5 {
            proxy: Endpoint {
                host: proxy_host,
                port,
            },
            target: Socks5Target::LocalDns(Endpoint {
                host: "127.0.0.1",
                port: 443,
            }),
            auth: Socks5Auth::None,
        },
        server_name: TEST_SERVER_NAME,
        setup: DirectTlsSetup::Default,
    }
}
async fn get(connection: &Http1Connection, path: &str) -> TestResult<()> {
    let response = connection
        .send_get(
            OriginForm::parse(path)?,
            vec![
                RequestHeader::new("Host", TEST_SERVER_NAME),
                RequestHeader::new("X-Claim", "current"),
            ],
        )
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    Ok(())
}
async fn respond<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, path: &str) -> TestResult<()> {
    assert_eq!(
        read_plaintext_head(stream).await?,
        format!("GET {path} HTTP/1.1\r\nHost: {TEST_SERVER_NAME}\r\nX-Claim: current\r\n\r\n")
            .as_bytes()
    );
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    Ok(())
}

#[tokio::test]
async fn the_spare_finishes_verified_tls_but_sends_no_request_until_claimed() -> TestResult<()> {
    for strategy in [
        crate::http1::Http1WriteStrategy::Automatic,
        crate::http1::Http1WriteStrategy::Queued,
    ] {
        bounded(async {
        let identity=TestIdentity::generate()?;let acceptor=identity.acceptor(TestServerAlpn::Http1)?;let connector=early_data_connector(&identity)?.with_write_strategy(strategy);
        let listener=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).await?;let address=listener.local_addr()?;let host=address.ip().to_string();let family=AddressFamilyMemory::default();
        let (release_tx,release_rx)=oneshot::channel();let (ready_tx,ready_rx)=oneshot::channel();let (quiet_tx,quiet_rx)=oneshot::channel();
        let peer=async {
            let mut first=negotiate(&listener).await?;let mut second=negotiate(&listener).await?;reply(&mut second).await?;let mut winner=tls(second,&acceptor).await?;
            release_rx.await?;reply(&mut first).await?;let mut spare=tls(first,&acceptor).await?;
            let mut byte=[0];tokio::select! {biased;read=spare.read(&mut byte)=>return Err(format!("unused TLS spare produced application data or closure: {read:?}").into()),ready=ready_rx=>ready?};
            quiet_tx.send(()).map_err(|_|"claim ended before quiet check")?;respond(&mut spare,"/current").await?;
            let mut byte=[0];match winner.read(&mut byte).await {Ok(0)=>{},Err(e) if matches!(e.kind(),io::ErrorKind::ConnectionAborted|io::ErrorKind::ConnectionReset|io::ErrorKind::BrokenPipe|io::ErrorKind::UnexpectedEof)=>{},other=>return Err(format!("unused winner received a request: {other:?}").into())};
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        };
        let operation=async {
            let (winner,slower)=connector.connect_socks_retaining(origin(&host,address.port()),&family).await?;
            assert_eq!(family.family(),Some(AddressFamily::Ipv4));let slower=slower.ok_or("missing slower complete SOCKS connection")?;
            assert!(!slower.progress().has_connected());release_tx.send(()).map_err(|_|"peer ended")?;
            let spare=slower.finish().await.ok_or("spare TLS failed")?;ready_tx.send(()).map_err(|_|"peer ended")?;quiet_rx.await?;
            get(&spare,"/current").await?;drop(spare);drop(winner);Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        };
        tokio::try_join!(peer,operation)?;Ok(())
    }).await?;
    }
    Ok(())
}

#[tokio::test]
async fn failed_spare_tls_preserves_the_verified_winner_without_request_replay() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let wrong = TestIdentity::generate_for_names(&["wrong.test"])?;
        let wrong = wrong.acceptor(TestServerAlpn::Http1)?;
        let connector = test_connector(&identity)?.with_tcp_settings(&settings());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let family = AddressFamilyMemory::default();
        let (release_tx, release_rx) = oneshot::channel();
        let peer = async {
            let mut first = negotiate(&listener).await?;
            let mut second = negotiate(&listener).await?;
            reply(&mut second).await?;
            let mut winner = tls(second, &acceptor).await?;
            release_rx.await?;
            reply(&mut first).await?;
            assert!(tls(first, &wrong).await.is_err());
            respond(&mut winner, "/winner").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let operation = async {
            let (winner, slower) = connector
                .connect_socks_retaining(origin(&host, address.port()), &family)
                .await?;
            release_tx.send(()).map_err(|_| "peer ended")?;
            assert!(slower.ok_or("missing spare")?.finish().await.is_none());
            get(&winner, "/winner").await?;
            drop(winner);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(peer, operation)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn non_backup_policy_keeps_the_existing_single_tunnel_path() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let connector = test_connector(&identity)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let family = AddressFamilyMemory::default();
        let peer = async {
            let mut stream = negotiate(&listener).await?;
            reply(&mut stream).await?;
            let mut stream = tls(stream, &acceptor).await?;
            respond(&mut stream, "/single").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let operation = async {
            let (connection, slower) = connector
                .connect_socks_retaining(origin(&host, address.port()), &family)
                .await?;
            assert!(slower.is_none());
            assert_eq!(family.family(), None);
            get(&connection, "/single").await?;
            drop(connection);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(peer, operation)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn non_backup_policy_keeps_the_early_data_connector_on_one_socks_tunnel() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut tcp = settings();
        tcp.address_selection = phantom_profile::TcpAddressSelection::default();
        let connector = early_data_connector(&identity)?.with_tcp_settings(&tcp);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let family = AddressFamilyMemory::default();
        let peer = async {
            let mut stream = negotiate(&listener).await?;
            reply(&mut stream).await?;
            respond(&mut stream, "/early-policy").await?;
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(listener.poll_accept(&mut context).is_pending());
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let operation = async {
            let route = OriginRoute::Plaintext {
                tcp: TcpRoute::Socks5 {
                    proxy: Endpoint {
                        host: &host,
                        port: address.port(),
                    },
                    target: Socks5Target::LocalDns(Endpoint {
                        host: "127.0.0.1",
                        port: 443,
                    }),
                    auth: Socks5Auth::None,
                },
                family: None,
            };
            let (connection, slower) = connector.connect_socks_retaining(route, &family).await?;
            assert!(slower.is_none());
            assert!(connector.tls.offers_early_data());
            assert_eq!(family.family(), None);
            get(&connection, "/early-policy").await?;
            drop(connection);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(operation, peer)?;
        Ok(())
    })
    .await
}
