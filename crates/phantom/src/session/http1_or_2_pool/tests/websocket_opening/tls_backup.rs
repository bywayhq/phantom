//! Authenticated direct TLS siblings do not outlive an unused Upgrade backup.

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::{Pin, pin},
    sync::Arc,
    task::Poll,
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use phantom_net::{
    http1::{Http1Connection, Http1TlsConnector},
    route::{DirectTlsSetup, Endpoint as NetEndpoint, Http1Route, OriginRoute, TcpRoute},
    tcp::{AddressFamily, SlowerConnection, SlowerProgress},
};
use phantom_profile::{
    ClientProfile, WebSocketNewConnection, WebSocketTlsBackup, browser::firefox,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{TestResult, WAIT, identity};
use crate::{Client, HttpProtocol, authority::Endpoint, session::prune_timer::PruneTimer};

#[derive(Clone, Copy, Debug)]
enum Pool {
    Exact,
    Negotiated,
}

#[tokio::test]
async fn authenticated_unused_tls_backup_closes_while_winner_websocket_stays_open() -> TestResult {
    for pool in [Pool::Exact, Pool::Negotiated] {
        lifecycle(pool, WebSocketTlsBackup::CloseWhenUnused).await?;
    }
    Ok(())
}

#[tokio::test]
async fn keep_policy_retains_authenticated_tls_backup_until_close_idle() -> TestResult {
    for pool in [Pool::Exact, Pool::Negotiated] {
        lifecycle(pool, WebSocketTlsBackup::Keep).await?;
    }
    Ok(())
}

async fn lifecycle(pool: Pool, policy: WebSocketTlsBackup) -> TestResult {
    timeout(WAIT, async {
        let (root, acceptor) = identity()?;
        let mut websocket = firefox::v157_websocket();
        websocket.connection.http1_tls_backup = policy;
        // This fixture selects the direct H1 fallback instead of opening H2.
        websocket.connection.without_http2_session = WebSocketNewConnection::Http1Upgrade;
        let profile = ClientProfile::new(firefox::v157_tcp_tls())
            .with_tcp(firefox::v157_tcp()).with_http1(firefox::v157_http1())
            .with_http2(firefox::v157_http2()).with_websocket(websocket);
        let timer = PruneTimer::unscheduled(Duration::ZERO);
        let mut client = Client::builder(profile).add_root_certificate_der(root).build()?;
        let state = Arc::get_mut(&mut client.state).ok_or("client state already shared")?;
        let one = std::num::NonZeroUsize::MIN;
        state.http1 = crate::session::http1_pool::Http1Pool::new(one, one, one)
            .with_prune_timer(Some(Arc::clone(&timer)));
        state.http1_or_2 = crate::session::http1_or_2_pool::Http1Or2Pool::new(one, one, one, one, one, one)
            .with_prune_timer(Some(Arc::clone(&timer)));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let endpoint = Endpoint::new(address.to_string().parse()?, 443)?;
        let (authenticated, authentication) = oneshot::channel();
        let (held, retained) = oneshot::channel();
        let (closed, mut closure) = oneshot::channel();
        let uri = format!("wss://{address}/winner");
        let caller = async {
            let builder = match pool {
                Pool::Exact => client.websocket_with_protocol(HttpProtocol::Http1, &uri)?,
                Pool::Negotiated => client.websocket_with_profile_policy(&uri)?,
            };
            let socket = builder.connect().await?;
            let connectors = client.inner.connectors_for(&endpoint);
            // Only setup is gated here: the sibling itself uses verified native TLS.
            let family = match pool {
                Pool::Exact => {
                    let owner = client.state.http1.origin_opening(&endpoint, false).await;
                    let connector = owner.connector(connectors.http1.ok_or("no H1 connector")?, &endpoint)?;
                    let family = Arc::clone(owner.family());
                    owner.adopt(backup(connector, address, authenticated), policy);
                    family
                }
                Pool::Negotiated => {
                    let owner = client.state.http1_or_2.origin_opening(&endpoint).await;
                    let connector = owner.connector(connectors.http1_or_2.ok_or("no negotiated connector")?, &endpoint)?
                        .http1_connector(&[Box::from(b"http/1.1".as_slice())])?;
                    let family = Arc::clone(owner.family());
                    owner.adopt(backup(connector, address, authenticated), policy);
                    family
                }
            };
            authentication.await?.map_err(|error| format!("backup TLS failed: {error}"))?;
            assert_eq!(family.family(), Some(AddressFamily::Ipv4), "{pool:?}");
            if policy == WebSocketTlsBackup::Keep {
                retained.await?;
                // Close-idle can race the terminal setup report. Drive it until
                // the peer observes the close, without a timing assertion.
                loop {
                    client.close_idle_connections().await;
                    tokio::select! {
                        result = &mut closure => { result?; break; }
                        () = tokio::task::yield_now() => {}
                    }
                }
            } else {
                closure.await?;
            }
            timer.fire();
            assert_eq!(family.family(), None, "{pool:?}");
            drop(socket);
            TestResult::Ok(())
        };
        let peer = async {
            let mut winner = accept(&listener, &acceptor).await?;
            let head = head(&mut winner).await?;
            let text = std::str::from_utf8(&head)?;
            assert!(text.starts_with("GET /winner HTTP/1.1\r\n"));
            let key = text.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("sec-websocket-key").then(|| value.trim())
            }).ok_or("missing WebSocket key")?;
            let mut bytes = key.as_bytes().to_vec();
            bytes.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            let accept_value = btls::base64::encode_block(&btls::sha::sha1(&bytes));
            winner.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_value}\r\n\r\n").as_bytes()).await?;
            let sibling = async {
                let mut sibling = accept(&listener, &acceptor).await?;
                let mut byte = [0; 1];
                let mut read = pin!(sibling.read(&mut byte));
                if policy == WebSocketTlsBackup::Keep {
                    std::future::poll_fn(|cx| {
                        if read.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(Err("Keep backup closed or sent HTTP before close-idle"));
                        }
                        Poll::Ready(Ok(()))
                    }).await?;
                    held.send(()).map_err(|()| "retained-backup observer ended")?;
                }
                disconnected(read.await)?;
                closed.send(()).map_err(|()| "backup-close observer ended")?;
                TestResult::Ok(())
            };
            let mut unexpected = [0; 1];
            tokio::select! {
                result = sibling => result?,
                result = winner.read(&mut unexpected) => {
                    return Err(format!("winning WebSocket ended before backup closure: {result:?}").into());
                }
            }
            disconnected(winner.read(&mut unexpected).await)?;
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    }).await?
}

fn backup(
    connector: Http1TlsConnector,
    address: SocketAddr,
    authenticated: oneshot::Sender<Result<(), String>>,
) -> SlowerConnection<Http1Connection> {
    SlowerConnection::new(SlowerProgress::new(), async move {
        let result = connector
            .connect(Http1Route::Origin(OriginRoute::Tls {
                tcp: TcpRoute::Direct(NetEndpoint {
                    host: "127.0.0.1",
                    port: address.port(),
                }),
                server_name: "127.0.0.1",
                setup: DirectTlsSetup::Default,
            }))
            .await;
        let (connection, status) = match result {
            Ok((connection, None)) => {
                connection.early_data_answered().await;
                if let Some(error) = connection.early_data_failure() {
                    (None, Err(error.to_string()))
                } else {
                    (Some(connection), Ok(()))
                }
            }
            Ok(_) => (
                None,
                Err("single-address setup returned another slower connection".to_owned()),
            ),
            Err(error) => (None, Err(error.to_string())),
        };
        if authenticated.send(status).is_err() {
            return None;
        }
        connection
    })
}

async fn accept(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> Result<SslStream<TcpStream>, Box<dyn std::error::Error>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    assert_eq!(
        stream.ssl().selected_alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    Ok(stream)
}

async fn head(stream: &mut SslStream<TcpStream>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == 16 * 1024 {
            return Err("Upgrade head exceeded test bound".into());
        }
        let mut byte = [0; 1];
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    Ok(head)
}

fn disconnected(result: std::io::Result<usize>) -> TestResult {
    match result {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        other => {
            Err(format!("unused TLS sibling sent application data or failed: {other:?}").into())
        }
    }
}
