//! Exact-H1 requests claim complete authenticated SOCKS backups without redial.
use crate::support::tls::{
    H1_ALPN, TestIdentity, TestResult, accept_tls_stream, read_head, tls_settings,
};
use http_body_util::BodyExt;
use phantom::{
    AddressResolver, Client, HttpProtocol, RequestHeader, Route, Socks4Proxy, Socks5Proxy,
    profile::{ClientProfile, TcpAddressSelection, TcpBackupConnection, browser::firefox},
};
use std::{
    io,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
const WAIT: Duration = Duration::from_secs(10);
const HOST: &str = "origin.socks.test";
mod negotiated;
#[derive(Clone, Copy)]
enum Protocol {
    Four,
    Five,
}
#[tokio::test]
async fn socks5_authenticated_plaintext_backup_uses_the_claiming_request_without_redial()
-> TestResult<()> {
    retained(Protocol::Five, false).await
}
#[tokio::test]
async fn socks4a_backup_preserves_user_id_remote_dns_and_current_request() -> TestResult<()> {
    retained(Protocol::Four, false).await
}
#[tokio::test]
async fn socks5_authenticated_backup_finishes_origin_tls_and_stays_application_quiet()
-> TestResult<()> {
    retained(Protocol::Five, true).await
}

async fn retained(protocol: Protocol, tls: bool) -> TestResult<()> {
    timeout(WAIT, async {
        let identity = TestIdentity::generate_for_dns(HOST)?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let port = if tls { 443 } else { 80 };
        let route = match protocol {
            Protocol::Four => Route::socks4(
                Socks4Proxy::new(&format!("socks4a://{address}"))?.with_user_id("owner")?,
            ),
            Protocol::Five => Route::socks5(
                Socks5Proxy::new(&format!("socks5h://{address}"))?
                    .with_username_password("user", "secret")?,
            ),
        };
        let mut tcp = firefox::v157_tcp();
        tcp.address_selection = TcpAddressSelection::Backup(TcpBackupConnection {
            delay: Duration::from_millis(1),
            known_family_backup_timeout: Some(Duration::from_secs(1)),
            socks_proxy_dns_feedback: phantom::profile::SocksProxyDnsFeedback::AllConnectFailures,
        });
        let mut tls_profile = tls_settings();
        tls_profile.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
        let profile = ClientProfile::new(tls_profile).with_tcp(tcp);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .route(route)
            .dns_resolver(AddressResolver::from_fn(move |_| {
                count.fetch_add(1, Ordering::Relaxed);
                async { Err(io::Error::other("SOCKS remote target lookup must not run")) }
            }))
            .build()?;
        let (release_tx, release_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (claim_tx, claim_rx) = oneshot::channel();
        let (quiet_tx, quiet_rx) = oneshot::channel();
        let request = async {
            let scheme = if tls { "https" } else { "http" };
            let url = format!("{scheme}://{HOST}");
            let first = client
                .get(HttpProtocol::Http1, &format!("{url}/prime"))?
                .header(RequestHeader::new("X-Claim", "prime"))
                .send()
                .await?;
            assert_eq!(first.status(), 200);
            assert_eq!(first.into_body().collect().await?.to_bytes(), "ok");
            release_tx.send(()).map_err(|_| "spare peer ended")?;
            ready_rx.await?;
            claim_tx.send(()).map_err(|_| "spare peer ended")?;
            quiet_rx.await?;
            let second = client
                .get(HttpProtocol::Http1, &format!("{url}/current"))?
                .header(RequestHeader::new("X-Claim", "current"))
                .send()
                .await?;
            assert_eq!(second.status(), 200);
            assert_eq!(second.into_body().collect().await?.to_bytes(), "ok");
            drop(client);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let mut first = negotiate(&listener, protocol, port).await?;
            let mut second = negotiate(&listener, protocol, port).await?;
            reply(&mut second, protocol).await?;
            if tls {
                let mut second = accept_tls_stream(second, acceptor.clone()).await?;
                respond(&mut second, "prime", "X-Claim").await?;
            } else {
                respond(&mut second, "prime", "X-Claim").await?;
            }
            release_rx.await?;
            reply(&mut first, protocol).await?;
            if tls {
                let first = accept_tls_stream(first, acceptor).await?;
                claim(first, ready_tx, claim_rx, quiet_tx, "X-Claim").await?;
            } else {
                claim(first, ready_tx, claim_rx, quiet_tx, "X-Claim").await?;
            }
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(
                listener.poll_accept(&mut context).is_pending(),
                "claim redialled or repeated SOCKS authentication"
            );
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(request, peer)?;
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        Ok(())
    })
    .await?
}
async fn claim<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    ready: oneshot::Sender<()>,
    claim: oneshot::Receiver<()>,
    quiet: oneshot::Sender<()>,
    claim_header: &str,
) -> TestResult<()> {
    ready.send(()).map_err(|_| "claim owner ended")?;
    let mut byte = [0];
    tokio::select! {biased;read=stream.read(&mut byte)=>return Err(format!("unused SOCKS spare carried application bytes/closure: {read:?}").into()),claim=claim=>claim?};
    quiet.send(()).map_err(|_| "claim owner ended")?;
    respond(&mut stream, "current", claim_header).await
}
async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    value: &str,
    claim_header: &str,
) -> TestResult<()> {
    assert_eq!(
        read_head(stream).await?,
        format!("GET /{value} HTTP/1.1\r\nHost: {HOST}\r\n{claim_header}: {value}\r\n\r\n")
            .as_bytes()
    );
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    stream.shutdown().await?;
    Ok(())
}
async fn negotiate(listener: &TcpListener, protocol: Protocol, port: u16) -> TestResult<TcpStream> {
    let (mut stream, _) = listener.accept().await?;
    match protocol {
        Protocol::Four => {
            let mut head = [0; 8];
            stream.read_exact(&mut head).await?;
            let [hi, lo] = port.to_be_bytes();
            assert_eq!(head, [4, 1, hi, lo, 0, 0, 0, 1]);
            assert_eq!(nul(&mut stream).await?, b"owner");
            assert_eq!(nul(&mut stream).await?, HOST.as_bytes());
        }
        Protocol::Five => {
            let mut greeting = [0; 4];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 2, 0, 2]);
            stream.write_all(&[5, 2]).await?;
            assert_eq!(stream.read_u8().await?, 1);
            assert_eq!(length(&mut stream).await?, b"user");
            assert_eq!(length(&mut stream).await?, b"secret");
            stream.write_all(&[1, 0]).await?;
            let mut head = [0; 4];
            stream.read_exact(&mut head).await?;
            assert_eq!(head, [5, 1, 0, 3]);
            assert_eq!(length(&mut stream).await?, HOST.as_bytes());
            assert_eq!(stream.read_u16().await?, port);
        }
    }
    Ok(stream)
}
async fn reply(stream: &mut TcpStream, protocol: Protocol) -> io::Result<()> {
    match protocol {
        Protocol::Four => stream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await,
        Protocol::Five => stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await,
    }
}
async fn length(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let length = stream.read_u8().await?;
    let mut bytes = vec![0; usize::from(length)];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn nul(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            return Ok(bytes);
        }
        if bytes.len() == 255 {
            return Err(io::Error::other("unbounded SOCKS4 field"));
        }
        bytes.push(byte)
    }
}
