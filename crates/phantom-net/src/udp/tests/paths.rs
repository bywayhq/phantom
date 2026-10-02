//! Every HTTP/3 connect path that opens a UDP socket applies the
//! connector's UDP settings.
//!
//! The peers never answer a QUIC packet, so each connection attempt is
//! dropped once its socket is bound; the socket is read back when it binds.

use std::{future::Future, io, net::SocketAddr, time::Duration};

use phantom_profile::{UdpSettings, chromium};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use super::{IPV4_LOOPBACK, TestResult, sets_random_port};
use crate::{
    SourceBinding,
    http3::Http3Connector,
    udp::observed::{self, ObservedSocket},
};

const SERVER_NAME: &str = "server.phantom.test";

fn http3(settings: Option<UdpSettings>) -> TestResult<Http3Connector> {
    let connector = Http3Connector::new(
        &chromium::v154_http3_tls(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
    )?;
    Ok(match settings {
        Some(settings) => connector.with_udp_settings(&settings),
        None => connector,
    })
}

/// Polls `connect` until it binds a UDP socket or ends, drops it, and
/// returns the sockets bound meanwhile.
async fn sockets_bound_by<F: Future>(connect: F) -> Vec<ObservedSocket> {
    observed::take();
    tokio::select! {
        _ = connect => {}
        () = async {
            while observed::count() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        } => {}
        () = tokio::time::sleep(Duration::from_secs(10)) => {}
    }
    observed::take()
}

fn assert_bound_with(path: &str, sockets: &[ObservedSocket], settings: Option<UdpSettings>) {
    assert_eq!(
        sockets,
        [ObservedSocket {
            random_port: sets_random_port(settings),
        }],
        "{path}"
    );
}

/// A SOCKS5 proxy that grants every UDP ASSOCIATE with a relay that never
/// answers, and holds each control connection open.
struct Socks5Peer {
    port: u16,
    task: JoinHandle<()>,
}

impl Socks5Peer {
    async fn bind() -> TestResult<Self> {
        let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
        let port = listener.local_addr()?.port();
        let relay = phantom_testkit::udp::bind_tokio((IPV4_LOOPBACK, 0).into())?;
        let relay = relay.local_addr()?;
        let task = tokio::spawn(async move {
            let mut controls = Vec::new();
            while let Ok((mut control, _)) = listener.accept().await {
                if grant_udp_associate(&mut control, relay).await.is_ok() {
                    controls.push(control);
                }
            }
        });
        Ok(Self { port, task })
    }
}

impl Drop for Socks5Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn grant_udp_associate(control: &mut TcpStream, relay: SocketAddr) -> io::Result<()> {
    let mut greeting = [0; 3];
    control.read_exact(&mut greeting).await?;
    control.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    control.read_exact(&mut header).await?;
    let address_length = match header[3] {
        1 => 4,
        4 => 16,
        _ => usize::from(control.read_u8().await?),
    };
    let mut rest = vec![0; address_length + 2];
    control.read_exact(&mut rest).await?;
    let SocketAddr::V4(relay) = relay else {
        return Err(io::Error::other("test relay must be IPv4"));
    };
    let mut reply = vec![5, 0, 0, 1];
    reply.extend_from_slice(&relay.ip().octets());
    reply.extend_from_slice(&relay.port().to_be_bytes());
    control.write_all(&reply).await
}

#[tokio::test(flavor = "current_thread")]
async fn direct_quic_sockets_apply_the_udp_settings() -> TestResult {
    let peer = phantom_testkit::udp::bind_tokio((IPV4_LOOPBACK, 0).into())?;
    let port = peer.local_addr()?.port();
    let source = SourceBinding::new().with_address(IPV4_LOOPBACK);

    for settings in [Some(chromium::v154_udp()), None] {
        let connector = http3(settings)?;
        let sockets =
            sockets_bound_by(connector.connect_direct("127.0.0.1", port, SERVER_NAME)).await;
        assert_bound_with("direct", &sockets, settings);

        let connector = connector.with_source_binding(source.clone());
        let sockets =
            sockets_bound_by(connector.connect_direct("127.0.0.1", port, SERVER_NAME)).await;
        assert_bound_with("source-bound direct", &sockets, settings);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_association_sockets_apply_the_udp_settings() -> TestResult {
    let proxy = Socks5Peer::bind().await?;

    for settings in [Some(chromium::v154_udp()), None] {
        let connector = http3(settings)?;
        let sockets = sockets_bound_by(connector.connect_socks5_local(
            "127.0.0.1",
            proxy.port,
            "127.0.0.1",
            443,
            SERVER_NAME,
        ))
        .await;
        assert_bound_with("SOCKS5 local DNS", &sockets, settings);

        let sockets = sockets_bound_by(connector.connect_socks5_remote(
            "127.0.0.1",
            proxy.port,
            SERVER_NAME,
            443,
            SERVER_NAME,
        ))
        .await;
        assert_bound_with("SOCKS5 remote DNS", &sockets, settings);
    }
    Ok(())
}
