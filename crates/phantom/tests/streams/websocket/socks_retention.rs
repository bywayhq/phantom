//! Complete authenticated SOCKS tunnels stay quiet until their pool claimant.
use crate::support::tls::{TestIdentity, TestResult, tls_settings};
use phantom::{
    AddressResolver, Client, HttpProtocol, RequestHeader, Route, Socks4Proxy, Socks5Proxy,
    profile::{
        ClientProfile, TcpAddressSelection, TcpBackupConnection, WebSocketField,
        WebSocketNewConnection,
        browser::{chrome, firefox},
    },
};
use std::{io, net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};
mod http1;
mod http2;
mod peer;
const WAIT: Duration = Duration::from_secs(10);
const HOST: &str = "origin.socks.test";
#[derive(Clone, Copy)]
enum Socks {
    Four,
    FiveRemote,
    FiveLocal,
}
fn client(
    identity: &TestIdentity,
    port: u16,
    socks: Socks,
    h2: bool,
    password: &str,
) -> TestResult<Client> {
    let route = match socks {
        Socks::Four => Route::socks4(
            Socks4Proxy::new(&format!("socks4a://127.0.0.1:{port}"))?.with_user_id("owner")?,
        ),
        Socks::FiveRemote | Socks::FiveLocal => Route::socks5(
            Socks5Proxy::new(&format!(
                "{}://127.0.0.1:{port}",
                if matches!(socks, Socks::FiveRemote) {
                    "socks5h"
                } else {
                    "socks5"
                }
            ))?
            .with_username_password("user", password)?,
        ),
    };
    let mut tcp = firefox::v157_tcp();
    tcp.address_selection = TcpAddressSelection::Backup(TcpBackupConnection {
        delay: Duration::from_millis(1),
        known_family_backup_timeout: Some(Duration::from_secs(1)),
    });
    let mut websocket = chrome::v154_websocket();
    websocket.connection.without_http2_session = if h2 {
        WebSocketNewConnection::Http2ExtendedConnect
    } else {
        WebSocketNewConnection::Http1Upgrade
    };
    websocket.http1_fields = vec![
        WebSocketField::authority("Host"),
        WebSocketField::literal("Upgrade", "websocket"),
        WebSocketField::literal("Connection", "Upgrade"),
        WebSocketField::key("Sec-WebSocket-Key"),
        WebSocketField::literal("Sec-WebSocket-Version", "13"),
        WebSocketField::caller("x-claim"),
    ];
    websocket.http2_fields = vec![
        WebSocketField::literal("sec-websocket-version", "13"),
        WebSocketField::caller("x-claim"),
    ];
    let profile = ClientProfile::new(tls_settings())
        .with_tcp(tcp)
        .with_http1(firefox::v157_http1())
        .with_http2(firefox::v157_http2())
        .with_websocket(websocket);
    let resolver = AddressResolver::from_fn(move |host| async move {
        if host == HOST && matches!(socks, Socks::FiveLocal) {
            Ok(vec![Ipv4Addr::LOCALHOST.into()])
        } else {
            Err(io::Error::other("remote SOCKS target was resolved locally"))
        }
    });
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .route(route)
        .dns_resolver(resolver)
        .build()?)
}
fn password() -> TestResult<String> {
    let mut bytes = [0; 16];
    btls::rand::rand_bytes(&mut bytes)?;
    Ok(bytes
        .iter()
        .map(|&byte| char::from(b'a' + byte % 26))
        .collect())
}
