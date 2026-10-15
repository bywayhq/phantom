//! Real ECH authentication and requests on retained TCP attempts. Portable
//! controls script only the TCP race result, not TLS or protocol completion.

use http_body_util::BodyExt as _;
use phantom_profile::browser::firefox;
use tokio::{sync::oneshot, task::JoinSet};

use super::*;

mod peer;
use crate::{
    direct::SelectedEch,
    http1::{Http1Connection, Http1TlsConnector},
    request::{OriginForm, RequestHeader},
    route::{DirectTlsSetup, Endpoint, Http1Route, OriginRoute, TcpRoute},
    tcp::{AddressFamily, AddressFamilyMemory, SlowerAttempt},
};
use peer::serve_requests;

#[derive(Clone, Copy)]
enum Opening {
    Composite,
    Spare,
    RetriedSpare,
    #[cfg(windows)]
    Race,
}

fn selected() -> TestResult<SelectedEch> {
    SelectedEch::new(Some(published(1, &TEST_ECH_KEYS[0])))
        .map_err(|_| "valid ECH configuration rejected".into())
}

fn attempt(address: SocketAddr) -> SlowerAttempt {
    SlowerAttempt::scripted(TcpStream::connect(address), Duration::ZERO, None)
}

async fn open(
    exact: bool,
    opening: Opening,
    identity: &TestIdentity,
    address: SocketAddr,
) -> TestResult<Vec<Http1Connection>> {
    let mut settings = firefox::v157_tcp_tls();
    settings.ech = v154_tcp_tls().ech;
    let family = AddressFamilyMemory::new();
    #[cfg(windows)]
    let _unlistened = if matches!(opening, Opening::Race) {
        let socket = tokio::net::TcpSocket::new_v6()?;
        socket.bind(SocketAddr::new(
            std::net::Ipv6Addr::LOCALHOST.into(),
            address.port(),
        ))?;
        Some(socket)
    } else {
        None
    };
    let mut addresses = vec![std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST)];
    if matches!(opening, Opening::RetriedSpare) {
        // The scripted TCP result already selected 127.0.0.1. Resolving the
        // origin again for its ECH retry would reach another loopback address.
        addresses[0] = std::net::Ipv4Addr::new(127, 0, 0, 2).into();
    }
    #[cfg(windows)]
    if matches!(opening, Opening::Race) {
        addresses.insert(0, std::net::Ipv6Addr::LOCALHOST.into());
    }
    let resolver = crate::host_resolver::HostResolver::new().with_override(INNER_NAME, addresses);
    let mut lookup = std::pin::pin!(async { Some(published(1, &TEST_ECH_KEYS[0])) });
    let route = OriginRoute::Tls {
        tcp: TcpRoute::Direct(Endpoint {
            host: INNER_NAME,
            port: address.port(),
        }),
        server_name: INNER_NAME,
        setup: DirectTlsSetup::EchKeepingSlower {
            lookup: lookup.as_mut(),
            family: &family,
        },
    };
    let mut connections = Vec::new();
    if exact {
        let connector =
            Http1TlsConnector::new_with_additional_roots(&settings, [identity.root_der()])?
                .with_tcp_settings(&firefox::v157_tcp())
                .with_host_resolver(resolver);
        match opening {
            Opening::Composite => {
                let (connection, slower) = connector.connect(Http1Route::Origin(route)).await?;
                assert!(
                    slower.is_none(),
                    "one address unexpectedly produced a backup"
                );
                connections.push(connection);
            }
            Opening::Spare | Opening::RetriedSpare => connections.push(
                connector
                    .slower_tls_with_ech(attempt(address), INNER_NAME, selected()?)
                    .finish()
                    .await
                    .ok_or("retained ECH connection failed")?,
            ),
            #[cfg(windows)]
            Opening::Race => {
                let (first, slower) = connector.connect(Http1Route::Origin(route)).await?;
                connections.push(first);
                connections.push(
                    slower
                        .ok_or("actual backup race lost its slower attempt")?
                        .finish()
                        .await
                        .ok_or("actual slower ECH handshake failed")?,
                );
            }
        }
    } else {
        let connector = connector_with(&settings, identity)?
            .with_tcp_settings(&firefox::v157_tcp())
            .with_host_resolver(resolver);
        let opened = match opening {
            Opening::Composite => {
                let (connection, slower) = connector.connect(route).await?;
                assert!(
                    slower.is_none(),
                    "one address unexpectedly produced a backup"
                );
                vec![connection]
            }
            Opening::Spare | Opening::RetriedSpare => vec![
                connector
                    .slower_connection_with_ech(attempt(address), INNER_NAME, selected()?)
                    .finish()
                    .await
                    .ok_or("retained ECH connection failed")?,
            ],
            #[cfg(windows)]
            Opening::Race => {
                let (first, slower) = connector.connect(route).await?;
                vec![
                    first,
                    slower
                        .ok_or("actual backup race lost its slower attempt")?
                        .finish()
                        .await
                        .ok_or("actual slower ECH handshake failed")?,
                ]
            }
        };
        for connection in opened {
            let Http1Or2Connection::Http1(connection) = connection else {
                return Err("HTTP/1.1 peer selected another protocol".into());
            };
            connections.push(connection);
        }
    }
    if matches!(opening, Opening::Composite) {
        assert_eq!(family.family(), Some(AddressFamily::Ipv4));
    }
    Ok(connections)
}

async fn control(exact: bool, opening: Opening) -> TestResult<()> {
    let identity = identity()?;
    let retry = matches!(opening, Opening::RetriedSpare);
    let key = server_key(if retry { 2 } else { 1 }, TEST_ECH_KEYS[usize::from(retry)]);
    let acceptor = acceptor(&identity, Some(&key))?;
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
    let address = listener.local_addr()?;
    let count = match opening {
        #[cfg(windows)]
        Opening::Race => 2,
        _ => 1,
    };
    let mut tasks = JoinSet::new();
    let mut ready = Vec::new();
    for _ in 0..count {
        let (sender, receiver) = oneshot::channel();
        ready.push(receiver);
        tasks.spawn(serve_requests(
            Arc::clone(&listener),
            acceptor.clone(),
            retry,
            sender,
        ));
    }
    tasks.spawn(async move {
        let connections = open(exact, opening, &identity, address).await?;
        assert_eq!(connections.len(), count);
        for receiver in ready {
            receiver.await?;
        }
        for connection in connections {
            for path in ["/first", "/second"] {
                let response = connection
                    .send_get(
                        OriginForm::parse(path)?,
                        vec![RequestHeader::new("Host", INNER_NAME)],
                    )
                    .await?;
                assert_eq!(response.status(), 200);
                assert_eq!(
                    response.into_body().collect().await?.to_bytes().as_ref(),
                    b"ok"
                );
            }
        }
        Ok(())
    });
    let primary = tokio::time::timeout(TEST_TIMEOUT, async {
        while let Some(result) = tasks.join_next().await {
            result??;
        }
        TestResult::<()>::Ok(())
    })
    .await;
    tasks.abort_all();
    let mut cleanup_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                cleanup_error.get_or_insert(error);
            }
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                cleanup_error.get_or_insert(error.into());
            }
        }
    }
    primary??;
    if let Some(error) = cleanup_error {
        return Err(error);
    }
    Ok(())
}

#[tokio::test]
async fn the_ech_retention_route_records_its_connected_family() -> TestResult<()> {
    for exact in [true, false] {
        control(exact, Opening::Composite).await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_retained_ech_connection_authenticates_before_its_first_request_and_is_reused()
-> TestResult<()> {
    for exact in [true, false] {
        control(exact, Opening::Spare).await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_retained_ech_connection_retries_authenticated_rejection_at_its_selected_address()
-> TestResult<()> {
    for exact in [true, false] {
        control(exact, Opening::RetriedSpare).await?;
    }
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn an_actual_backup_race_keeps_its_ech_connection_for_requests() -> TestResult<()> {
    let probe = tokio::net::TcpSocket::new_v6()?;
    match probe.bind(SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 0)) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
            eprintln!("skipped: this host has no IPv6 loopback address");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    drop(probe);
    for exact in [true, false] {
        control(exact, Opening::Race).await?;
    }
    Ok(())
}
