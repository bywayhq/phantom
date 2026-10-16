use super::TestResult;
use crate::{
    direct::Dialer,
    host_resolver::{AddressResolver, HostResolver},
    proxy::{Socks5Auth, Socks5ErrorKind, socks5_tunnel_local_dns, socks5_tunnel_remote_dns},
};
use phantom_profile::{DnsAddressFailurePolicy, browser::chrome};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

const WAIT: Duration = Duration::from_secs(5);
const REFUSED: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
const REACHED: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));

fn resolver(names: Arc<Mutex<Vec<String>>>) -> HostResolver {
    let mut settings = chrome::v154_dns_cache();
    settings.address_failure_policy = DnsAddressFailurePolicy::Record {
        max_unusable_addresses: NonZeroUsize::MIN,
    };
    HostResolver::new()
        .with_resolver(AddressResolver::from_fn(move |host| {
            let result = names
                .lock()
                .map_err(|_| io::Error::other("name log poisoned"))
                .map(|mut names| {
                    names.push(host.clone());
                    if host == "proxy.test" {
                        vec![REFUSED, REACHED]
                    } else {
                        vec![TARGET]
                    }
                });
            async move { result }
        }))
        .with_cache(settings)
}
async fn next(resolver: &HostResolver, host: &str, port: u16) -> TestResult<SocketAddr> {
    Ok(
        crate::host_resolver::resolve_tcp(Some(resolver), host, port)
            .await?
            .cursor()
            .next()
            .ok_or("no candidate")?
            .address(),
    )
}
fn both(client: TestResult, peer: TestResult) -> TestResult {
    match (client, peer) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; peer: {cleanup}").into()),
    }
}

#[tokio::test]
async fn actual_refused_connect_is_shared_but_successful_eof_is_not_an_ip_failure() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let resolver = resolver(Arc::default());
    let client = async {
        let mut stream =
            super::super::connect("proxy.test", port, None, None, Some(&resolver)).await?;
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await?, 0);
        assert_eq!(next(&resolver, "proxy.test", port).await?.ip(), REACHED);
        Ok(())
    };
    let peer = async {
        let (stream, _) = listener.accept().await?;
        drop(stream);
        Ok(())
    };
    let (client, peer) = tokio::time::timeout(WAIT, async { tokio::join!(client, peer) }).await?;
    both(client, peer)
}

#[tokio::test]
async fn local_socks_rejection_does_not_poison_target_or_successful_proxy_ip() -> TestResult {
    socks_rejection(false, false).await
}
#[tokio::test]
async fn remote_socks_dns_never_performs_a_local_target_lookup() -> TestResult {
    socks_rejection(true, false).await
}
#[tokio::test]
async fn socks_authentication_failure_does_not_poison_successful_proxy_ip() -> TestResult {
    socks_rejection(true, true).await
}
async fn socks_rejection(remote: bool, authentication: bool) -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let names = Arc::new(Mutex::new(Vec::new()));
    let resolver = resolver(Arc::clone(&names));
    let client = async {
        let dialer = Dialer {
            resolver: Some(&resolver),
            ..Dialer::default()
        };
        let result = if remote {
            socks5_tunnel_remote_dns(
                dialer,
                "proxy.test",
                port,
                "target.test",
                443,
                Socks5Auth::None,
            )
            .await
        } else {
            socks5_tunnel_local_dns(
                dialer,
                "proxy.test",
                port,
                "target.test",
                443,
                Socks5Auth::None,
            )
            .await
        };
        let error = match result {
            Err(error) => error,
            Ok(_) => return Err("unexpected tunnel".into()),
        };
        assert_eq!(
            error.kind(),
            if authentication {
                Socks5ErrorKind::Authentication
            } else {
                Socks5ErrorKind::Rejected
            }
        );
        assert_eq!(next(&resolver, "proxy.test", port).await?.ip(), REACHED);
        let observed = names.lock().map_err(|_| "name log poisoned")?.clone();
        assert_eq!(
            observed
                .iter()
                .filter(|name| name.as_str() == "proxy.test")
                .count(),
            1
        );
        assert_eq!(
            observed
                .iter()
                .filter(|name| name.as_str() == "target.test")
                .count(),
            usize::from(!remote)
        );
        if !remote {
            assert_eq!(next(&resolver, "target.test", 443).await?.ip(), TARGET);
        }
        Ok(())
    };
    let peer = async {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 0]);
        if authentication {
            stream.write_all(&[5, 255]).await?;
            return Ok(());
        }
        stream.write_all(&[5, 0]).await?;
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        assert_eq!(header, [5, 1, 0, if remote { 3 } else { 1 }]);
        if remote {
            let length = stream.read_u8().await?;
            let mut name = vec![0; usize::from(length)];
            stream.read_exact(&mut name).await?;
            assert_eq!(name, b"target.test");
        } else {
            let mut address = [0; 4];
            stream.read_exact(&mut address).await?;
            assert_eq!(address, [127, 0, 0, 3]);
        }
        assert_eq!(stream.read_u16().await?, 443);
        stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        Ok(())
    };
    let (client, peer) = tokio::time::timeout(WAIT, async { tokio::join!(client, peer) }).await?;
    both(client, peer)
}

fn resource_error() -> io::Error {
    use crate::host_resolver::address_feedback::FeedbackResourceError;
    io::Error::other(super::super::ConnectFeedbackError {
        connect: io::Error::from(io::ErrorKind::ConnectionRefused),
        feedback: io::Error::other(FeedbackResourceError::HistoryCapacity {
            limit: NonZeroUsize::MIN,
        }),
    })
}
fn candidates() -> TestResult<crate::host_resolver::tcp_addresses::TcpAddresses> {
    Ok(vec!["127.0.0.1:443".parse()?, "127.0.0.2:443".parse()?].into())
}
#[tokio::test]
async fn sequential_capacity_error_never_retries_even_after_any_failure() -> TestResult {
    let calls = std::cell::Cell::new(0);
    let result = super::super::connect_candidates_sequentially(
        candidates()?,
        phantom_profile::TcpAddressAdvance::AfterAnyFailure,
        |_| {
            calls.set(calls.get() + 1);
            std::future::ready(Err::<(), _>(resource_error()))
        },
    )
    .await;
    assert!(
        result
            .as_ref()
            .is_err_and(super::super::is_feedback_resource_error)
    );
    assert_eq!(calls.get(), 1);
    Ok(())
}
#[tokio::test]
async fn racing_capacity_error_never_starts_another_address() -> TestResult {
    let calls = std::cell::Cell::new(0);
    let result = super::super::address_racing::race_candidates(
        candidates()?,
        std::future::pending(),
        |_| {
            calls.set(calls.get() + 1);
            std::future::ready(Err::<(), _>(resource_error()))
        },
    )
    .await;
    assert!(
        result
            .as_ref()
            .is_err_and(super::super::is_feedback_resource_error)
    );
    assert_eq!(calls.get(), 1);
    Ok(())
}
#[tokio::test]
async fn backup_capacity_error_never_starts_another_address() -> TestResult {
    let calls = std::cell::Cell::new(0);
    let plan = super::super::backup_connection::Plan {
        family: None,
        known_family_backup_timeout: None,
    };
    let result = super::super::backup_connection::connect_candidates(
        candidates()?,
        plan,
        std::future::pending(),
        |_, _| {
            calls.set(calls.get() + 1);
            std::future::ready(Err::<(), _>(resource_error()))
        },
        std::time::Instant::now(),
    )
    .await;
    assert!(
        result
            .as_ref()
            .is_err_and(super::super::is_feedback_resource_error)
    );
    assert_eq!(calls.get(), 1);
    Ok(())
}

#[tokio::test]
async fn an_invalid_backup_deadline_precedes_socket_setup_without_recording_failure() -> TestResult
{
    let resolver = resolver(Arc::default());
    let resolved = crate::host_resolver::resolve_tcp(Some(&resolver), "proxy.test", 443).await?;
    let candidate = resolved.cursor().next().ok_or("no candidate")?;
    let source = crate::SourceBinding::new().with_address(std::net::Ipv6Addr::LOCALHOST.into());
    let result =
        super::super::connect_candidate_within(candidate, None, Some(&source), Some(Duration::MAX))
            .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => return Err("invalid deadline unexpectedly connected".into()),
    };
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(
        error.to_string(),
        "could not schedule the connection fallback timer"
    );
    assert_eq!(next(&resolver, "proxy.test", 443).await?.ip(), REFUSED);
    Ok(())
}
