use std::{io, net::SocketAddr, task::Poll, time::Duration};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::proxy_h2::relay_contract::Fault;

use super::{
    OriginFaults, TestIdentity, TestResult, chromium_profile, client, get_forwarded, get_https,
    peer_contract::{TaskProbe, TaskRole},
    seen, spawn_origin_fixture_with_faults, spawn_proxy_fixture_with_faults,
};

pub(super) async fn accept(
    listener: &TcpListener,
    fault: Option<&Fault>,
) -> io::Result<(TcpStream, SocketAddr)> {
    let Some(fault) = fault else {
        return listener.accept().await;
    };
    std::future::poll_fn(|context| {
        if let Some(error) = fault.error(context) {
            return Poll::Ready(Err(error));
        }
        listener.poll_accept(context)
    })
    .await
}

#[derive(Clone, Copy)]
enum Owner {
    Proxy,
    Origin,
}

async fn actual_listener_failure(owner: Owner) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let proxy_probe = TaskProbe::default();
    let origin_probe = TaskProbe::default();
    let fault = Fault::default();
    let proxy = spawn_proxy_fixture_with_faults(
        &identity,
        None,
        Some(proxy_probe.clone()),
        None,
        matches!(owner, Owner::Proxy).then(|| fault.clone()),
    )
    .await?;
    let origin = spawn_origin_fixture_with_faults(
        &identity,
        Some(origin_probe.clone()),
        OriginFaults {
            accept: matches!(owner, Owner::Origin).then(|| fault.clone()),
            ..OriginFaults::default()
        },
    )
    .await?;
    let client = client(chromium_profile(), &identity, &identity, proxy.address)?;
    match owner {
        Owner::Proxy => {
            timeout(
                Duration::from_secs(5),
                get_forwarded(&client, "listener.test:8080"),
            )
            .await??
        }
        Owner::Origin => {
            timeout(Duration::from_secs(5), get_https(&client, origin.address)).await??
        }
    }
    let records = seen(&proxy.log);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].method,
        match owner {
            Owner::Proxy => http::Method::GET,
            Owner::Origin => http::Method::CONNECT,
        }
    );
    assert_eq!(fault.observations(), 0);
    assert!(proxy_probe.live().contains(&TaskRole::ProxyListener));
    assert!(origin_probe.live().contains(&TaskRole::OriginListener));
    fault.enable()?;
    let completed = timeout(Duration::from_secs(5), async {
        while match owner {
            Owner::Proxy => !proxy.listener.is_finished(),
            Owner::Origin => !origin.listener.is_finished(),
        } {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let returned = match owner {
        Owner::Proxy => proxy.finish().await,
        Owner::Origin => origin.finish().await,
    };
    let proxy_stop = proxy_probe.backup().await;
    let origin_stop = origin_probe.backup().await;
    let cleanup = crate::support::tunnel_proxy::finish_with_cleanup(proxy_stop, origin_stop);
    drop(client);
    let checked = (|| {
        completed?;
        assert!(
            fault.observations() > 0,
            "actual listener never returned the controlled accept error"
        );
        let error = returned
            .err()
            .ok_or("actual listener discarded its controlled postexchange accept error")?;
        assert_eq!(
            error
                .downcast_ref::<io::Error>()
                .ok_or("listener lost its typed accept error")?
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        Ok(())
    })();
    crate::support::tunnel_proxy::finish_with_cleanup(checked, cleanup)
}

#[tokio::test]
async fn actual_proxy_listener_keeps_its_postexchange_accept_error() -> TestResult<()> {
    actual_listener_failure(Owner::Proxy).await
}

#[tokio::test]
async fn actual_origin_listener_keeps_its_postexchange_accept_error() -> TestResult<()> {
    actual_listener_failure(Owner::Origin).await
}

#[tokio::test]
async fn actual_proxy_keeps_an_unrelated_tls_failure_after_a_healthy_exchange() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let probe = TaskProbe::default();
    let fixture = super::spawn_proxy_fixture(&identity, None, Some(probe.clone())).await?;
    let client = client(chromium_profile(), &identity, &identity, fixture.address)?;
    timeout(
        Duration::from_secs(5),
        get_forwarded(&client, "healthy-tls.test:8080"),
    )
    .await??;
    assert_eq!(seen(&fixture.log).len(), 1);
    assert_eq!(fixture.completed_handlers()?, 0);
    assert!(probe.live().contains(&TaskRole::ProxyConnection));
    let mut invalid =
        timeout(Duration::from_secs(5), TcpStream::connect(fixture.address)).await??;
    timeout(
        Duration::from_secs(5),
        invalid.write_all(b"GET /not-tls HTTP/1.0\r\n\r\n"),
    )
    .await??;
    timeout(Duration::from_secs(5), invalid.shutdown()).await??;
    let completed = timeout(Duration::from_secs(5), async {
        while fixture.completed_handlers()? != 1 {
            tokio::task::yield_now().await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    let returned = fixture.finish().await;
    let cleanup = probe.backup().await;
    drop(client);
    let checked = (|| {
        completed??;
        let error = returned
            .err()
            .ok_or("actual proxy discarded its unrelated TLS handshake failure")?;
        assert!(
            error.downcast_ref::<btls::ssl::Error>().is_some(),
            "actual proxy lost its TLS error type"
        );
        Ok(())
    })();
    crate::support::tunnel_proxy::finish_with_cleanup(checked, cleanup)
}
