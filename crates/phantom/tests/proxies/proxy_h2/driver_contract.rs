use std::{error::Error, io, net::Ipv4Addr, time::Duration};

use http_body_util::BodyExt;
use phantom::{HttpProtocol, HttpProxy, Route};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use crate::support::tunnel_proxy::ConnectionPeer;

use super::{
    H1_ALPN, H2Proxy, Reply, TaskProbe, TaskRole, TestIdentity, TestResult, accept_tls,
    client_builder, read_head, relay_contract::Fault, serve_connects_with_fault,
    serve_forwarded_with_fault, serve_h2_origin,
};

fn permission_denied(error: &(dyn Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
        {
            return true;
        }
        if error
            .downcast_ref::<::http2::Error>()
            .and_then(|error| error.get_io())
            .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
        {
            return true;
        }
        cause = error.source();
    }
    false
}

#[tokio::test]
async fn an_actual_h2_origin_keeps_its_postexchange_accept_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let fault = Fault::default();
    let mut origin = ConnectionPeer::spawn(serve_h2_origin(
        listener,
        identity.acceptor(super::H2_ALPN)?,
        Some(fault.clone()),
    ));
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let probe = TaskProbe::default();
    let observe = probe.clone();
    let mut proxy = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        super::serve_connects_observed(tcp, &acceptor, vec![Reply::Tunnel(address)], Some(observe))
            .await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http2, &format!("https://{address}/nested"))?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), 200);
    assert_eq!(
        timeout(Duration::from_secs(5), response.into_body().collect())
            .await??
            .to_bytes(),
        "h2-in-h2"
    );
    assert!(!origin.is_finished());
    let fixture = timeout(Duration::from_secs(5), &mut proxy).await???;
    assert_eq!(fixture.records.len(), 1);
    assert_eq!(
        fixture.records[0].authority.as_deref(),
        Some(address.to_string().as_str())
    );
    assert_eq!(fault.observations(), 0);
    fault.enable()?;
    let completed = timeout(Duration::from_secs(5), async {
        while !origin.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let joined = timeout(Duration::from_secs(5), &mut origin).await;
    let origin_stop = if joined.is_err() {
        origin.stop().await
    } else {
        Ok(())
    };
    let proxy_stop = probe.backup().await;
    let cleanup = crate::support::tunnel_proxy::finish_with_cleanup(origin_stop, proxy_stop);
    drop(fixture);
    drop(client);
    let checked = (|| {
        completed?;
        assert!(
            fault.observations() > 0,
            "actual H2 origin never returned its controlled accept error"
        );
        let error = joined??
            .err()
            .ok_or("actual H2 origin discarded its postexchange accept error")?;
        assert!(
            permission_denied(error.as_ref()),
            "actual H2 origin lost its typed I/O cause"
        );
        Ok(())
    })();
    crate::support::tunnel_proxy::finish_with_cleanup(checked, cleanup)
}

#[tokio::test]
async fn a_forward_driver_keeps_its_actual_postexchange_accept_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let probe = TaskProbe::default();
    let observe = probe.clone();
    let fault = Fault::default();
    let reader = fault.clone();
    let mut peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        serve_forwarded_with_fault(tcp, &acceptor, &[200], None, Some(observe), Some(reader)).await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http2, "http://driver.test:8080/ready")?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), 200);
    assert_eq!(
        timeout(Duration::from_secs(5), response.into_body().collect())
            .await??
            .to_bytes(),
        "forwarded"
    );
    let record = timeout(Duration::from_secs(5), &mut peer).await???;
    assert_eq!(record.requests.len(), 1);
    assert_eq!(record.requests[0].path, "/ready");
    assert_eq!(record.alpn.as_deref(), Some(b"h2".as_slice()));
    assert!(probe.live().contains(&TaskRole::ForwardDriver));
    assert_eq!(fault.observations(), 0);
    fault.enable()?;
    let completed = timeout(Duration::from_secs(5), async {
        while !record.driver.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let finished = record.finish().await;
    let cleanup = probe.backup().await;
    drop(client);
    let checked = (|| {
        completed?;
        assert!(fault.observations() > 0);
        let error = finished
            .err()
            .ok_or("actual forward driver discarded its postexchange accept error")?;
        assert!(
            permission_denied(error.as_ref()),
            "forward driver lost its typed I/O cause"
        );
        Ok(())
    })();
    crate::support::tunnel_proxy::finish_with_cleanup(checked, cleanup)
}

#[tokio::test]
async fn a_connect_driver_keeps_its_actual_postexchange_accept_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let origin_acceptor = identity.acceptor(H1_ALPN)?;
    let origin = ConnectionPeer::spawn(async move {
        let mut stream = accept_tls(listener, origin_acceptor).await?;
        assert_eq!(
            read_head(&mut stream).await?,
            format!("GET /held HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await?;
        std::future::pending::<()>().await;
        drop(stream);
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let probe = TaskProbe::default();
    let observe = probe.clone();
    let fault = Fault::default();
    let reader = fault.clone();
    let mut peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        serve_connects_with_fault(
            tcp,
            &acceptor,
            vec![Reply::Tunnel(address)],
            Some(observe),
            Some(reader),
        )
        .await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http1, &format!("https://{address}/held"))?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), 200);
    assert_eq!(
        timeout(Duration::from_secs(5), response.into_body().collect())
            .await??
            .to_bytes(),
        "ok"
    );
    let fixture = timeout(Duration::from_secs(5), &mut peer).await???;
    assert_eq!(fixture.records.len(), 1);
    assert_eq!(
        fixture.records[0].authority.as_deref(),
        Some(address.to_string().as_str())
    );
    assert!(!origin.is_finished());
    assert!(probe.live().contains(&TaskRole::ConnectDriver));
    assert_eq!(fault.observations(), 0);
    fault.enable()?;
    let driver = fixture
        .children
        .last()
        .ok_or("actual CONNECT driver absent")?;
    let completed = timeout(Duration::from_secs(5), async {
        while !driver.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let finished = fixture.finish().await;
    let backup = probe.backup().await;
    let origin_stop = origin.stop().await;
    let cleanup = crate::support::tunnel_proxy::finish_with_cleanup(backup, origin_stop);
    drop(client);
    let checked = (|| {
        completed?;
        assert!(fault.observations() > 0);
        let error = finished
            .err()
            .ok_or("actual CONNECT driver discarded its postexchange accept error")?;
        assert!(
            permission_denied(error.as_ref()),
            "CONNECT driver lost its typed I/O cause"
        );
        Ok(())
    })();
    crate::support::tunnel_proxy::finish_with_cleanup(checked, cleanup)
}
