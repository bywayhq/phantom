use std::{error::Error, fmt, io, time::Duration};

use phantom::{HttpProtocol, HttpProxy, RequestError, RequestErrorKind, Route};
use tokio::{io::AsyncWriteExt, sync::oneshot, time::timeout};

use super::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls_stream, bind, client_builder,
    finish_h2_proxy_exchange, negotiated_get, observe_h2_proxy_response, read_head, tunnel_proxy,
};

const DEADLINE: Duration = Duration::from_secs(5);
const COMPLETE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
const TRUNCATED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\no";

#[derive(Debug)]
struct OriginFailure;

impl fmt::Display for OriginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("negotiated origin failed after its actual response")
    }
}

impl Error for OriginFailure {}

async fn exchange(response: &'static [u8], outcome: TestResult<()>) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let proxy_identity = TestIdentity::generate()?;
    let (origin_address, listener) = bind().await?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (proxy_address, proxy_listener) = bind().await?;
    let proxy_acceptor = proxy_identity.acceptor(H2_ALPN)?;
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
        .route(Route::http_proxy(
            HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
        ))
        .build()?;
    let (responded, response_seen) = oneshot::channel();
    let origin = tunnel_proxy::ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = accept_tls_stream(tcp, acceptor).await?;
        let selected = stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
        let head = read_head(&mut stream).await?;
        assert_eq!(selected.as_deref(), Some(&b"http/1.1"[..]));
        assert_eq!(
            head,
            format!("GET /observed HTTP/1.1\r\nHost: {origin_address}\r\n\r\n").as_bytes()
        );
        stream.write_all(response).await?;
        stream.shutdown().await?;
        responded
            .send(())
            .map_err(|()| "negotiated origin response observer closed")?;
        // The selected typed outcome is injected after actual request/response I/O.
        outcome?;
        TestResult::Ok(selected)
    });

    let (connected, connect_seen) = oneshot::channel();
    let proxy = tunnel_proxy::ConnectionPeer::spawn(async move {
        // Use the actual HTTP/2 CONNECT fixture, including its owned relay/driver.
        let tunnel =
            tunnel_proxy::http2_connect(proxy_listener, proxy_acceptor, origin_address).await?;
        assert_eq!(
            tunnel.observed.authority.as_deref(),
            Some(origin_address.to_string().as_str())
        );
        connected
            .send(())
            .map_err(|()| "negotiated CONNECT observer closed")?;
        Ok(tunnel)
    });
    let response = async {
        let response = negotiated_get(&client, origin_address, "/observed").await?;
        timeout(DEADLINE, connect_seen).await??;
        timeout(DEADLINE, response_seen).await??;
        timeout(DEADLINE, async {
            while !origin.is_finished() || !proxy.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        TestResult::Ok(response)
    }
    .await;

    let result = match response {
        Ok(response) => observe_h2_proxy_response(response, origin_address, proxy, origin).await,
        Err(error) => finish_h2_proxy_exchange(Err(error), origin_address, proxy, origin).await,
    };
    drop(client);
    result
}

fn assert_truncated(error: &(dyn Error + 'static)) -> TestResult<()> {
    let mut cause = error;
    loop {
        if let Some(request) = cause.downcast_ref::<RequestError>() {
            assert_eq!(request.kind(), RequestErrorKind::Http1);
            assert_eq!(request.protocol(), Some(HttpProtocol::Http1));
            break;
        }
        cause = cause.source().ok_or("missing negotiated request error")?;
    }
    loop {
        if let Some(io) = cause.downcast_ref::<io::Error>() {
            assert_eq!(io.kind(), io::ErrorKind::UnexpectedEof);
            return Ok(());
        }
        cause = cause
            .source()
            .ok_or("missing negotiated truncated-body I/O cause")?;
    }
}

#[tokio::test]
async fn a_truncated_body_keeps_the_completed_origin_failure() -> TestResult<()> {
    let error = timeout(DEADLINE, exchange(TRUNCATED, Err(OriginFailure.into())))
        .await?
        .err()
        .ok_or("truncated negotiated response succeeded")?;
    assert_truncated(error.as_ref())?;
    let failures = error
        .downcast_ref::<tunnel_proxy::connection_peer::FixtureFailures>()
        .ok_or("negotiated caller discarded its completed origin failure")?;
    assert!(failures.cleanup.downcast_ref::<OriginFailure>().is_some());
    Ok(())
}

#[tokio::test]
async fn a_truncated_body_keeps_its_error_with_a_successful_origin() -> TestResult<()> {
    let error = timeout(DEADLINE, exchange(TRUNCATED, Ok(())))
        .await?
        .err()
        .ok_or("truncated negotiated response succeeded")?;
    assert_truncated(error.as_ref())
}

#[tokio::test]
async fn a_complete_body_keeps_its_completed_origin_failure() -> TestResult<()> {
    let error = timeout(DEADLINE, exchange(COMPLETE, Err(OriginFailure.into())))
        .await?
        .err()
        .ok_or("failed negotiated origin succeeded")?;
    assert!(error.downcast_ref::<OriginFailure>().is_some());
    Ok(())
}

#[tokio::test]
async fn a_complete_body_and_origin_keep_the_actual_connect_and_alpn_oracles() -> TestResult<()> {
    timeout(DEADLINE, exchange(COMPLETE, Ok(()))).await?
}
