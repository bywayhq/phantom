use std::{error::Error, net::Ipv4Addr, time::Duration};

use phantom::profile::{InvalidRequestTemplate, RequestField};
use phantom::{HttpProtocol, PreparedRequestTemplate, RequestError, RequestErrorKind};
use phantom_net::{TlsError, TlsErrorKind, proxy::HttpConnectError};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use crate::support::tunnel_proxy::ConnectionPeer;

use super::{
    Browser, Client, ClientProfile, HttpProxy, Route, TestResult, browsers, head_names,
    open_tunnel, profile_client, read_head, record_connects,
};

const DEADLINE: Duration = Duration::from_secs(5);
const REJECTED: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

fn source<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(found) = error.downcast_ref::<T>() {
            return Some(found);
        }

        error = error.source()?;
    }
}

fn assert_connect(head: &str, port: u16) -> TestResult<()> {
    let (line, _) = head_names(head)?;
    assert_eq!(line, format!("CONNECT origin.phantom.test:{port} HTTP/1.1"));
    assert!(head.contains(&format!("\r\nHost: origin.phantom.test:{port}\r\n")));
    Ok(())
}

async fn rejecting_proxy() -> TestResult<(Client, Browser, ConnectionPeer<TestResult<String>>)> {
    let browser = browsers().swap_remove(0);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
    let server = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let head = String::from_utf8(read_head(&mut stream).await?)?;
        stream.write_all(REJECTED).await?;
        stream.shutdown().await?;
        Ok(head)
    });
    let client = profile_client(&browser, Route::http_proxy(proxy))?;
    Ok((client, browser, server))
}

fn assert_proxy_rejection(error: &(dyn Error + 'static)) -> TestResult<()> {
    let request = source::<RequestError>(error).ok_or("tunnel attempt lost its RequestError")?;
    assert_eq!(request.kind(), RequestErrorKind::Proxy);
    assert!(matches!(
        source::<HttpConnectError>(error),
        Some(HttpConnectError::Rejected { status: 502 })
    ));
    Ok(())
}

fn assert_peer_closed_tls(error: &(dyn Error + 'static)) -> TestResult<()> {
    let tls =
        source::<TlsError>(error).ok_or("closed tunnel did not reach typed origin TLS setup")?;
    assert_eq!(tls.kind(), TlsErrorKind::Handshake);
    assert!(source::<btls::ssl::Error>(error).is_some());
    Ok(())
}

#[tokio::test]
async fn an_invalid_navigation_template_is_not_a_successful_tunnel_attempt() -> TestResult<()> {
    let mut browser = browsers().swap_remove(0);
    browser.navigation.http1_fields.push(RequestField::Literal {
        name: "X-Invalid".into(),
        value: "invalid\r\nvalue".into(),
    });
    assert!(PreparedRequestTemplate::new(browser.navigation.clone()).is_err());
    let client = Client::builder(ClientProfile::new(browser.tls.clone())).build()?;
    let result = open_tunnel(&client, &browser, Vec::new()).await;

    let error = result
        .err()
        .ok_or("invalid navigation template was silently skipped")?;
    assert!(source::<InvalidRequestTemplate>(error.as_ref()).is_some());
    Ok(())
}

#[tokio::test]
async fn an_actual_rejected_connect_is_not_an_expected_origin_tls_failure() -> TestResult<()> {
    let (client, browser, server) = rejecting_proxy().await?;
    let result = timeout(DEADLINE, open_tunnel(&client, &browser, Vec::new())).await?;
    let head = timeout(DEADLINE, server).await???;
    assert_connect(&head, 443)?;
    drop(client);

    let error = result
        .err()
        .ok_or("rejected CONNECT was discarded as an expected origin failure")?;
    assert_proxy_rejection(error.as_ref())
}

#[tokio::test]
async fn the_recording_proxy_closes_after_connect_at_the_origin_tls_handshake() -> TestResult<()> {
    let browser = browsers().swap_remove(0);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
    let server = ConnectionPeer::spawn(record_connects(listener, 0, 2));
    let client = profile_client(&browser, Route::http_proxy(proxy))?;
    timeout(DEADLINE, open_tunnel(&client, &browser, Vec::new())).await??;
    let request = client
        .get(HttpProtocol::Http1, "https://origin.phantom.test/page")?
        .send()
        .await;
    let heads = timeout(DEADLINE, server).await???;
    assert_eq!(heads.len(), 2);
    for head in heads {
        assert_connect(&head, 443)?;
    }
    drop(client);

    let error = request
        .err()
        .ok_or("recording proxy unexpectedly served the origin request")?;
    assert_eq!(error.kind(), RequestErrorKind::Tls);
    assert_peer_closed_tls(&error)
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn an_actual_wss_proxy_rejection_is_not_an_expected_origin_tls_failure() -> TestResult<()> {
    let (client, browser, server) = rejecting_proxy().await?;
    let result = timeout(DEADLINE, super::open_wss_tunnel(&client, &browser)).await?;
    let head = timeout(DEADLINE, server).await???;
    assert_connect(&head, 8443)?;
    drop(client);

    let error = result
        .err()
        .ok_or("rejected WSS CONNECT was discarded as an expected origin failure")?;
    let opening = source::<phantom::WebSocketError>(error.as_ref())
        .ok_or("WSS attempt lost its typed opening error")?;
    assert_eq!(opening.kind(), phantom::WebSocketErrorKind::Proxy);
    assert!(matches!(
        source::<HttpConnectError>(error.as_ref()),
        Some(HttpConnectError::Rejected { status: 502 })
    ));
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn the_recording_proxy_closes_wss_at_the_origin_tls_handshake() -> TestResult<()> {
    let browser = browsers().swap_remove(0);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
    let server = ConnectionPeer::spawn(record_connects(listener, 0, 2));
    let client = profile_client(&browser, Route::http_proxy(proxy))?;
    timeout(DEADLINE, super::open_wss_tunnel(&client, &browser)).await??;
    let opening = client
        .websocket("wss://origin.phantom.test:8443/tls")?
        .connect()
        .await;
    let heads = timeout(DEADLINE, server).await???;
    assert_eq!(heads.len(), 2);
    for head in heads {
        assert_connect(&head, 8443)?;
    }
    drop(client);

    let error = opening
        .err()
        .ok_or("recording proxy unexpectedly opened a WSS session")?;
    assert_eq!(error.kind(), phantom::WebSocketErrorKind::Tls);
    assert_peer_closed_tls(&error)
}
