use std::{net::Ipv4Addr, num::NonZeroUsize};

use phantom::{HttpProtocol, HttpProxy, RedirectPolicy, RequestErrorKind, Route, Socks5Proxy};
use tokio::{net::TcpListener, time::timeout};

use super::*;

#[tokio::test]
async fn cleartext_origin_is_rejected_before_io_with_or_without_redirects() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    for redirects in [
        RedirectPolicy::none(),
        RedirectPolicy::limited(NonZeroUsize::MIN),
    ] {
        let client = builder(&identity)
            .server_spki_pins(pins(&identity)?)
            .redirect_policy(redirects)
            .build()?;
        let error = client
            .get(HttpProtocol::Http1, &format!("http://{address}/"))?
            .send()
            .await
            .err()
            .ok_or("cleartext origin bypassed pin policy")?;
        assert_eq!(error.kind(), RequestErrorKind::ServerPinPolicy);
    }
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn proxy_pins_reject_plaintext_http_and_socks_before_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let client = builder(&identity)
        .proxy_server_spki_pins(pins(&identity)?)
        .build()?;
    for route in [
        Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?),
        Route::socks5(Socks5Proxy::new(&format!("socks5://{address}"))?),
    ] {
        let error = client
            .get(HttpProtocol::Http1, "https://origin.phantom.test/")?
            .route(route)
            .send()
            .await
            .err()
            .ok_or("plaintext proxy bypassed pin policy")?;
        assert_eq!(error.kind(), RequestErrorKind::ServerPinPolicy);
    }
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn secure_forward_proxy_cannot_bypass_cleartext_origin_restriction() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let client = builder(&identity)
        .server_spki_pins(pins(&identity)?)
        .build()?;
    let error = client
        .get(HttpProtocol::Http1, "http://origin.phantom.test/")?
        .route(Route::http_proxy(HttpProxy::new(&format!(
            "https://{address}"
        ))?))
        .send()
        .await
        .err()
        .ok_or("secure proxy bypassed cleartext origin restriction")?;
    assert_eq!(error.kind(), RequestErrorKind::ServerPinPolicy);
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_cleartext_origin_is_rejected_before_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let client = Client::builder(
        ClientProfile::new(tls_settings())
            .with_websocket(phantom::profile::browser::chrome::v154_websocket()),
    )
    .server_spki_pins(pins(&identity)?)
    .build()?;
    let error = client
        .websocket_with_protocol(HttpProtocol::Http1, &format!("ws://{address}/"))?
        .connect()
        .await
        .err()
        .ok_or("cleartext WebSocket bypassed pin policy")?;
    assert_eq!(error.kind(), phantom::WebSocketErrorKind::ServerPinPolicy);
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[cfg(feature = "danger-disable-verification")]
#[test]
fn pins_cannot_replace_certificate_or_hostname_verification() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    for proxy in [false, true] {
        let builder = Client::builder(ClientProfile::new(tls_settings()));
        let builder = if proxy {
            builder
                .proxy_server_spki_pins(pins(&identity)?)
                .proxy_server_authentication(phantom::ServerAuthentication::DangerDisabled)
        } else {
            builder
                .server_spki_pins(pins(&identity)?)
                .server_authentication(phantom::ServerAuthentication::DangerDisabled)
        };
        let error = builder
            .build()
            .err()
            .ok_or("pins disabled normal verification")?;
        assert_eq!(error.kind(), phantom::BuildErrorKind::InvalidPolicy);
    }
    Ok(())
}
