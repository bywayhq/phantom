use phantom::{ConnectUdpProxy, HttpProtocol, Route};
use tokio::time::timeout;

use super::*;
use crate::support::{
    masque::{MasqueProxy, ProxyMode, masque_client_settings},
    tunnel_proxy::finish_with_cleanup,
};

#[tokio::test]
async fn connect_udp_outer_pin_rejection_precedes_connect() -> TestResult<()> {
    timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let client = builder(&identity)
            .add_proxy_root_certificate_der(identity.root_der.clone())
            .proxy_server_spki_pins(ServerSpkiPins::new(vec![[0; 32]])?)
            .route(Route::connect_udp(ConnectUdpProxy::new(&format!(
                "https://{address}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
            ))?))
            .build()?;
        let peer = async {
            let incoming = endpoint.accept().await.ok_or("proxy endpoint closed")?;
            assert!(incoming.await.is_err(), "wrong outer pin completed TLS");
            TestResult::Ok(())
        };
        let caller = async {
            let error = client
                .get(HttpProtocol::Http3, "https://127.0.0.1:443/")?
                .send()
                .await
                .err()
                .ok_or("wrong outer pin was accepted")?;
            assert_eq!(tls_error(&error)?, TlsErrorKind::SpkiPinMismatch);
            TestResult::Ok(())
        };
        let (caller, peer) = tokio::join!(caller, peer);
        endpoint.close(0_u32.into(), b"test complete");
        finish_with_cleanup(caller, peer)
    })
    .await?
}

#[tokio::test]
async fn connect_udp_enforces_separate_matching_origin_and_proxy_pins() -> TestResult<()> {
    timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let mut proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let client = Client::builder(
            ClientProfile::new(tls_settings()).with_http3(masque_client_settings()),
        )
        .add_root_certificate_der(identity.root_der.clone())
        .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
        .server_spki_pins(pins(&identity)?)
        .proxy_server_spki_pins(pins(&proxy_identity)?)
        .route(Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?))
        .build()?;
        let peer = async {
            let (_, mut stream, mut connection) = h3_support::accept_request(&endpoint).await?;
            stream.send_response(http::Response::new(())).await?;
            stream.finish().await?;
            let _ = connection.accept().await;
            TestResult::Ok(())
        };
        let caller = async {
            let response = client
                .get(HttpProtocol::Http3, &format!("https://{address}/"))?
                .send()
                .await?;
            assert_eq!(response.status(), 200);
            response.into_body().collect_with_limit(0).await?;
            assert_eq!(proxy.requests().len(), 1);
            drop(client);
            TestResult::Ok(())
        };
        let (caller, peer) = tokio::join!(caller, peer);
        endpoint.close(0_u32.into(), b"test complete");
        finish_with_cleanup(finish_with_cleanup(caller, peer), proxy.finish().await)
    })
    .await?
}
