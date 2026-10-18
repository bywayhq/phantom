use phantom::{HttpProtocol, RequestErrorKind};
use tokio::time::timeout;

use super::*;
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn quic_pin_mismatch_is_typed_before_origin_http() -> TestResult<()> {
    timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let client = builder(&identity)
            .server_spki_pins(ServerSpkiPins::new(vec![[0; 32]])?)
            .build()?;
        let peer = async {
            let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
            assert!(
                incoming.await.is_err(),
                "wrong-pin QUIC handshake completed"
            );
            Ok(())
        };
        let caller = async {
            let error = client
                .get(HttpProtocol::Http3, &format!("https://{address}/"))?
                .send()
                .await
                .err()
                .ok_or("wrong QUIC pin was accepted")?;
            assert_eq!(error.kind(), RequestErrorKind::Tls);
            assert_eq!(tls_error(&error)?, TlsErrorKind::SpkiPinMismatch);
            Ok(())
        };
        let (caller, peer) = tokio::join!(caller, peer);
        endpoint.close(0_u32.into(), b"test complete");
        finish_with_cleanup(caller, peer)
    })
    .await?
}

#[tokio::test]
async fn quic_matching_pin_keeps_connections_usable_and_shared() -> TestResult<()> {
    timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let client = builder(&identity)
            .server_spki_pins(pins(&identity)?)
            .build()?;
        let peer = async {
            let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
            let connection = incoming.await?;
            let mut connection: h3::server::Connection<_, bytes::Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
            for _ in 0..2 {
                let resolver = connection.accept().await?.ok_or("connection closed")?;
                let (_, mut stream) = resolver.resolve_request().await?;
                stream.send_response(http::Response::new(())).await?;
                stream.finish().await?;
            }
            endpoint.wait_idle().await;
            Ok(())
        };
        let caller = async {
            for _ in 0..2 {
                let response = client
                    .clone()
                    .get(HttpProtocol::Http3, &format!("https://{address}/"))?
                    .send()
                    .await?;
                assert_eq!(response.status(), 200);
                response.into_body().collect_with_limit(0).await?;
            }
            drop(client);
            Ok(())
        };
        let (caller, peer) = tokio::join!(caller, peer);
        finish_with_cleanup(caller, peer)
    })
    .await?
}
