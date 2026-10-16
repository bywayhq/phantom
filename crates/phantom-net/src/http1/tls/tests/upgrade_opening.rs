use super::*;
use crate::route::Endpoint;
use std::{net::Ipv4Addr, time::Duration};
use tokio::net::TcpListener;

const QUIET: Duration = Duration::from_millis(100);

#[tokio::test]
async fn connected_tls_upgrade_stays_quiet_until_send_and_preserves_fields() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let (opened, peer) = tokio::try_join!(
            async {
                TestResult::<_>::Ok(
                    connector
                        .open_upgrade(
                            OriginRoute::Tls {
                                tcp: TcpRoute::Direct(Endpoint {
                                    host: "127.0.0.1",
                                    port: address.port(),
                                }),
                                server_name: TEST_SERVER_NAME,
                                setup: DirectTlsSetup::Default,
                            },
                            OriginForm::parse("/socket")?,
                            vec![
                                RequestHeader::new("Host", TEST_SERVER_NAME),
                                RequestHeader::new("X-Order", "second"),
                            ],
                        )
                        .await?,
                )
            },
            accept_tls(listener, acceptor),
        )?;
        let (opening, slower) = opened;
        assert!(slower.is_none());
        let (mut peer, _) = peer;
        let mut byte = [0; 1];
        assert!(timeout(QUIET, peer.read(&mut byte)).await.is_err());
        let (result, request) = tokio::try_join!(
            async {
                opening
                    .send()
                    .await
                    .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
            },
            async {
                let head = read_head(&mut peer).await?;
                peer.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                TestResult::<_>::Ok(head)
            },
        )?;
        assert_eq!(
            request,
            format!("GET /socket HTTP/1.1\r\nHost: {TEST_SERVER_NAME}\r\nX-Order: second\r\n\r\n")
                .as_bytes()
        );
        assert!(matches!(result, Http1UpgradeOutcome::Rejected(_)));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropping_a_connected_plaintext_upgrade_closes_without_a_get() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let target = OriginForm::parse("/never-sent")?;
        let (opened, accepted) = tokio::try_join!(
            async {
                connector
                    .open_upgrade(
                        OriginRoute::Plaintext {
                            tcp: TcpRoute::Direct(Endpoint {
                                host: "127.0.0.1",
                                port: address.port(),
                            }),
                            family: None,
                        },
                        target,
                        vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
                    )
                    .await
                    .map_err(io::Error::other)
            },
            listener.accept(),
        )?;
        let (opening, slower) = opened;
        assert!(slower.is_none());
        drop(opening);
        let (mut peer, _) = accepted;
        let mut written = Vec::new();
        peer.read_to_end(&mut written).await?;
        assert!(written.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_upgrade_fields_fail_before_connecting() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let result = connector
            .open_upgrade(
                OriginRoute::Plaintext {
                    tcp: TcpRoute::Direct(Endpoint {
                        host: "127.0.0.1",
                        port: address.port(),
                    }),
                    family: None,
                },
                OriginForm::parse("/")?,
                vec![RequestHeader::new("Host", "bad\r\nInjected: value")],
            )
            .await;
        assert!(result.is_err());
        assert!(timeout(QUIET, listener.accept()).await.is_err());
        Ok(())
    })
    .await
}

mod proxy;
