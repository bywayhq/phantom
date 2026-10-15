use super::*;
use crate::route::{DirectTlsSetup, Http2Route, OriginRoute};
use crate::tcp::{AddressFamily, AddressFamilyMemory};
use tokio::sync::oneshot;

#[tokio::test]
async fn connected_opening_is_quiet_until_send_and_preserves_connect_shape() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let connector = test_connector(&identity)?
            .with_tcp_settings(&phantom_profile::browser::firefox::v157_tcp());
        let family = AddressFamilyMemory::new();
        let (opened, opening_ready) = oneshot::channel();
        let (quiet, peer_ready) = oneshot::channel();
        let caller = async {
            let (opening, slower) = connector
                .open_extended_connect(
                    Http2Route::Origin(OriginRoute::Tls {
                        tcp: TcpRoute::Direct(Endpoint {
                            host: "127.0.0.1",
                            port: address.port(),
                        }),
                        server_name: TEST_SERVER_NAME,
                        setup: DirectTlsSetup::KeepSlower(&family),
                    }),
                    TEST_AUTHORITY,
                    OriginForm::parse("/events")?,
                    vec![RequestHeader::new("x-order", "last")],
                )
                .await?;
            assert!(slower.is_none());
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            assert!(!opening.connection().is_closed());
            let debug = format!("{opening:?}");
            assert!(!debug.contains(TEST_AUTHORITY));
            assert!(!debug.contains("/events"));
            opened
                .send(())
                .map_err(|_| "peer ended before connected opening")?;
            peer_ready.await?;
            let outcome = opening.send().await?;
            assert!(matches!(
                outcome,
                super::super::super::Http2ExtendedConnectOutcome::Accepted { .. }
            ));
            drop(outcome);
            TestResult::Ok(())
        };
        let peer = async {
            let (mut stream, _) = accept_tls(listener, acceptor).await?;
            let mut preface = [0; 24];
            stream.read_exact(&mut preface).await?;
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            opening_ready.await?;
            // Before send no request is queued, even if the peer enables it.
            write_raw_frame(&mut stream, 4, 0, 0, &[0, 8, 0, 0, 0, 1]).await?;
            stream.flush().await?;
            loop {
                let frame = read_raw_frame(&mut stream).await?;
                assert_ne!(frame.kind, 1, "connected opening sent CONNECT before send");
                if frame.kind == 4 && frame.flags & 1 == 0 {
                    write_raw_frame(&mut stream, 4, 1, 0, &[]).await?;
                }
                if frame.kind == 4 && frame.flags & 1 != 0 {
                    break;
                }
            }
            assert!(
                timeout(std::time::Duration::from_millis(50), stream.read_u8())
                    .await
                    .is_err()
            );
            quiet
                .send(())
                .map_err(|_| "opening owner ended before quiet barrier")?;
            loop {
                let frame = read_raw_frame(&mut stream).await?;
                if frame.kind != 1 {
                    continue;
                }
                assert_eq!(frame.stream_id, 1);
                assert_eq!(frame.flags & 1, 0, "CONNECT ended its stream on HEADERS");
                write_raw_frame(&mut stream, 1, 4, 1, &[0x88]).await?;
                stream.flush().await?;
                break;
            }
            // Drain the client's cancellation before releasing the real TLS peer.
            loop {
                let frame = read_raw_frame(&mut stream).await?;
                assert_ne!(frame.kind, 1, "opening was sent twice");
                if frame.kind == 3 || frame.kind == 7 {
                    break;
                }
            }
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_connected_opening_headers_fail_without_dialing() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let connector = test_connector(&identity)?;
        let family = AddressFamilyMemory::new();
        let result = connector
            .open_extended_connect(
                Http2Route::Origin(OriginRoute::Tls {
                    tcp: TcpRoute::Direct(Endpoint {
                        host: "127.0.0.1",
                        port: address.port(),
                    }),
                    server_name: TEST_SERVER_NAME,
                    setup: DirectTlsSetup::KeepSlower(&family),
                }),
                TEST_AUTHORITY,
                OriginForm::parse("/")?,
                vec![RequestHeader::new("connection", "upgrade")],
            )
            .await;
        assert!(result.is_err());
        assert_eq!(family.family(), None);
        assert!(
            timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelling_send_while_peer_settings_are_missing_closes_without_connect() -> TestResult<()>
{
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let connector = test_connector(&identity)?;
        let family = AddressFamilyMemory::new();
        let (ready, preface) = oneshot::channel();
        let caller = async {
            let (opening, slower) = connector
                .open_extended_connect(
                    Http2Route::Origin(OriginRoute::Tls {
                        tcp: TcpRoute::Direct(Endpoint {
                            host: "127.0.0.1",
                            port: address.port(),
                        }),
                        server_name: TEST_SERVER_NAME,
                        setup: DirectTlsSetup::KeepSlower(&family),
                    }),
                    TEST_AUTHORITY,
                    OriginForm::parse("/events")?,
                    Vec::new(),
                )
                .await?;
            assert!(slower.is_none());
            preface.await?;
            let mut sending = Box::pin(opening.send());
            assert!(
                std::future::poll_fn(|context| {
                    std::task::Poll::Ready(sending.as_mut().poll(context))
                })
                .await
                .is_pending()
            );
            drop(sending);
            TestResult::Ok(())
        };
        let peer = async {
            let (mut stream, _) = accept_tls(listener, acceptor).await?;
            let mut preface = [0; 24];
            stream.read_exact(&mut preface).await?;
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            ready.send(()).map_err(|_| "opening ended before preface")?;
            loop {
                let frame = read_raw_frame(&mut stream).await?;
                assert_ne!(frame.kind, 1, "cancelled opening sent CONNECT HEADERS");
                assert_ne!(frame.kind, 0, "cancelled opening sent application DATA");
                if frame.kind == 7 {
                    break;
                }
            }
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connected_opening_preserves_certificate_failure_before_http_startup() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let other_root = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let connector = test_connector(&other_root)?;
        let family = AddressFamilyMemory::new();
        let caller = async {
            let result = connector
                .open_extended_connect(
                    Http2Route::Origin(OriginRoute::Tls {
                        tcp: TcpRoute::Direct(Endpoint {
                            host: "127.0.0.1",
                            port: address.port(),
                        }),
                        server_name: TEST_SERVER_NAME,
                        setup: DirectTlsSetup::KeepSlower(&family),
                    }),
                    TEST_AUTHORITY,
                    OriginForm::parse("/events")?,
                    Vec::new(),
                )
                .await;
            assert!(matches!(result, Err(Http2TlsError::Tls(_))));
            TestResult::Ok(())
        };
        let peer = async {
            assert!(
                accept_tls(listener, acceptor).await.is_err(),
                "untrusted handshake unexpectedly completed"
            );
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    })
    .await
}
