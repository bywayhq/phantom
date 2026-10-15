use std::time::Duration;

use tokio::sync::oneshot;

use super::*;
use crate::{
    host_resolver::HostResolver,
    route::{DirectTlsSetup, Http2Route, OriginRoute},
    tcp::{AddressFamily, AddressFamilyMemory, SlowerAttempt},
};

async fn no_request<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> TestResult<()> {
    loop {
        let frame = read_raw_frame(stream).await?;
        assert_ne!(frame.kind, 1, "backup sent request HEADERS before claim");
        if frame.kind == 4 && frame.flags & 1 == 0 {
            write_raw_frame(stream, 4, 1, 0, &[]).await?;
            stream.flush().await?;
        }
        if frame.kind == 4 && frame.flags & 1 != 0 {
            break;
        }
    }
    // The peer has acknowledged our SETTINGS after writing its startup.
    // Use a cancel-safe read so the quiet window cannot lose half a frame.
    let mut byte = [0];
    assert!(
        timeout(Duration::from_millis(50), stream.read(&mut byte))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn a_connected_backup_authenticates_and_starts_h2_without_a_request() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let connector = test_connector(&identity)?;
        let attempt = SlowerAttempt::scripted(TcpStream::connect(address), Duration::ZERO, None);
        let slower = connector.slower_connection(
            attempt,
            TEST_SERVER_NAME,
            #[cfg(feature = "https-records")]
            None,
        );
        let (ready, quiet) = oneshot::channel();
        let caller = async {
            let connection = slower.finish().await.ok_or("backup setup failed")?;
            quiet.await?;
            request_and_collect(&connection, "/first", vec![]).await?;
            request_and_collect(&connection, "/second", vec![]).await?;
            drop(connection);
            TestResult::Ok(())
        };
        let peer = async {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
            let mut preface = [0; 24];
            stream.read_exact(&mut preface).await?;
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            write_raw_frame(&mut stream, 4, 0, 0, &[]).await?;
            stream.flush().await?;
            no_request(&mut stream).await?;
            ready.send(()).map_err(|_| "backup owner left")?;
            for id in [1, 3] {
                loop {
                    let frame = read_raw_frame(&mut stream).await?;
                    if frame.kind == 4 && frame.flags & 1 == 0 {
                        write_raw_frame(&mut stream, 4, 1, 0, &[]).await?;
                    }
                    if frame.kind == 1 {
                        assert_eq!(frame.stream_id, id);
                        write_raw_frame(&mut stream, 1, 5, id, &[0x89]).await?;
                        stream.flush().await?;
                        break;
                    }
                }
            }
            loop {
                let frame = read_raw_frame(&mut stream).await?;
                assert_ne!(frame.kind, 1, "extra application request");
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
async fn retaining_exact_h2_learns_the_family_without_fabricating_a_backup() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let connector = test_connector(&identity)?
            .with_tcp_settings(&phantom_profile::browser::firefox::v157_tcp())
            .with_host_resolver(
                HostResolver::new().with_override(TEST_SERVER_NAME, vec![address.ip()]),
            );
        let family = AddressFamilyMemory::new();
        let caller = async {
            let (connection, slower) = connector
                .connect(Http2Route::Origin(OriginRoute::Tls {
                    tcp: TcpRoute::Direct(Endpoint {
                        host: TEST_SERVER_NAME,
                        port: address.port(),
                    }),
                    server_name: TEST_SERVER_NAME,
                    setup: DirectTlsSetup::KeepSlower(&family),
                }))
                .await?;
            assert!(slower.is_none());
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            request_and_collect(&connection, "/one", vec![]).await?;
            request_and_collect(&connection, "/two", vec![]).await?;
            drop(connection);
            TestResult::Ok(())
        };
        let peer = async {
            let (stream, _) = accept_tls(listener, acceptor).await?;
            assert_eq!(serve_two_requests(stream).await?, ["/one", "/two"]);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    })
    .await
}
