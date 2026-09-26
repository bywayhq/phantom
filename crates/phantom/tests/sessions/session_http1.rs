//! HTTP/1.1 session connection lifecycle tests.

use crate::support::tls as tls_support;

use std::{
    error::Error, future::Future, net::Ipv4Addr, num::NonZeroUsize, pin::Pin, time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, ServerAuthentication, profile::ClientProfile,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use tls_support::{H1_ALPN, TestIdentity, client_builder, read_head, test_client, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn canonical_and_unicode_equivalent_hosts_reuse_one_connection() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_one(&listener, &acceptor).await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
                .await?;
            let second = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first, second))
        });

        let session = test_client(&identity, false)?.session();
        let first = session
            .get(
                HttpProtocol::Http1,
                &format!("https://１２７．０．０．１:{}/first", address.port()),
            )?
            .send()
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes();
        let second = session
            .get(HttpProtocol::Http1, &format!("https://{address}/second"))?
            .send()
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes();
        assert_eq!(first, "first");
        assert_eq!(second, "second");

        let (first, second) = server.await??;
        assert_eq!(
            first,
            format!(
                "GET /first HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                address.port()
            )
            .as_bytes()
        );
        assert_eq!(
            second,
            format!(
                "GET /second HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                address.port()
            )
            .as_bytes()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_requests_reuse_one_connection() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_one(&listener, &acceptor).await?;
            for _ in 0..2 {
                read_head(&mut stream).await?;
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await?;
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = test_client(&identity, false)?;
        for path in ["first", "second"] {
            client
                .get(HttpProtocol::Http1, &format!("https://{address}/{path}"))?
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
        }
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn disabled_authentication_replaces_connections_without_session_resumption() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let first_acceptor = identity.acceptor(H1_ALPN)?;
        let second_acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_one(&listener, &first_acceptor).await?;
            read_head(&mut first).await?;
            first
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            drop(first);

            let mut second = accept_one(&listener, &second_acceptor).await?;
            read_head(&mut second).await?;
            second
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = Client::builder(ClientProfile::new(tls_settings()))
            .server_authentication(ServerAuthentication::Disabled)
            .build()?;
        for path in ["first", "second"] {
            client
                .get(HttpProtocol::Http1, &format!("https://{address}/{path}"))?
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
        }

        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connection_close_response_is_replaced_without_replay() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_one(&listener, &acceptor).await?;
            let first_head = read_head(&mut first).await?;
            first
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .await?;
            drop(first);

            let mut second = accept_one(&listener, &acceptor).await?;
            let second_head = read_head(&mut second).await?;
            second
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first_head, second_head))
        });

        let session = test_client(&identity, false)?.session();
        for path in ["first", "second"] {
            session
                .get(HttpProtocol::Http1, &format!("https://{address}/{path}"))?
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
        }
        let (first, second) = server.await??;
        assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /second HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn segmented_close_response_is_reassembled_before_connection_replacement() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_one(&listener, &acceptor).await?;
            let first_head = read_head(&mut first).await?;
            let body = b"segmented response body";
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let segments: [&[u8]; 6] = [
                b"HTTP/1.",
                b"1 200 OK\r\n",
                &head.as_bytes()[17..head.len() - 3],
                &head.as_bytes()[head.len() - 3..],
                &body[..17],
                &body[17..],
            ];
            for segment in segments {
                first.write_all(segment).await?;
                first.flush().await?;
                tokio::task::yield_now().await;
            }
            drop(first);

            let mut second = accept_one(&listener, &acceptor).await?;
            let second_head = read_head(&mut second).await?;
            second
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first_head, second_head))
        });

        let session = test_client(&identity, false)?.session();
        let first = session
            .get(HttpProtocol::Http1, &format!("https://{address}/segmented"))?
            .send()
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes();
        assert_eq!(first, "segmented response body");

        let second = session
            .get(HttpProtocol::Http1, &format!("https://{address}/followup"))?
            .send()
            .await?;
        assert_eq!(second.status(), 204);
        assert!(second.into_body().collect().await?.to_bytes().is_empty());

        let (first_head, second_head) = server.await??;
        assert!(first_head.starts_with(b"GET /segmented HTTP/1.1\r\n"));
        assert!(second_head.starts_with(b"GET /followup HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn incomplete_body_is_discarded_before_the_next_request() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_one(&listener, &acceptor).await?;
            read_head(&mut first).await?;
            first
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                .await?;
            let mut remaining = Vec::new();
            first.read_to_end(&mut remaining).await?;

            let mut second = accept_one(&listener, &acceptor).await?;
            let second_head = read_head(&mut second).await?;
            second
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(second_head)
        });

        let session = test_client(&identity, false)?.session();
        let first = session
            .get(HttpProtocol::Http1, &format!("https://{address}/first"))?
            .send()
            .await?;
        drop(first);
        session
            .get(HttpProtocol::Http1, &format!("https://{address}/second"))?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;

        let second = server.await??;
        assert!(second.starts_with(b"GET /second HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn truncated_chunked_body_fails_and_replaces_the_connection() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_one(&listener, &acceptor).await?;
            let first_head = read_head(&mut first).await?;
            // curl/curl test207 at 01346829096c61b372692f6dc43ffa778c6caccd.
            first
                .write_all(
                    b"HTTP/1.1 200 funky chunky! swsclose\r\n\
                      Server: fakeit/0.9 fakeitbad/1.0\r\n\
                      Transfer-Encoding: chunked\r\n\
                      Connection: mooo\r\n\r\n\
                      41\r\n",
                )
                .await?;
            first.write_all(&[b'a'; 64]).await?;
            first.write_all(b"\n\r\n").await?;
            first.flush().await?;
            drop(first);

            let mut replacement = accept_one(&listener, &acceptor).await?;
            let replacement_head = read_head(&mut replacement).await?;
            replacement
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first_head, replacement_head))
        });

        let session = test_client(&identity, false)?.session();
        let mut body = session
            .get(HttpProtocol::Http1, &format!("https://{address}/truncated"))?
            .send()
            .await?
            .into_body();
        let mut received = Vec::new();
        let mut body_error = None;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    let data = frame
                        .into_data()
                        .map_err(|_| "truncated response emitted unexpected trailers")?;
                    received.extend_from_slice(&data);
                }
                Err(error) => {
                    body_error = Some(error);
                    break;
                }
            }
        }
        let error = body_error.ok_or("truncated chunked response completed successfully")?;
        assert_eq!(error.kind(), RequestErrorKind::Http1);
        assert_eq!(received, [vec![b'a'; 64], vec![b'\n']].concat());

        let followup = session
            .get(HttpProtocol::Http1, &format!("https://{address}/followup"))?
            .send()
            .await?;
        assert_eq!(followup.status(), 204);
        assert!(followup.into_body().collect().await?.to_bytes().is_empty());

        let (first, replacement) = server.await??;
        assert!(first.starts_with(b"GET /truncated HTTP/1.1\r\n"));
        assert!(replacement.starts_with(b"GET /followup HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn pending_requests_are_bounded_while_a_body_is_active() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_one(&listener, &acceptor).await?;
            read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                .await?;
            let mut remaining = Vec::new();
            stream.read_to_end(&mut remaining).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let session = client_builder(&identity, false)
            .max_pending_http1_requests_per_origin(NonZeroUsize::MIN)
            .build()?;
        let active = session
            .get(HttpProtocol::Http1, &format!("https://{address}/active"))?
            .send()
            .await?;
        let first_waiter = session.get(
            HttpProtocol::Http1,
            &format!("https://{address}/waiting-one"),
        )?;
        let second_waiter = session.get(
            HttpProtocol::Http1,
            &format!("https://{address}/waiting-two"),
        )?;
        let mut first_waiter = tokio::spawn(first_waiter.send());
        let mut second_waiter = tokio::spawn(second_waiter.send());

        let rejected = tokio::select! {
            result = &mut first_waiter => {
                second_waiter.abort();
                result?
            }
            result = &mut second_waiter => {
                first_waiter.abort();
                result?
            }
        };
        let error = match rejected {
            Ok(_) => return Err("excess HTTP/1 waiter was admitted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Capacity);

        drop(active);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reused_send_failure_is_not_replayed() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (release_tx, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut first = accept_one(&listener, &acceptor).await?;
            let first_head = read_head(&mut first).await?;
            first
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            release_rx.await?;
            let failed_head = read_head(&mut first).await?;
            drop(first);

            let mut replacement = accept_one(&listener, &acceptor).await?;
            let later_head = read_head(&mut replacement).await?;
            replacement
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first_head, failed_head, later_head))
        });

        let session = test_client(&identity, false)?.session();
        session
            .get(HttpProtocol::Http1, &format!("https://{address}/first"))?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        let _ = release_tx.send(());

        let failed = session
            .get(HttpProtocol::Http1, &format!("https://{address}/second"))?
            .send()
            .await;
        let error = match failed {
            Ok(_) => return Err("failed reused HTTP/1 request was hidden".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Http1);

        session
            .get(HttpProtocol::Http1, &format!("https://{address}/third"))?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;

        let (first, failed, later) = server.await??;
        assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(failed.starts_with(b"GET /second HTTP/1.1\r\n"));
        assert!(later.starts_with(b"GET /third HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

async fn accept_one(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

async fn bounded<F>(future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/1 session test exceeded deadline")?
}
