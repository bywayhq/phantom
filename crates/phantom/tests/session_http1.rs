//! HTTP/1.1 session connection lifecycle tests.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    error::Error, future::Future, net::Ipv4Addr, num::NonZeroUsize, pin::Pin, time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RequestErrorKind};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use tls_support::{H1_ALPN, TestIdentity, read_head, test_client};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn sequential_session_requests_reuse_one_connection() -> TestResult {
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
            .get(HttpProtocol::Http1, &format!("https://{address}/first"))?
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
        assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /second HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn bare_client_requests_remain_one_shot() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut stream = accept_one(&listener, &acceptor).await?;
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

        let client = test_client(&identity, false)?;
        let session = client
            .session_builder()
            .max_pending_http1_requests_per_origin(NonZeroUsize::MIN)
            .build();
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
