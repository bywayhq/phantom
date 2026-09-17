//! Public HTTP/3 session reuse and admission integration tests.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    future::{Future, poll_fn},
    num::NonZeroUsize,
    task::Poll,
    time::Duration,
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{Client, ClientBuilder, HttpProtocol, RequestErrorKind, profile::ClientProfile};
use tokio::{sync::oneshot, time::timeout};

use h3_support::{client_settings, server_endpoint};
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

type ServerConnection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[tokio::test]
async fn sequential_session_requests_reuse_one_http3_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = accept_connection(&endpoint).await?;
            let requests = serve_requests(&mut connection, 2).await?;
            let _ = done_received.await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
        });

        let session = test_client(&identity)?.session();
        for path in ["/first", "/second"] {
            let response = session
                .get(HttpProtocol::Http3, &format!("https://{address}{path}"))?
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.into_body().collect().await?.to_bytes(), path);
        }

        let _ = client_done.send(());
        assert_eq!(
            server.await??,
            vec!["/first".to_owned(), "/second".to_owned()]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn warmed_session_reuse_uses_the_connection_runtime() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = accept_connection(&endpoint).await?;
            let requests = serve_requests(&mut connection, 2).await?;
            let _ = done_received.await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
        });

        let session = test_client(&identity)?.session();
        let first = send_and_drain(session.clone(), format!("https://{address}/first")).await?;
        assert_eq!(first, "/first");

        let second_session = session.clone();
        let second_uri = format!("https://{address}/second");
        let second = tokio::task::spawn_blocking(move || -> TestResult<Bytes> {
            let runtime = tokio::runtime::Builder::new_current_thread().build()?;
            runtime.block_on(send_and_drain(second_session, second_uri))
        })
        .await??;
        assert_eq!(second, "/second");

        let _ = client_done.send(());
        assert_eq!(
            server.await??,
            vec!["/first".to_owned(), "/second".to_owned()]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn concurrent_cloned_session_requests_multiplex_one_http3_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = accept_connection(&endpoint).await?;
            let (first_request, first_stream) = accept_stream(&mut connection).await?;
            let (second_request, second_stream) = accept_stream(&mut connection).await?;
            let first_path = first_request.uri().path().to_owned();
            let second_path = second_request.uri().path().to_owned();
            let mut requests = vec![first_path.clone(), second_path.clone()];
            send_response(first_stream, &first_path).await?;
            send_response(second_stream, &second_path).await?;
            requests.sort_unstable();
            let _ = done_received.await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
        });

        let session = test_client(&identity)?.session();
        let first = tokio::spawn(send_and_drain(
            session.clone(),
            format!("https://{address}/first"),
        ));
        let second = tokio::spawn(send_and_drain(
            session.clone(),
            format!("https://{address}/second"),
        ));
        assert_eq!(first.await??, Bytes::from_static(b"/first"));
        assert_eq!(second.await??, Bytes::from_static(b"/second"));

        let _ = client_done.send(());
        assert_eq!(
            server.await??,
            vec!["/first".to_owned(), "/second".to_owned()]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn independently_built_clients_do_not_share_http3_connections() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connections = Vec::new();
            let mut requests = Vec::new();
            for _ in 0..2 {
                let mut connection = accept_connection(&endpoint).await?;
                let (request, stream) = accept_stream(&mut connection).await?;
                requests.push(request.uri().path().to_owned());
                send_response(stream, request.uri().path()).await?;
                connections.push(connection);
            }
            let _ = done_received.await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
        });

        for (client, path) in [
            (test_client(&identity)?, "/first"),
            (test_client(&identity)?, "/second"),
        ] {
            let payload = send_and_drain(client, format!("https://{address}{path}")).await?;
            assert_eq!(payload, path);
        }

        let _ = client_done.send(());
        assert_eq!(
            server.await??,
            vec!["/first".to_owned(), "/second".to_owned()]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_http3_requests_reuse_one_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = accept_connection(&endpoint).await?;
            let requests = serve_requests(&mut connection, 2).await?;
            let _ = done_received.await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
        });

        let client = test_client(&identity)?;
        for path in ["/first", "/second"] {
            let response = client
                .get(HttpProtocol::Http3, &format!("https://{address}{path}"))?
                .send()
                .await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), path);
        }

        let _ = client_done.send(());
        assert_eq!(
            server.await??,
            vec!["/first".to_owned(), "/second".to_owned()]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_admission_is_bounded_until_a_body_is_dropped_or_completed() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = accept_connection(&endpoint).await?;

            let (held_request, mut held) = accept_stream(&mut connection).await?;
            assert_eq!(held_request.uri().path(), "/held");
            held.send_response(Response::builder().status(StatusCode::OK).body(())?)
                .await?;

            let (waiting_request, waiting) = accept_stream(&mut connection).await?;
            assert_eq!(waiting_request.uri().path(), "/waiting");
            send_response(waiting, "waiting").await?;

            let (later_request, later) = accept_stream(&mut connection).await?;
            assert_eq!(later_request.uri().path(), "/after-complete");
            send_response(later, "after-complete").await?;

            let _ = done_received.await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let one = NonZeroUsize::MIN;
        let session = test_client_builder(&identity)
            .max_concurrent_http3_requests_per_origin(one)
            .max_pending_http3_requests_per_origin(one)
            .build()?;
        let held = session
            .get(HttpProtocol::Http3, &format!("https://{address}/held"))?
            .send()
            .await?;

        let waiting_request =
            session.get(HttpProtocol::Http3, &format!("https://{address}/waiting"))?;
        let mut waiting = std::pin::pin!(waiting_request.send());
        poll_fn(|context| {
            assert!(waiting.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;

        let rejected = session
            .get(HttpProtocol::Http3, &format!("https://{address}/rejected"))?
            .send()
            .await
            .err()
            .ok_or("third admitted HTTP/3 request was not rejected")?;
        assert_eq!(rejected.kind(), RequestErrorKind::Capacity);
        assert_eq!(rejected.protocol(), Some(HttpProtocol::Http3));

        drop(held);
        let waiting = waiting.await?;
        assert_eq!(waiting.into_body().collect().await?.to_bytes(), "waiting");

        let later = session
            .get(
                HttpProtocol::Http3,
                &format!("https://{address}/after-complete"),
            )?
            .send()
            .await?;
        assert_eq!(
            later.into_body().collect().await?.to_bytes(),
            "after-complete"
        );

        let _ = client_done.send(());
        server.await??;
        Ok(())
    })
    .await
}

async fn accept_connection(endpoint: &quinn::Endpoint) -> TestResult<ServerConnection> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    let connection = incoming.await?;
    Ok(h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?)
}

async fn accept_stream(
    connection: &mut ServerConnection,
) -> TestResult<(Request<()>, ServerStream)> {
    let resolver = connection
        .accept()
        .await?
        .ok_or("client closed before sending a request")?;
    Ok(resolver.resolve_request().await?)
}

async fn serve_requests(
    connection: &mut ServerConnection,
    count: usize,
) -> TestResult<Vec<String>> {
    let mut requests = Vec::with_capacity(count);
    for _ in 0..count {
        let (request, stream) = accept_stream(connection).await?;
        requests.push(request.uri().path().to_owned());
        send_response(stream, request.uri().path()).await?;
    }
    Ok(requests)
}

async fn send_response(mut stream: ServerStream, payload: &str) -> TestResult<()> {
    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    stream
        .send_data(Bytes::copy_from_slice(payload.as_bytes()))
        .await?;
    stream.finish().await?;
    Ok(())
}

async fn send_and_drain(client: Client, uri: String) -> TestResult<Bytes> {
    let response = client.get(HttpProtocol::Http3, &uri)?.send().await?;
    Ok(response.into_body().collect().await?.to_bytes())
}

fn test_client(identity: &TestIdentity) -> TestResult<Client> {
    Ok(test_client_builder(identity).build()?)
}

fn test_client_builder(identity: &TestIdentity) -> ClientBuilder {
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let profile = ClientProfile::new(tcp_tls).with_http3(client_settings());
    Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/3 session integration test exceeded its deadline")?
}
