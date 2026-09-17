//! HTTP/2 session authority-isolation integration tests.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::HttpProtocol;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use tls_support::{H2_ALPN, TestIdentity, test_client};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn secondary_authority_uses_a_dedicated_connection() -> TestResult<()> {
    bounded(async {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), "localhost")?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let primary = accept_tls(&listener, &acceptor).await?;
            let primary = tokio::spawn(serve_one_request(primary, StatusCode::NO_CONTENT));

            let secondary = accept_tls(&listener, &acceptor).await?;
            let secondary = tokio::spawn(serve_one_request(secondary, StatusCode::OK));

            Ok::<_, Box<dyn Error + Send + Sync>>([primary.await??, secondary.await??])
        });

        let session = test_client(&identity, true)?.session();
        let primary = session
            .get(HttpProtocol::Http2, &format!("https://{address}/"))?
            .send()
            .await?;
        assert_eq!(primary.status(), StatusCode::NO_CONTENT);
        primary.into_body().collect().await?;

        let secondary_authority = format!("localhost:{}", address.port());
        let secondary = session
            .get(
                HttpProtocol::Http2,
                &format!("https://{secondary_authority}/.well-known/phantom/421?key=fixed"),
            )?
            .send()
            .await?;
        assert_eq!(secondary.status(), StatusCode::OK);
        secondary.into_body().collect().await?;
        drop(session);

        let [primary, secondary] = server.await??;
        assert_eq!(primary.authority, address.to_string());
        assert_eq!(primary.path_and_query, "/");
        assert_eq!(secondary.authority, secondary_authority);
        assert_eq!(
            secondary.path_and_query,
            "/.well-known/phantom/421?key=fixed"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dedicated_421_is_returned_without_hidden_replay() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (response_seen, response_seen_by_server) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            serve_421_without_replay(listener, stream, response_seen_by_server).await
        });

        let session = test_client(&identity, true)?.session();
        let response = session
            .get(
                HttpProtocol::Http2,
                &format!("https://{address}/.well-known/phantom/421?key=fixed"),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
        response.into_body().collect().await?;
        response_seen
            .send(())
            .map_err(|()| "421 server stopped before the response was observed")?;

        let request = server.await??;
        drop(session);
        assert_eq!(request.authority, address.to_string());
        assert_eq!(request.path_and_query, "/.well-known/phantom/421?key=fixed");
        Ok(())
    })
    .await
}

struct ObservedRequest {
    authority: String,
    path_and_query: String,
}

async fn serve_one_request(
    stream: SslStream<TcpStream>,
    status: StatusCode,
) -> TestResult<ObservedRequest> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let authority = request
        .uri()
        .authority()
        .ok_or("HTTP/2 request omitted :authority")?
        .to_string();
    let path_and_query = request
        .uri()
        .path_and_query()
        .ok_or("HTTP/2 request omitted :path")?
        .to_string();
    respond.send_response(Response::builder().status(status).body(())?, true)?;
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(ObservedRequest {
        authority,
        path_and_query,
    })
}

async fn serve_421_without_replay(
    listener: TcpListener,
    stream: SslStream<TcpStream>,
    response_seen: oneshot::Receiver<()>,
) -> TestResult<ObservedRequest> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let observed = ObservedRequest {
        authority: request
            .uri()
            .authority()
            .ok_or("HTTP/2 request omitted :authority")?
            .to_string(),
        path_and_query: request
            .uri()
            .path_and_query()
            .ok_or("HTTP/2 request omitted :path")?
            .to_string(),
    };
    respond.send_response(
        Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(())?,
        true,
    )?;

    tokio::select! {
        biased;
        replay = connection.accept() => {
            match replay {
                Some(Ok(_)) => Err("421 triggered a replay on the same connection".into()),
                Some(Err(error)) => Err(error.into()),
                None => Err("421 connection closed before the response was returned".into()),
            }
        }
        accepted = listener.accept() => {
            accepted?;
            Err("421 triggered a replay on a new connection".into())
        }
        observed_response = response_seen => {
            observed_response.map_err(|_| "client stopped before observing the 421 response")?;
            Ok(observed)
        }
    }
}

async fn accept_tls(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/2 authority test exceeded its deadline")?
}
