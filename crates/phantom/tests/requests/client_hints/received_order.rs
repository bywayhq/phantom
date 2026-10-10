use std::{future::poll_fn, io, net::SocketAddr, sync::Arc, time::Duration};

use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use rustls::pki_types::CertificateDer;
use tokio::{sync::oneshot, time::timeout};

use crate::support::{
    h3 as h3_support,
    tls::TestIdentity,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::{TestResult, observed_names};

const DEADLINE: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(5);
const INTERLEAVED: [(&str, &str); 4] = [
    ("x-repeat", "alpha"),
    ("x-middle", "between"),
    ("x-repeat", "beta"),
    ("x-last", "tail"),
];
const ADJACENT: [(&str, &str); 4] = [
    ("x-repeat", "alpha"),
    ("x-repeat", "beta"),
    ("x-middle", "between"),
    ("x-last", "tail"),
];

#[tokio::test]
async fn real_http2_decoding_distinguishes_equal_maps_with_different_order() -> TestResult<()> {
    let requests = exchange_http2().await?;
    assert_decoded(&requests, Version::HTTP_2)
}

#[tokio::test]
async fn the_actual_http2_observer_distinguishes_interleaved_duplicate_order() -> TestResult<()> {
    let requests = exchange_http2().await?;
    assert_decoded(&requests, Version::HTTP_2)?;

    assert_observer(&requests)
}

#[tokio::test]
async fn real_http3_decoding_distinguishes_equal_maps_with_different_order() -> TestResult<()> {
    let requests = exchange_http3().await?;
    assert_decoded(&requests, Version::HTTP_3)
}

#[tokio::test]
async fn the_actual_http3_observer_distinguishes_interleaved_duplicate_order() -> TestResult<()> {
    let requests = exchange_http3().await?;
    assert_decoded(&requests, Version::HTTP_3)?;

    assert_observer(&requests)
}

fn assert_decoded(requests: &[Request<()>], version: Version) -> TestResult<()> {
    assert_eq!(requests.len(), 2);
    for (request, expected) in requests.iter().zip([INTERLEAVED, ADJACENT]) {
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri().path(), "/received-order");
        assert_eq!(request.version(), version);
        assert_eq!(request.headers().len(), 4);
        assert_eq!(request.headers()["x-middle"], "between");
        assert_eq!(request.headers()["x-last"], "tail");
        assert_eq!(
            request
                .headers()
                .get_all("x-repeat")
                .iter()
                .map(HeaderValue::as_bytes)
                .collect::<Vec<_>>(),
            [b"alpha".as_slice(), b"beta".as_slice()]
        );

        let decoded = if version == Version::HTTP_2 {
            request
                .extensions()
                .get::<::http2::ext::OrderedHeaders>()
                .ok_or("actual HTTP/2 decode omitted ordinary order")?
                .as_slice()
        } else {
            request
                .extensions()
                .get::<h3::ext::OrderedHeaders>()
                .ok_or("actual HTTP/3 decode omitted ordinary order")?
                .as_slice()
        };
        let decoded = decoded
            .iter()
            .map(|(name, value)| Ok((name.as_str(), value.to_str()?)))
            .collect::<TestResult<Vec<_>>>()?;
        assert_eq!(decoded, expected);
    }
    assert_eq!(requests[0].headers(), requests[1].headers());
    Ok(())
}

fn assert_observer(requests: &[Request<()>]) -> TestResult<()> {
    let first = observed_names(&requests[0]);
    let second = observed_names(&requests[1]);
    assert_ne!(
        first, second,
        "actual hint observer collapsed distinct decoded ordinary sequences"
    );
    assert_eq!(first, ["x-repeat", "x-middle", "x-repeat", "x-last"]);
    assert_eq!(second, ["x-repeat", "x-repeat", "x-middle", "x-last"]);
    Ok(())
}

struct OutgoingRequest {
    request: Request<()>,
    ordered: Vec<(HeaderName, HeaderValue)>,
}

fn outgoing(uri: &str, fields: &[(&str, &str)]) -> TestResult<OutgoingRequest> {
    let mut request = Request::builder().method(Method::GET).uri(uri).body(())?;
    let mut ordered = Vec::new();
    for &(name, value) in fields {
        let name: HeaderName = name.parse()?;
        let value: HeaderValue = value.parse()?;
        request.headers_mut().append(name.clone(), value.clone());
        ordered.push((name, value));
    }
    Ok(OutgoingRequest { request, ordered })
}

async fn exchange_http2() -> TestResult<Vec<Request<()>>> {
    let (client_io, server_io) = tokio::io::duplex(8192);
    let (done, completed) = oneshot::channel();
    let (captured, observed) = oneshot::channel();
    let server = ConnectionPeer::spawn(async move {
        let mut connection = ::http2::server::handshake(server_io).await?;
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("order peer closed before an actual HTTP/2 request")??;
            assert_eq!(request.method(), Method::GET);
            assert_eq!(
                request.uri().to_string(),
                "http://origin.test/received-order"
            );
            assert!(request.body().is_end_stream());
            requests.push(request.map(|_| ()));
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
        }
        tokio::select! {
            result = completed => result.map_err(io::Error::other)?,
            result = poll_fn(|context| connection.poll_closed(context)) => {
                result?;
                return Err("actual HTTP/2 client closed before response collection".into());
            }
        }
        captured
            .send(requests)
            .map_err(|_| "order capture receiver disappeared")?;
        std::future::pending::<()>().await;
        drop(connection);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut sender = None;
    let mut driver = None;
    let operation = async {
        let (requests, connection) = ::http2::client::handshake(client_io).await?;
        sender = Some(requests);
        driver = Some(ConnectionPeer::spawn(async move {
            connection.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }));
        let requests = sender
            .as_mut()
            .ok_or("actual HTTP/2 sender was not retained")?;
        for fields in [INTERLEAVED, ADJACENT] {
            let OutgoingRequest {
                mut request,
                ordered,
            } = outgoing("http://origin.test/received-order", &fields)?;
            request
                .extensions_mut()
                .insert(::http2::ext::OrderedHeaders::new(ordered));
            poll_fn(|context| requests.poll_ready(context)).await?;
            let (response, _body) = requests.send_request(request, true)?;
            let response = response.await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            let mut body = response.into_body();
            assert!(body.data().await.is_none());
        }
        done.send(())
            .map_err(|_| "order peer stopped before HTTP/2 response collection")?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed.await?)
    };
    let result = match timeout(DEADLINE, operation).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };

    // Retain the actual sender through finite ownership cleanup, even on expiry.
    let driver_stop = match driver {
        Some(driver) => driver.stop().await,
        None => Ok(()),
    };
    let server_stop = server.stop().await;
    let cleanup = finish_with_cleanup(driver_stop, server_stop);
    drop(sender);
    finish_with_cleanup(result, cleanup)
}

async fn exchange_http3() -> TestResult<Vec<Request<()>>> {
    let identity = TestIdentity::generate()?;
    let (address, server_endpoint) = h3_support::server_endpoint(&identity)?;
    let client_endpoint = client_endpoint(&identity)?;
    let uri = format!("https://{address}/received-order");
    let (done, completed) = oneshot::channel();
    let peer = async {
        let (first, mut stream, mut connection) =
            h3_support::accept_request(&server_endpoint).await?;
        assert!(stream.recv_data().await?.is_none());
        let mut requests = vec![first];
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        drop(stream);

        let resolver = connection
            .accept()
            .await?
            .ok_or("order peer missed the second HTTP/3 request")?;
        let (second, mut stream) = resolver.resolve_request().await?;
        assert!(stream.recv_data().await?.is_none());
        requests.push(second);
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        completed.await.map_err(io::Error::other)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
    };
    let client = async {
        let connection = client_endpoint.connect(address, "127.0.0.1")?.await?;
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;
        let requests = async {
            for fields in [INTERLEAVED, ADJACENT] {
                let OutgoingRequest {
                    mut request,
                    ordered,
                } = outgoing(&uri, &fields)?;
                request
                    .extensions_mut()
                    .insert(h3::ext::OrderedHeaders::new(ordered));
                let mut stream = sender.send_request(request).await?;
                stream.finish().await?;
                let response = stream.recv_response().await?;
                assert_eq!(response.status(), StatusCode::NO_CONTENT);
                assert_eq!(response.version(), Version::HTTP_3);
                assert!(stream.recv_data().await?.is_none());
            }
            done.send(())
                .map_err(|_| "order peer stopped before HTTP/3 response collection")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::select! {
            result = requests => result,
            error = poll_fn(|context| driver.poll_close(context)) => Err(error.into()),
        }
    };
    let result = match timeout(DEADLINE, async { tokio::try_join!(peer, client) }).await {
        Ok(result) => result.map(|(requests, ())| requests),
        Err(error) => Err(error.into()),
    };

    server_endpoint.close(0_u32.into(), b"order control complete");
    client_endpoint.close(0_u32.into(), b"order control complete");
    let cleanup = async {
        timeout(CLEANUP, async {
            tokio::join!(server_endpoint.wait_idle(), client_endpoint.wait_idle());
        })
        .await?;
        Ok(())
    }
    .await;
    finish_with_cleanup(result, cleanup)
}

fn client_endpoint(identity: &TestIdentity) -> TestResult<quinn::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(identity.root_der.clone()))?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        phantom_testkit::udp::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    Ok(endpoint)
}
