//! The H3 fork's received-request ordinary field-order contract.

use std::{future::poll_fn, io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use h3::ext::OrderedHeaders;
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use rustls::pki_types::CertificateDer;
use tokio::{sync::oneshot, time::timeout};

use crate::support::{
    h3 as h3_support,
    tls::{TestIdentity, TestResult},
    tunnel_proxy::finish_with_cleanup,
};

const DEADLINE: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(5);
const INTERLEAVED: [(&str, &str); 4] = [
    ("x-repeat", "alpha"),
    ("x-middle", "between"),
    ("x-repeat", "beta"),
    ("x-last", "tail"),
];
const UNIQUE: [(&str, &str); 3] = [
    ("x-first", "one"),
    ("x-middle", "between"),
    ("x-last", "tail"),
];

#[tokio::test]
async fn an_interleaved_request_decodes_semantically_and_collects_its_response() -> TestResult<()> {
    let received = exchange(&INTERLEAVED).await?;

    assert_interleaved_values(&received);
    Ok(())
}

#[tokio::test]
async fn received_unique_fields_keep_their_declared_qpack_order() -> TestResult<()> {
    let received = exchange(&UNIQUE).await?;

    assert_eq!(received.headers().len(), 3);
    assert_eq!(received.headers()["x-first"], "one");
    assert_eq!(received.headers()["x-middle"], "between");
    assert_eq!(received.headers()["x-last"], "tail");

    assert_received_order(&received, &UNIQUE)
}

#[tokio::test]
async fn received_interleaved_duplicates_keep_global_and_per_name_order() -> TestResult<()> {
    let received = exchange(&INTERLEAVED).await?;

    assert_interleaved_values(&received);

    assert_received_order(&received, &INTERLEAVED)
}

fn assert_interleaved_values(received: &Request<()>) {
    assert_eq!(received.headers().len(), 4);
    assert_eq!(
        received
            .headers()
            .get_all("x-repeat")
            .iter()
            .map(HeaderValue::as_bytes)
            .collect::<Vec<_>>(),
        [b"alpha".as_slice(), b"beta".as_slice()]
    );
    assert_eq!(received.headers()["x-middle"], "between");
    assert_eq!(received.headers()["x-last"], "tail");
}

fn assert_received_order(received: &Request<()>, expected: &[(&str, &str)]) -> TestResult<()> {
    let ordered = received
        .extensions()
        .get::<OrderedHeaders>()
        .ok_or("resolved HTTP3 request omitted its decoded OrderedHeaders")?;

    let actual = ordered
        .as_slice()
        .iter()
        .map(|(name, value)| Ok((name.as_str(), value.to_str()?)))
        .collect::<TestResult<Vec<_>>>()?;

    assert_eq!(actual, expected);
    assert!(
        ordered
            .as_slice()
            .iter()
            .all(|(name, _)| !name.as_str().starts_with(':'))
    );
    Ok(())
}

async fn exchange(fields: &[(&str, &str)]) -> TestResult<Request<()>> {
    let identity = TestIdentity::generate()?;
    let (address, server_endpoint) = h3_support::server_endpoint(&identity)?;
    let client_endpoint = client_endpoint(&identity)?;

    let uri = format!("https://{address}/received-order?probe=1");
    let mut outgoing = Request::builder().method(Method::GET).uri(&uri).body(())?;
    let mut ordered = Vec::new();
    for &(name, value) in fields {
        let name: HeaderName = name.parse()?;
        let value: HeaderValue = value.parse()?;
        outgoing.headers_mut().append(name.clone(), value.clone());
        ordered.push((name, value));
    }
    // This is an outgoing declaration, not a replacement for received metadata.
    outgoing
        .extensions_mut()
        .insert(OrderedHeaders::new(ordered));
    let (collected, collection_received) = oneshot::channel();

    let peer = async {
        let (received, mut stream, _connection) =
            h3_support::accept_request(&server_endpoint).await?;

        assert_eq!(received.method(), Method::GET);
        assert_eq!(received.uri().to_string(), uri);
        assert_eq!(received.version(), Version::HTTP_3);
        assert!(stream.recv_data().await?.is_none());

        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        stream.send_data(Bytes::from_static(b"received")).await?;
        stream.finish().await?;

        collection_received.await.map_err(io::Error::other)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(received)
    };
    let request = async {
        let connection = client_endpoint.connect(address, "127.0.0.1")?.await?;
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(connection)).await?;
        let response = async {
            let mut stream = send.send_request(outgoing).await?;
            stream.finish().await?;

            let response = stream.recv_response().await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.version(), Version::HTTP_3);

            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await? {
                let count = chunk.remaining();
                body.extend_from_slice(&chunk.copy_to_bytes(count));
            }

            assert_eq!(body, b"received");
            collected
                .send(())
                .map_err(|_| "receive peer stopped before response collection")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::select! {
            result = response => result,
            error = poll_fn(|context| driver.poll_close(context)) => Err(error.into()),
        }
    };
    // Neither flow owns a detached task. Expiry drops both actual QUIC workflows.
    let received = match timeout(DEADLINE, async { tokio::try_join!(peer, request) }).await {
        Ok(result) => result.map(|(received, ())| received),
        Err(error) => Err(error.into()),
    };

    server_endpoint.close(0_u32.into(), b"received-order fixture complete");
    client_endpoint.close(0_u32.into(), b"received-order fixture complete");
    let cleanup = async {
        timeout(CLEANUP, async {
            tokio::join!(server_endpoint.wait_idle(), client_endpoint.wait_idle());
        })
        .await?;
        Ok(())
    }
    .await;
    finish_with_cleanup(received, cleanup)
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
