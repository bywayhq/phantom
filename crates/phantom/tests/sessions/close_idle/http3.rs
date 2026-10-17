use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, profile::ClientProfile};
use tokio::{sync::oneshot, time::timeout};

use super::super::peer_completion::{self, Peer};
use super::DEADLINE;
use crate::support::{
    h3 as h3_support,
    tls::{self, TestIdentity, TestResult},
};

type Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[tokio::test]
async fn close_idle_replaces_http3_connections() -> TestResult<()> {
    let mut peer = None;
    let result = timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let (done, finished) = oneshot::channel();
        let (retired, mut retirement) = oneshot::channel();
        peer = Some(Peer::spawn(async move {
            let mut first = accept_connection(&endpoint).await?;
            let mut stream = accept_stream(&mut first).await?;
            stream
                .send_response(Response::builder().status(204).body(())?)
                .await?;
            stream.finish().await?;
            drop(stream);
            // Observe retirement before the caller starts its replacement.
            // HTTP/3 reports a normal application close as a typed error too.
            match first.accept().await {
                Ok(None) => {}
                Err(error) if error.is_h3_no_error() => {}
                Ok(Some(_)) => return Err("idle connection carried another request".into()),
                Err(error) => return Err(error.into()),
            }
            retired.send(()).map_err(|_| "caller stopped")?;
            let second = endpoint.accept().await.ok_or("endpoint stopped")?.await?;
            let mut second = Connection::new(h3_quinn::Connection::new(second)).await?;
            let mut stream = accept_stream(&mut second).await?;
            stream
                .send_response(Response::builder().status(204).body(())?)
                .await?;
            stream.finish().await?;
            finished.await?;
            Ok(())
        }));
        let client = client(&identity)?;
        let url = format!("https://{address}/");
        for round in 0..2 {
            let response = client.get(HttpProtocol::Http3, &url)?.send().await?;
            if response.status() != 204 {
                return Err("unexpected status".into());
            }
            response.into_body().collect().await?;
            if round == 0 {
                client.clone().close_idle_connections().await;
                client.close_idle_connections().await;
                (&mut retirement).await?;
            }
        }
        done.send(()).map_err(|_| "peer stopped")?;
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|r| r);
    peer_completion::finish(result, &mut peer).await
}

#[tokio::test]
async fn close_idle_preserves_http3_active_body_and_multiplexing() -> TestResult<()> {
    let mut peer = None;
    let result = timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let (done, finished) = oneshot::channel();
        peer = Some(Peer::spawn(async move {
            let mut connection = accept_connection(&endpoint).await?;
            let mut first = accept_stream(&mut connection).await?;
            first
                .send_response(Response::builder().status(200).body(())?)
                .await?;
            first.send_data(Bytes::from_static(b"held")).await?;
            let mut second = accept_stream(&mut connection).await?;
            second
                .send_response(Response::builder().status(204).body(())?)
                .await?;
            second.finish().await?;
            first.send_data(Bytes::from_static(b"-done")).await?;
            first.finish().await?;
            finished.await?;
            Ok(())
        }));
        let client = client(&identity)?;
        let url = format!("https://{address}/");
        let held = client
            .get(HttpProtocol::Http3, &url)?
            .send()
            .await?
            .into_body();
        client.close_idle_connections().await;
        let second = client.get(HttpProtocol::Http3, &url)?.send().await?;
        if second.status() != 204 {
            return Err("unexpected second status".into());
        }
        second.into_body().collect().await?;
        if held.collect().await?.to_bytes() != "held-done" {
            return Err("active HTTP/3 body changed".into());
        }
        done.send(()).map_err(|_| "peer stopped")?;
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|r| r);
    peer_completion::finish(result, &mut peer).await
}

fn client(identity: &TestIdentity) -> TestResult<Client> {
    Ok(Client::builder(
        ClientProfile::new(tls::tls_settings()).with_http3(h3_support::client_settings()),
    )
    .add_root_certificate_der(identity.root_der.clone())
    .build()?)
}

async fn accept_connection(endpoint: &quinn::Endpoint) -> TestResult<Connection> {
    let incoming = endpoint.accept().await.ok_or("endpoint stopped")?.await?;
    Ok(Connection::new(h3_quinn::Connection::new(incoming)).await?)
}

async fn accept_stream(connection: &mut Connection) -> TestResult<Stream> {
    let request = connection
        .accept()
        .await?
        .ok_or("connection closed before request")?;
    Ok(request.resolve_request().await?.1)
}
