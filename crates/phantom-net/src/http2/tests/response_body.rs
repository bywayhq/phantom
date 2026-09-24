use std::{error::Error, future::poll_fn};

use bytes::Bytes;
use http::{HeaderMap, Response};
use http_body_util::BodyExt;
use phantom_profile::chromium::v154_http2;
use tokio::{
    io::{DuplexStream, duplex},
    sync::oneshot,
};
use tracing::instrument::WithSubscriber;

use super::{TestResult, bounded_peer_test, headers, next_nonempty_data, target};
use crate::{
    http2::{Http2Connection, send_get},
    tracing_test::OutcomeSubscriber,
};

#[tokio::test]
async fn streams_data_then_trailers_without_buffering_later_data() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let (release_tx, release_rx) = oneshot::channel();
        let server_task = tokio::spawn(streaming_server(server, release_rx));

        let response =
            send_get(client, &v154_http2(), "example.test", target()?, headers()).await?;
        assert_eq!(response.status(), 206);
        let mut body = response.into_body();
        let first = next_nonempty_data(&mut body).await?;
        assert_eq!(first, "first");

        release_tx
            .send(())
            .map_err(|_| "server stopped before later data release")?;
        let mut later = None;
        let mut trailers = None;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            match frame.into_data() {
                Ok(data) if !data.is_empty() => later = Some(data),
                Ok(_) => {}
                Err(frame) => {
                    if let Ok(fields) = frame.into_trailers() {
                        trailers = Some(fields);
                    }
                }
            }
        }
        assert_eq!(later.as_deref(), Some(&b"later"[..]));
        assert_eq!(
            trailers
                .as_ref()
                .and_then(|fields| fields.get("x-finished"))
                .and_then(|value| value.to_str().ok()),
            Some("yes")
        );

        let request = server_task.await??;
        assert_eq!(request.method, http::Method::GET);
        assert_eq!(
            request.uri.authority().map(|value| value.as_str()),
            Some("example.test")
        );
        assert_eq!(
            request.uri.path_and_query().map(|value| value.as_str()),
            Some("/resource?item=1")
        );
        assert_eq!(request.repeat_count, 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn terminal_data_completes_without_an_extra_body_poll() -> TestResult<()> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(terminal_data_server(server));

        async {
            let response =
                send_get(client, &v154_http2(), "example.test", target()?, vec![]).await?;
            let mut body = response.into_body();
            let frame = body
                .frame()
                .await
                .ok_or("response ended before terminal DATA")??;
            assert_eq!(frame.into_data().map_err(|_| "expected DATA")?, "terminal");
            drop(body);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone())
        .await?;

        assert!(!server_task.await??, "terminal DATA was followed by CANCEL");
        assert_eq!(
            subscriber.response_body_events(),
            [(8, "complete".to_owned())]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn informational_sequence_preserves_final_body_trailers_and_reuse() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(informational_server(server));
        let connection = Http2Connection::connect(client, &v154_http2()).await?;

        let response = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        assert_eq!(response.status(), 206);
        assert_eq!(response.headers().get("x-final"), Some(&"yes".parse()?));
        assert!(response.headers().get("link").is_none());
        assert!(response.headers().get("x-processing").is_none());

        let mut body = response.into_body();
        let mut data = Vec::new();
        let mut trailers = None;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            match frame.into_data() {
                Ok(bytes) => data.extend_from_slice(&bytes),
                Err(frame) => trailers = frame.into_trailers().ok(),
            }
        }
        assert_eq!(data, b"complete");
        assert_eq!(
            trailers.as_ref().and_then(|fields| fields.get("x-trailer")),
            Some(&"done".parse()?)
        );

        let followup = connection
            .send_get("example.test", target()?, Vec::new())
            .await?;
        assert_eq!(followup.status(), 204);
        assert!(followup.into_body().collect().await?.to_bytes().is_empty());
        drop(connection);
        server_task.await??;
        Ok(())
    })
    .await
}

async fn streaming_server(
    stream: DuplexStream,
    release_later: oneshot::Receiver<()>,
) -> TestResult<RequestObservation> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(206).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"first"), false)?;

    tokio::pin!(release_later);
    tokio::select! {
        result = &mut release_later => {
            result.map_err(std::io::Error::other)?;
        }
        incoming = connection.accept() => {
            if incoming.is_none() {
                return Err("connection closed before later data release".into());
            }
            return Err("one-shot client sent an unexpected second request".into());
        }
    }

    send.send_data(Bytes::from_static(b"later"), false)?;
    let mut trailers = HeaderMap::new();
    trailers.insert("x-finished", http::HeaderValue::from_static("yes"));
    send.send_trailers(trailers)?;
    let observation = RequestObservation {
        method: request.method().clone(),
        uri: request.uri().clone(),
        repeat_count: request.headers().get_all("x-repeat").iter().count(),
    };
    drop(request);
    drop(send);
    drop(respond);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(observation)
}

struct RequestObservation {
    method: http::Method,
    uri: http::Uri,
    repeat_count: usize,
}

async fn terminal_data_server(stream: DuplexStream) -> TestResult<bool> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(200).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"terminal"), true)?;
    drop(request);
    drop(respond);

    let reset = tokio::select! {
        biased;
        result = poll_fn(|context| send.poll_reset(context)) => {
            result?;
            true
        }
        incoming = connection.accept() => {
            if incoming.is_some() {
                return Err("one-shot client sent an unexpected second request".into());
            }
            false
        }
    };
    drop(send);
    Ok(reset)
}

async fn informational_server(stream: DuplexStream) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (_request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before first request")??;

    respond.send_informational(
        Response::builder()
            .status(103)
            .header("link", "</first.css>; rel=preload")
            .body(())?,
    )?;
    respond.send_informational(
        Response::builder()
            .status(102)
            .header("x-processing", "yes")
            .body(())?,
    )?;
    respond.send_informational(
        Response::builder()
            .status(103)
            .header("link", "</second.css>; rel=preload")
            .body(())?,
    )?;
    let response = Response::builder()
        .status(206)
        .header("x-final", "yes")
        .body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"complete"), false)?;
    let mut trailers = HeaderMap::new();
    trailers.insert("x-trailer", http::HeaderValue::from_static("done"));
    send.send_trailers(trailers)?;
    drop(send);
    drop(respond);

    let (_request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before follow-up request")??;
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    drop(respond);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}
