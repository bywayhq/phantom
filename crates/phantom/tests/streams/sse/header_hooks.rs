use std::{
    error::Error,
    future::pending,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::poll;
use phantom::{
    Client, ClientBuilder, ConnectedStream, HttpProtocol, RequestError, RequestErrorKind,
    RequestHeader, RequestTimeouts, SseError, TcpConnector, TimeoutPhase,
    profile::{ClientProfile, Http2PseudoHeader, browser::chrome},
};
use tokio::{
    io::DuplexStream,
    sync::{mpsc, oneshot},
    time::{Instant, sleep, timeout},
};

use crate::support::{h2, tls::tls_settings};

use super::TestResult;

mod reconnect;

const URL: &str = "http://hooks.invalid/events";
const LIMIT: Duration = Duration::from_secs(10);

fn builder() -> (
    ClientBuilder,
    mpsc::Receiver<DuplexStream>,
    Arc<AtomicUsize>,
) {
    let (sender, receiver) = mpsc::channel(2);
    let connections = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&connections);
    let connector = TcpConnector::from_fn(move |_| {
        let sender = sender.clone();
        observed.fetch_add(1, Ordering::SeqCst);
        async move {
            let (client, peer) = tokio::io::duplex(8192);
            sender
                .send(peer)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            Ok(ConnectedStream::new(client))
        }
    });
    let mut http2 = chrome::v154_http2();
    http2.pseudo_header_order = vec![
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Path,
    ];
    (
        Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
            .tcp_connector(connector),
        receiver,
        connections,
    )
}

fn request_error(error: &SseError) -> TestResult<&RequestError> {
    error
        .source()
        .and_then(|cause| cause.downcast_ref::<RequestError>())
        .ok_or_else(|| "EventSource lost its request error".into())
}

struct PendingHook(Arc<AtomicBool>);

impl Drop for PendingHook {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cancelling_initial_connect_drops_the_hook_before_opening_a_connection() -> TestResult<()> {
    let (builder, mut peers, connections) = builder();
    let client = builder.build()?;
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&dropped);
    let mut connect = Box::pin(
        client
            .event_source(HttpProtocol::Http1, URL)?
            .async_header_hook(move |headers| {
                let observed = Arc::clone(&observed);
                Box::pin(async move {
                    let _owner = PendingHook(observed);
                    pending::<()>().await;
                    headers.append(RequestHeader::new("X-Late", "never"))
                })
            })
            .connect(),
    );

    assert!(poll!(connect.as_mut()).is_pending());
    assert!(!dropped.load(Ordering::SeqCst));
    assert_eq!(connections.load(Ordering::SeqCst), 0);
    assert!(peers.try_recv().is_err());
    drop(connect);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(connections.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn client_and_source_hooks_share_the_openings_total_deadline() -> TestResult<()> {
    let (builder, _, connections) = builder();
    let client = builder
        .request_timeouts(RequestTimeouts::new().total(Duration::from_millis(100)))
        .async_header_hook(|_| {
            Box::pin(async {
                sleep(Duration::from_millis(60)).await;
                Ok(())
            })
        })
        .build()?;
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&dropped);
    let start = Instant::now();
    let error = client
        .event_source(HttpProtocol::Http1, URL)?
        .async_header_hook(move |_| {
            let observed = Arc::clone(&observed);
            Box::pin(async move {
                let _owner = PendingHook(observed);
                pending().await
            })
        })
        .max_reconnects(0)
        .connect()
        .await
        .err()
        .ok_or("source hook exceeded the shared deadline")?;

    let request = request_error(&error)?;
    assert_eq!(request.kind(), RequestErrorKind::Timeout);
    assert_eq!(request.timeout_phase(), Some(TimeoutPhase::Total));
    assert_eq!(Instant::now() - start, Duration::from_millis(100));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(connections.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn source_hooks_cannot_append_set_or_remove_the_managed_event_id() -> TestResult<()> {
    for mutation in 0..3 {
        let (builder, _, connections) = builder();
        let client = builder.build()?;
        let error = client
            .event_source(HttpProtocol::Http1, URL)?
            .async_header_hook(move |headers| {
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    match mutation {
                        0 => headers.append(RequestHeader::new("Last-Event-ID", "caller")),
                        1 => headers.set(RequestHeader::new("last-event-id", "caller")),
                        _ => headers.remove("LAST-EVENT-ID"),
                    }
                })
            })
            .initial_retry(Duration::ZERO)
            .max_reconnects(5)
            .connect()
            .await
            .err()
            .ok_or("hook changed the managed event ID")?;

        assert_eq!(request_error(&error)?.kind(), RequestErrorKind::HeaderHook);
        assert_eq!(connections.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_an_event_source_hook_preserves_an_active_http2_sibling() -> TestResult<()> {
    timeout(LIMIT, async {
        let (builder, mut peers, connections) = builder();
        let client = builder.build()?;
        let (release, waiting) = oneshot::channel::<()>();
        let peer = async move {
            let mut stream = peers.recv().await.ok_or("HTTP/2 connection missing")?;
            h2::accept_client_preface(&mut stream).await?;
            h2::read_request_headers(&mut stream, 1).await?;
            h2::write_frame(&mut stream, 1, 4, 1, &[0x88]).await?;
            waiting.await?;
            h2::write_frame(&mut stream, 0, 1, 1, b"ok").await?;
            h2::read_request_headers(&mut stream, 3).await?;
            h2::write_frame(&mut stream, 1, 5, 3, &[0x88]).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let caller = async {
            let response = client
                .get_with_protocol(HttpProtocol::Http2, URL)?
                .send()
                .await?;
            let mut connect = Box::pin(
                client
                    .event_source(HttpProtocol::Http2, URL)?
                    .async_header_hook(|_| Box::pin(pending()))
                    .connect(),
            );
            assert!(poll!(connect.as_mut()).is_pending());
            drop(connect);
            release.send(()).map_err(|_| "HTTP/2 peer stopped early")?;
            assert_eq!(
                response.into_body().collect_with_limit(2).await?.as_ref(),
                b"ok"
            );
            assert_eq!(
                client
                    .get_with_protocol(HttpProtocol::Http2, URL)?
                    .send()
                    .await?
                    .status(),
                200
            );
            assert_eq!(connections.load(Ordering::SeqCst), 1);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(peer, caller)?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await?
}
