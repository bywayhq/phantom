use std::{
    error::Error,
    future::poll_fn,
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use btls::ssl::{Ssl, SslAcceptor};
use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use phantom::HttpProtocol;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::{AbortHandle, JoinError},
    time::timeout,
};
use tokio_btls::SslStream;

use super::{
    H2_ALPN, TEST_TIMEOUT, TestIdentity, TestResult, bounded, collect_h2_request_body, test_client,
};
use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

type Upload = (Bytes, [u32; 2]);
type Reset = (::http2::Reason, [u32; 2]);

pub(super) async fn upload() -> TestResult<()> {
    upload_controlled(None).await
}

async fn upload_controlled(control: Option<Control>) -> TestResult<()> {
    let mut server: Option<ConnectionPeer<TestResult<Upload>>> = None;
    let mut completed = None;

    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let observed = control.as_ref().map(|control| control.observed.clone());
        server = Some(ConnectionPeer::spawn(async move {
            let _life = PeerLife(observed.clone());
            let stream = accept_peer(&listener, &acceptor, observed).await?;
            let mut connection = ::http2::server::handshake(stream).await?;

            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before upload")??;
            let first_id = respond.stream_id().as_u32();
            assert_eq!(request.method(), Method::POST);
            let mut incoming = request.into_body();
            let body = collect_h2_request_body(&mut connection, &mut incoming).await?;
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;

            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before follow-up")??;
            let second_id = respond.stream_id().as_u32();
            assert_eq!(request.method(), Method::GET);
            assert_eq!(request.uri().path(), "/after-upload");
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((body, [first_id, second_id]))
        }));

        let target = match control {
            Some(control) => {
                control
                    .coordinate(Setup {
                        address,
                        peer: server.as_ref().ok_or("upload peer missing")?.abort_handle(),
                        sibling: None,
                    })
                    .await?
            }
            None => None,
        };

        let session = test_client(&identity, true)?;
        let upload_target = target.unwrap_or_else(|| format!("https://{address}/upload"));
        let response = session
            .request_with_protocol(HttpProtocol::Http2, Method::POST, &upload_target)?
            .body(Bytes::from_static(b"pooled-payload"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        let response = session
            .get_with_protocol(
                HttpProtocol::Http2,
                &format!("https://{address}/after-upload"),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(session);

        join_peer(&mut server, &mut completed).await
    })
    .await;

    let collected = collect_peer(
        server,
        completed,
        caller.is_err(),
        "upload peer did not finish",
    )
    .await;
    let (body, stream_ids) = finish_peer(caller, collected)?;

    assert_eq!(body, "pooled-payload");
    assert_eq!(stream_ids, [1, 3]);
    Ok(())
}

pub(super) async fn cancelled_body() -> TestResult<()> {
    cancelled_controlled(None).await
}

async fn cancelled_controlled(control: Option<Control>) -> TestResult<()> {
    let mut server: Option<ConnectionPeer<TestResult<Reset>>> = None;
    let mut completed = None;

    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let observed = control.as_ref().map(|control| control.observed.clone());
        server = Some(ConnectionPeer::spawn(async move {
            let _life = PeerLife(observed.clone());
            let stream = accept_peer(&listener, &acceptor, observed).await?;
            let mut connection = ::http2::server::handshake(stream).await?;

            let (_, mut first) = connection
                .accept()
                .await
                .ok_or("connection closed before first request")??;
            let first_id = first.stream_id().as_u32();
            let mut first_body =
                first.send_response(Response::builder().status(200).body(())?, false)?;
            first_body.send_data(Bytes::from_static(b"partial"), false)?;

            let mut reset = None;
            let mut later = None;
            while reset.is_none() || later.is_none() {
                tokio::select! {
                    observed = poll_fn(|context| first_body.poll_reset(context)), if reset.is_none() => {
                        reset = Some(observed?);
                    }
                    incoming = connection.accept(), if later.is_none() => {
                        later = Some(incoming.ok_or("connection closed before later request")??);
                    }
                }
            }

            let (_, mut later) = later.ok_or("later request was not retained")?;
            let later_id = later.stream_id().as_u32();
            later.send_response(Response::builder().status(204).body(())?, true)?;
            drop(first_body);
            drop(first);
            drop(later);
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((
                reset.ok_or("stream reset was not retained")?,
                [first_id, later_id],
            ))
        }));

        let target = match control {
            Some(control) => control.coordinate(Setup {
                address,
                peer: server.as_ref().ok_or("reset peer missing")?.abort_handle(),
                sibling: None,
            }).await?,
            None => None,
        };

        let session = test_client(&identity, true)?;
        let abandoned_target = target.unwrap_or_else(|| format!("https://{address}/abandoned"));
        let response = session
            .get_with_protocol(HttpProtocol::Http2, &abandoned_target)?
            .send()
            .await?;
        let mut abandoned = response.into_body();
        let frame = abandoned
            .frame()
            .await
            .ok_or("response ended before partial data")??;
        assert_eq!(frame.into_data().map_err(|_| "expected response data")?, "partial");
        drop(abandoned);

        let response = session
            .get_with_protocol(HttpProtocol::Http2, &format!("https://{address}/later"))?
            .send()
            .await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;
        drop(session);

        join_peer(&mut server, &mut completed).await
    })
    .await;

    let collected = collect_peer(
        server,
        completed,
        caller.is_err(),
        "reset peer did not finish",
    )
    .await;
    let (reset, stream_ids) = finish_peer(caller, collected)?;

    assert_eq!(reset, ::http2::Reason::CANCEL);
    assert_eq!(stream_ids, [1, 3]);
    Ok(())
}

pub(super) async fn join_peer<T>(
    peer: &mut Option<ConnectionPeer<TestResult<T>>>,
    completed: &mut Option<T>,
) -> TestResult<()> {
    let joined = peer
        .as_mut()
        .ok_or("session peer missing before join")?
        .await;

    drop(peer.take());

    *completed = Some(joined??);
    Ok(())
}

pub(super) async fn collect_peer<T: Send + 'static>(
    peer: Option<ConnectionPeer<TestResult<T>>>,
    completed: Option<T>,
    stop: bool,
    purpose: &'static str,
) -> TestResult<Option<T>> {
    if let Some(value) = completed {
        return Ok(Some(value));
    }

    let Some(mut peer) = peer else {
        return Ok(None);
    };

    let mut requested = false;
    if stop && !peer.is_finished() {
        requested = true;
        peer.abort();
    }

    match timeout(TEST_TIMEOUT, &mut peer).await {
        Ok(joined) => peer_outcome(joined, requested),
        Err(elapsed) => {
            if !peer.is_finished() {
                requested = true;
                peer.abort();
            }

            let cleanup = match timeout(TEST_TIMEOUT, &mut peer).await {
                Ok(joined) => peer_outcome(joined, requested).map(|_| ()),
                Err(elapsed) => Err(FixtureDeadline::new(purpose, elapsed).into()),
            };

            finish_with_cleanup(Err(FixtureDeadline::new(purpose, elapsed).into()), cleanup)
        }
    }
}

fn peer_outcome<T>(
    joined: Result<TestResult<T>, JoinError>,
    requested: bool,
) -> TestResult<Option<T>> {
    match joined {
        Ok(result) => result.map(Some),
        Err(error) if requested && error.is_cancelled() => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn finish_peer<T>(caller: TestResult<()>, collected: TestResult<Option<T>>) -> TestResult<T> {
    let mut output = None;
    let cleanup = match collected {
        Ok(value) => {
            output = value;
            Ok(())
        }
        Err(error) => Err(error),
    };

    finish_with_cleanup(caller, cleanup)?;

    output.ok_or_else(|| "session peer ended without an output".into())
}

#[derive(Clone, Debug, Default)]
pub(super) struct PeerState {
    pub(super) accepted: bool,
    pub(super) read_pending: bool,
    pub(super) destroyed: bool,
    pub(super) published: Option<Setup>,
}

#[derive(Clone, Debug)]
pub(super) struct Observation(pub(super) watch::Sender<PeerState>);

pub(super) struct PeerLife(pub(super) Option<Observation>);

impl Drop for PeerLife {
    fn drop(&mut self) {
        if let Some(observed) = &self.0 {
            observed.0.send_modify(|state| state.destroyed = true);
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Setup {
    pub(super) address: SocketAddr,
    pub(super) peer: AbortHandle,
    pub(super) sibling: Option<AbortHandle>,
}

pub(super) struct Control {
    pub(super) observed: Observation,
    pub(super) setup: oneshot::Sender<Setup>,
    pub(super) resume: oneshot::Receiver<()>,
    pub(super) target: Option<String>,
}

impl Control {
    pub(super) async fn coordinate(self, setup: Setup) -> TestResult<Option<String>> {
        self.observed
            .0
            .send_modify(|state| state.published = Some(setup.clone()));

        self.setup
            .send(setup)
            .map_err(|_| "peer setup observer ended")?;

        self.resume.await?;

        Ok(self.target)
    }
}

pub(super) struct ObservedTcp {
    stream: TcpStream,
    observed: Option<Observation>,
}

impl ObservedTcp {
    pub(super) fn new(stream: TcpStream, observed: Option<Observation>) -> Self {
        if let Some(observed) = &observed {
            observed.0.send_modify(|state| state.accepted = true);
        }

        Self { stream, observed }
    }
}

impl AsyncRead for ObservedTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_read(context, buffer);

        if result.is_pending()
            && let Some(observed) = &this.observed
        {
            observed.0.send_modify(|state| state.read_pending = true);
        }

        result
    }
}

impl AsyncWrite for ObservedTcp {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

pub(super) async fn accept_peer(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    observed: Option<Observation>,
) -> TestResult<SslStream<ObservedTcp>> {
    let (tcp, _) = listener.accept().await?;
    let tcp = ObservedTcp::new(tcp, observed);
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

pub(super) mod tests;
