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
    task::AbortHandle,
};
use tokio_btls::SslStream;

use super::{H2_ALPN, TestIdentity, TestResult, bounded, collect_h2_request_body, test_client};

pub(super) async fn upload() -> TestResult<()> {
    upload_controlled(None).await
}

async fn upload_controlled(control: Option<Control>) -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let observed = control.as_ref().map(|control| control.observed.clone());
        let server = tokio::spawn(async move {
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
        });

        let target = match control {
            Some(control) => {
                control
                    .coordinate(Setup {
                        address,
                        peer: server.abort_handle(),
                        sibling: None,
                    })
                    .await?
            }
            None => None,
        };

        let session = test_client(&identity, true)?;
        let upload_target = target.unwrap_or_else(|| format!("https://{address}/upload"));
        let response = session
            .request(HttpProtocol::Http2, Method::POST, &upload_target)?
            .body(Bytes::from_static(b"pooled-payload"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        let response = session
            .get(
                HttpProtocol::Http2,
                &format!("https://{address}/after-upload"),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(session);

        let (body, stream_ids) = server.await??;
        assert_eq!(body, "pooled-payload");
        assert_eq!(stream_ids, [1, 3]);
        Ok(())
    })
    .await
}

pub(super) async fn cancelled_body() -> TestResult<()> {
    cancelled_controlled(None).await
}

async fn cancelled_controlled(control: Option<Control>) -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let observed = control.as_ref().map(|control| control.observed.clone());
        let server = tokio::spawn(async move {
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
        });

        let target = match control {
            Some(control) => control.coordinate(Setup {
                address,
                peer: server.abort_handle(),
                sibling: None,
            }).await?,
            None => None,
        };

        let session = test_client(&identity, true)?;
        let abandoned_target = target.unwrap_or_else(|| format!("https://{address}/abandoned"));
        let response = session
            .get(HttpProtocol::Http2, &abandoned_target)?
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
            .get(HttpProtocol::Http2, &format!("https://{address}/later"))?
            .send()
            .await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;
        drop(session);

        let (reset, stream_ids) = server.await??;
        assert_eq!(reset, ::http2::Reason::CANCEL);
        assert_eq!(stream_ids, [1, 3]);
        Ok(())
    })
    .await
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
