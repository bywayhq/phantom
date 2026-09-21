use std::{any::Any, future::pending, future::poll_fn, pin::Pin, task::Poll};

use bytes::{Buf, Bytes};
use h3::error::{Code, StreamError};
use http::HeaderMap;
use http_body::Frame;
use tokio::{
    runtime::Handle,
    sync::{mpsc, watch},
};
use tracing::{Dispatch, Instrument, Span, debug_span, dispatcher, instrument::WithSubscriber};

use super::super::{
    DatagramMonitor, DriverSignal, Http3Connection, Http3Error, Http3ErrorKind, RequestRecvStream,
    SHUTDOWN_GRACE,
    upload::{RequestSend, UploadError},
};
use crate::shutdown_timer;

const BODY_EVENT_CAPACITY: usize = 1;
const BODY_DEMAND_CAPACITY: usize = 1;

pub(super) enum BodyEvent {
    Frame(Frame<Bytes>),
    End,
    Error(Http3Error),
}

pub(super) struct BodyTask {
    demand: mpsc::Sender<()>,
    events: mpsc::Receiver<BodyEvent>,
    _cancel: watch::Sender<()>,
    cleanup_guards: mpsc::UnboundedSender<Box<dyn Any + Send>>,
    pending: bool,
}

impl BodyTask {
    pub(super) fn spawn(
        send: RequestSend,
        recv: RequestRecvStream,
        connection: Http3Connection,
        datagrams: Option<DatagramMonitor>,
        runtime: Handle,
        dispatch: Dispatch,
        span: Span,
    ) -> Self {
        let (demand, demands) = mpsc::channel(BODY_DEMAND_CAPACITY);
        let (events, receiver) = mpsc::channel(BODY_EVENT_CAPACITY);
        let (cancel, cancellation) = watch::channel(());
        let (cleanup_guards, retained) = mpsc::unbounded_channel();

        let task = async move {
            let _retained = retained;
            run(
                send,
                recv,
                connection,
                datagrams,
                demands,
                events,
                cancellation,
            )
            .await;
        }
        .instrument(span)
        .with_subscriber(dispatch);
        // The channels own cancellation; the detached task must finish the QUIC stream.
        drop(runtime.spawn(task));

        Self {
            demand,
            events: receiver,
            _cancel: cancel,
            cleanup_guards,
            pending: false,
        }
    }

    pub(super) fn retain_until_cleanup<T>(&self, value: T)
    where
        T: Send + 'static,
    {
        let _ = self.cleanup_guards.send(Box::new(value));
    }

    pub(super) fn poll_event(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Option<BodyEvent>> {
        if let Poll::Ready(event) = Pin::new(&mut self.events).poll_recv(context) {
            self.pending = false;
            return Poll::Ready(event);
        }

        if !self.pending {
            match self.demand.try_send(()) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(())) => self.pending = true,
                Err(mpsc::error::TrySendError::Closed(())) => {}
            }
        }

        Pin::new(&mut self.events).poll_recv(context)
    }
}

pub(super) fn defer_datagram_abort(
    mut send: RequestSend,
    mut recv: RequestRecvStream,
    connection: Http3Connection,
) {
    let runtime = connection.runtime().clone();
    let dispatch = dispatcher::get_default(Clone::clone);
    let span = debug_span!("http3.stream_abort", code = "H3_DATAGRAM_ERROR");
    let task = async move {
        reset(&mut send, &mut recv, Code::H3_DATAGRAM_ERROR);
        wait_for_abort_grace().await;
        finish(send, recv, &connection, DriverSignal::ProtocolError);
    }
    .instrument(span)
    .with_subscriber(dispatch);
    drop(runtime.spawn(task));
}

#[derive(Clone, Copy)]
enum ReceiveState {
    Data,
    Trailers,
}

async fn run(
    mut send: RequestSend,
    mut recv: RequestRecvStream,
    connection: Http3Connection,
    mut datagrams: Option<DatagramMonitor>,
    mut demands: mpsc::Receiver<()>,
    events: mpsc::Sender<BodyEvent>,
    mut cancellation: watch::Receiver<()>,
) {
    let mut state = ReceiveState::Data;

    loop {
        let demand = tokio::select! {
            biased;
            () = wait_for_datagram(&mut datagrams) => {
                abort_for_datagram(&mut send, &mut recv, &events);
                wait_for_abort_grace().await;
                finish(send, recv, &connection, DriverSignal::ProtocolError);
                return;
            }
            _ = cancellation.changed() => {
                cancel(&mut send, &mut recv);
                wait_for_abort_grace().await;
                finish(send, recv, &connection, DriverSignal::Cancelled);
                return;
            }
            uploaded = send.uploaded() => {
                if let Some(error) = upload_failure(uploaded) {
                    fail_upload(send, recv, &connection, &events, error).await;
                    return;
                }
                continue;
            }
            demand = demands.recv() => demand,
        };
        if demand.is_none() {
            cancel(&mut send, &mut recv);
            wait_for_abort_grace().await;
            finish(send, recv, &connection, DriverSignal::Cancelled);
            return;
        }

        loop {
            let interrupted = match state {
                ReceiveState::Data => {
                    match recv_data(&mut recv, &mut send, &mut datagrams, &mut cancellation).await {
                        Receive::Value(Ok(Some(data))) => {
                            if events
                                .send(BodyEvent::Frame(Frame::data(data)))
                                .await
                                .is_err()
                            {
                                cancel(&mut send, &mut recv);
                                wait_for_abort_grace().await;
                                finish(send, recv, &connection, DriverSignal::Cancelled);
                                return;
                            }
                            break;
                        }
                        Receive::Value(Ok(None)) => {
                            state = ReceiveState::Trailers;
                            continue;
                        }
                        Receive::Value(Err(error)) => Interrupted::Stream(error),
                        Receive::Interrupted(interrupted) => interrupted,
                    }
                }
                ReceiveState::Trailers => {
                    match recv_trailers(&mut recv, &mut send, &mut datagrams, &mut cancellation)
                        .await
                    {
                        // A complete response ends the exchange; dropping `send`
                        // resets any unfinished upload (RFC 9114 section 4.1).
                        Receive::Value(Ok(Some(trailers))) => {
                            let _ = events
                                .send(BodyEvent::Frame(Frame::trailers(trailers)))
                                .await;
                            finish(send, recv, &connection, DriverSignal::Complete);
                            return;
                        }
                        Receive::Value(Ok(None)) => {
                            let _ = events.send(BodyEvent::End).await;
                            finish(send, recv, &connection, DriverSignal::Complete);
                            return;
                        }
                        Receive::Value(Err(error)) => Interrupted::Stream(error),
                        Receive::Interrupted(interrupted) => interrupted,
                    }
                }
            };
            match interrupted {
                Interrupted::Stream(error) => {
                    send_error(&events, error.into()).await;
                    finish(send, recv, &connection, DriverSignal::ProtocolError);
                    return;
                }
                Interrupted::Datagram => {
                    abort_for_datagram(&mut send, &mut recv, &events);
                    wait_for_abort_grace().await;
                    finish(send, recv, &connection, DriverSignal::ProtocolError);
                    return;
                }
                Interrupted::Cancelled => {
                    cancel(&mut send, &mut recv);
                    wait_for_abort_grace().await;
                    finish(send, recv, &connection, DriverSignal::Cancelled);
                    return;
                }
                Interrupted::Upload(uploaded) => {
                    if let Some(error) = upload_failure(uploaded) {
                        fail_upload(send, recv, &connection, &events, error).await;
                        return;
                    }
                }
            }
        }
    }
}

/// Classifies an upload that ended while the response was being received.
///
/// A peer STOP_SENDING ends only the upload: RFC 9114 section 4.1 lets a
/// server abort reading the request and still send a complete response.
fn upload_failure(uploaded: Result<(), UploadError>) -> Option<Http3Error> {
    match uploaded {
        Ok(()) | Err(UploadError::Stream(StreamError::RemoteTerminate { .. })) => None,
        Err(UploadError::Body(error)) => Some(error),
        Err(UploadError::Stream(error)) => Some(error.into()),
    }
}

async fn fail_upload(
    mut send: RequestSend,
    mut recv: RequestRecvStream,
    connection: &Http3Connection,
    events: &mpsc::Sender<BodyEvent>,
    error: Http3Error,
) {
    cancel(&mut send, &mut recv);
    send_error(events, error).await;
    wait_for_abort_grace().await;
    finish(send, recv, connection, DriverSignal::Cancelled);
}

enum Receive<T> {
    Value(Result<T, StreamError>),
    Interrupted(Interrupted),
}

enum Interrupted {
    Stream(StreamError),
    Datagram,
    Cancelled,
    Upload(Result<(), UploadError>),
}

async fn recv_data(
    stream: &mut RequestRecvStream,
    send: &mut RequestSend,
    datagrams: &mut Option<DatagramMonitor>,
    cancellation: &mut watch::Receiver<()>,
) -> Receive<Option<Bytes>> {
    tokio::select! {
        biased;
        () = wait_for_datagram(datagrams) => Receive::Interrupted(Interrupted::Datagram),
        _ = cancellation.changed() => Receive::Interrupted(Interrupted::Cancelled),
        uploaded = send.uploaded() => Receive::Interrupted(Interrupted::Upload(uploaded)),
        result = stream.recv_data() => Receive::Value(result.map(|data| {
            data.map(|mut data| data.copy_to_bytes(data.remaining()))
        })),
    }
}

async fn recv_trailers(
    stream: &mut RequestRecvStream,
    send: &mut RequestSend,
    datagrams: &mut Option<DatagramMonitor>,
    cancellation: &mut watch::Receiver<()>,
) -> Receive<Option<HeaderMap>> {
    tokio::select! {
        biased;
        () = wait_for_datagram(datagrams) => Receive::Interrupted(Interrupted::Datagram),
        _ = cancellation.changed() => Receive::Interrupted(Interrupted::Cancelled),
        uploaded = send.uploaded() => Receive::Interrupted(Interrupted::Upload(uploaded)),
        result = stream.recv_trailers() => Receive::Value(result),
    }
}

async fn wait_for_datagram(datagrams: &mut Option<DatagramMonitor>) {
    loop {
        let Some(monitor) = datagrams.as_mut() else {
            pending::<()>().await;
            return;
        };
        if poll_fn(|context| monitor.poll_violation(context))
            .await
            .is_some()
        {
            return;
        }
        *datagrams = None;
    }
}

fn abort_for_datagram(
    send: &mut RequestSend,
    recv: &mut RequestRecvStream,
    events: &mpsc::Sender<BodyEvent>,
) {
    reset(send, recv, Code::H3_DATAGRAM_ERROR);
    let event = BodyEvent::Error(Http3Error::without_source(
        Http3ErrorKind::Protocol,
        "peer sent an HTTP Datagram for a request without datagram semantics",
    ));
    match events.try_send(event) {
        Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
        Err(mpsc::error::TrySendError::Full(event)) => {
            let events = events.clone();
            drop(Handle::current().spawn(async move {
                let _ = events.send(event).await;
            }));
        }
    }
}

fn cancel(send: &mut RequestSend, recv: &mut RequestRecvStream) {
    reset(send, recv, Code::H3_REQUEST_CANCELLED);
}

fn reset(send: &mut RequestSend, recv: &mut RequestRecvStream, code: Code) {
    recv.stop_sending(code);
    send.reset(code);
}

async fn wait_for_abort_grace() {
    match shutdown_timer::after(SHUTDOWN_GRACE) {
        Ok(deadline) => {
            let _ = deadline.await;
        }
        Err(_) => tokio::task::yield_now().await,
    }
}

fn finish(
    send: RequestSend,
    recv: RequestRecvStream,
    connection: &Http3Connection,
    signal: DriverSignal,
) {
    drop((send, recv));
    connection.record(signal);
}

async fn send_error(events: &mpsc::Sender<BodyEvent>, error: Http3Error) {
    let _ = events.send(BodyEvent::Error(error)).await;
}
