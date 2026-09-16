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
    DatagramMonitor, DriverSignal, Http3Connection, Http3Error, Http3ErrorKind, RequestStream,
    SHUTDOWN_GRACE,
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
        stream: RequestStream,
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
            run(stream, connection, datagrams, demands, events, cancellation).await;
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

pub(super) fn defer_datagram_abort(mut stream: RequestStream, connection: Http3Connection) {
    let runtime = connection.runtime().clone();
    let dispatch = dispatcher::get_default(Clone::clone);
    let span = debug_span!("http3.stream_abort", code = "H3_DATAGRAM_ERROR");
    let task = async move {
        reset(&mut stream, Code::H3_DATAGRAM_ERROR);
        wait_for_abort_grace().await;
        finish(stream, &connection, DriverSignal::ProtocolError);
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
    mut stream: RequestStream,
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
                abort_for_datagram(&mut stream, &events);
                wait_for_abort_grace().await;
                finish(stream, &connection, DriverSignal::ProtocolError);
                return;
            }
            _ = cancellation.changed() => {
                cancel(&mut stream);
                wait_for_abort_grace().await;
                finish(stream, &connection, DriverSignal::Cancelled);
                return;
            }
            demand = demands.recv() => demand,
        };
        if demand.is_none() {
            cancel(&mut stream);
            wait_for_abort_grace().await;
            finish(stream, &connection, DriverSignal::Cancelled);
            return;
        }

        loop {
            match state {
                ReceiveState::Data => {
                    match recv_data(&mut stream, &mut datagrams, &mut cancellation).await {
                        Receive::Value(Ok(Some(data))) => {
                            if events
                                .send(BodyEvent::Frame(Frame::data(data)))
                                .await
                                .is_err()
                            {
                                cancel(&mut stream);
                                wait_for_abort_grace().await;
                                finish(stream, &connection, DriverSignal::Cancelled);
                                return;
                            }
                            break;
                        }
                        Receive::Value(Ok(None)) => state = ReceiveState::Trailers,
                        Receive::Value(Err(error)) => {
                            send_error(&events, error.into()).await;
                            finish(stream, &connection, DriverSignal::ProtocolError);
                            return;
                        }
                        Receive::Datagram => {
                            abort_for_datagram(&mut stream, &events);
                            wait_for_abort_grace().await;
                            finish(stream, &connection, DriverSignal::ProtocolError);
                            return;
                        }
                        Receive::Cancelled => {
                            cancel(&mut stream);
                            wait_for_abort_grace().await;
                            finish(stream, &connection, DriverSignal::Cancelled);
                            return;
                        }
                    }
                }
                ReceiveState::Trailers => {
                    match recv_trailers(&mut stream, &mut datagrams, &mut cancellation).await {
                        Receive::Value(Ok(Some(trailers))) => {
                            let _ = events
                                .send(BodyEvent::Frame(Frame::trailers(trailers)))
                                .await;
                            finish(stream, &connection, DriverSignal::Complete);
                            return;
                        }
                        Receive::Value(Ok(None)) => {
                            let _ = events.send(BodyEvent::End).await;
                            finish(stream, &connection, DriverSignal::Complete);
                            return;
                        }
                        Receive::Value(Err(error)) => {
                            send_error(&events, error.into()).await;
                            finish(stream, &connection, DriverSignal::ProtocolError);
                            return;
                        }
                        Receive::Datagram => {
                            abort_for_datagram(&mut stream, &events);
                            wait_for_abort_grace().await;
                            finish(stream, &connection, DriverSignal::ProtocolError);
                            return;
                        }
                        Receive::Cancelled => {
                            cancel(&mut stream);
                            wait_for_abort_grace().await;
                            finish(stream, &connection, DriverSignal::Cancelled);
                            return;
                        }
                    }
                }
            }
        }
    }
}

enum Receive<T> {
    Value(Result<T, StreamError>),
    Datagram,
    Cancelled,
}

async fn recv_data(
    stream: &mut RequestStream,
    datagrams: &mut Option<DatagramMonitor>,
    cancellation: &mut watch::Receiver<()>,
) -> Receive<Option<Bytes>> {
    tokio::select! {
        biased;
        () = wait_for_datagram(datagrams) => Receive::Datagram,
        _ = cancellation.changed() => Receive::Cancelled,
        result = stream.recv_data() => Receive::Value(result.map(|data| {
            data.map(|mut data| data.copy_to_bytes(data.remaining()))
        })),
    }
}

async fn recv_trailers(
    stream: &mut RequestStream,
    datagrams: &mut Option<DatagramMonitor>,
    cancellation: &mut watch::Receiver<()>,
) -> Receive<Option<HeaderMap>> {
    tokio::select! {
        biased;
        () = wait_for_datagram(datagrams) => Receive::Datagram,
        _ = cancellation.changed() => Receive::Cancelled,
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

fn abort_for_datagram(stream: &mut RequestStream, events: &mpsc::Sender<BodyEvent>) {
    reset(stream, Code::H3_DATAGRAM_ERROR);
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

fn cancel(stream: &mut RequestStream) {
    reset(stream, Code::H3_REQUEST_CANCELLED);
}

fn reset(stream: &mut RequestStream, code: Code) {
    stream.stop_sending(code);
    stream.stop_stream(code);
}

async fn wait_for_abort_grace() {
    match shutdown_timer::after(SHUTDOWN_GRACE) {
        Ok(deadline) => {
            let _ = deadline.await;
        }
        Err(_) => tokio::task::yield_now().await,
    }
}

fn finish(stream: RequestStream, connection: &Http3Connection, signal: DriverSignal) {
    drop(stream);
    connection.record(signal);
}

async fn send_error(events: &mpsc::Sender<BodyEvent>, error: Http3Error) {
    let _ = events.send(BodyEvent::Error(error)).await;
}
