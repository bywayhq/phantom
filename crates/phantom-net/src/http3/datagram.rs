use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use h3::quic::StreamId;
use h3_datagram::datagram_handler::DatagramReader;
use tokio::{runtime::Handle, sync::oneshot, task::JoinHandle};
use tracing::{Instrument, debug, debug_span, dispatcher, instrument::WithSubscriber};

type Reader = DatagramReader<h3_quinn::datagram::RecvDatagramHandler>;

const MAX_DATAGRAMS_PER_TURN: usize = 32;

pub(super) struct DatagramMonitor {
    receiver: oneshot::Receiver<()>,
    task: JoinHandle<()>,
}

impl DatagramMonitor {
    pub(super) fn spawn(mut reader: Reader, stream_id: StreamId) -> Self {
        let (sender, receiver) = oneshot::channel();
        let dispatch = dispatcher::get_default(Clone::clone);
        let span = debug_span!(
            "http3.datagram_reader",
            request_stream_id = stream_id.into_inner()
        );
        let task = Handle::current().spawn(
            async move {
                loop {
                    for _ in 0..MAX_DATAGRAMS_PER_TURN {
                        match reader.read_datagram().await {
                            Ok(datagram) if datagram.stream_id() == stream_id => {
                                let _ = sender.send(());
                                return;
                            }
                            Ok(_) => {}
                            Err(error) => {
                                debug!(%error, "HTTP/3 datagram reader stopped");
                                return;
                            }
                        }
                    }
                    tokio::task::yield_now().await;
                }
            }
            .instrument(span)
            .with_subscriber(dispatch),
        );
        Self { receiver, task }
    }

    pub(super) fn poll_violation(&mut self, context: &mut Context<'_>) -> Poll<Option<()>> {
        match Pin::new(&mut self.receiver).poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(())),
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DatagramMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
