use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{
    qpack::{Encoder, EncoderError, HeaderField},
    quic::{SendStreamUnframed, StreamErrorIncoming},
};

const COMMAND_CAPACITY: usize = 32;
const MAX_INSTRUCTION_BYTES: usize = 64 * 1024;
const MAX_COMMANDS_PER_POLL: usize = 32;
const LOCAL_MAX_TABLE_CAPACITY: usize = 64 * 1024;
const LOCAL_MAX_BLOCKED_STREAMS: usize = u16::MAX as usize;

pub(crate) fn channel() -> (Driver, Sender) {
    let (commands, command_rx) = mpsc::channel(COMMAND_CAPACITY);
    let (ready, ready_rx) = watch::channel(false);
    (
        Driver {
            commands: command_rx,
            ready,
            instructions: BytesMut::new(),
            pending_release: None,
            publications: Vec::new(),
            commands_closed: false,
            configuration: None,
            held_header: None,
        },
        Sender { commands, ready_rx },
    )
}

#[derive(Clone)]
pub(crate) struct Sender {
    commands: mpsc::Sender<EncodeCommand>,
    ready_rx: watch::Receiver<bool>,
}

impl Sender {
    pub(super) async fn wait_ready(&mut self) -> Result<(), Closed> {
        loop {
            if *self.ready_rx.borrow_and_update() {
                return Ok(());
            }
            self.ready_rx.changed().await.map_err(|_| Closed)?;
        }
    }

    pub(super) async fn reserve(&self) -> Result<mpsc::OwnedPermit<EncodeCommand>, Closed> {
        self.commands
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| Closed)
    }
}

#[derive(Debug)]
pub(super) struct Closed;

pub(super) struct EncodeCommand {
    stream_id: u64,
    fields: Vec<HeaderField>,
    response: oneshot::Sender<Result<Encoded, EncodeError>>,
}

impl EncodeCommand {
    pub(super) fn new(
        stream_id: u64,
        fields: Vec<HeaderField>,
    ) -> (Self, oneshot::Receiver<Result<Encoded, EncodeError>>) {
        let (response, receiver) = oneshot::channel();
        (
            Self {
                stream_id,
                fields,
                response,
            },
            receiver,
        )
    }
}

pub(super) struct Encoded {
    pub(super) block: Bytes,
    pub(super) publication: Publication,
}

pub(super) struct Publication {
    published: Option<oneshot::Sender<()>>,
}

impl Publication {
    pub(super) fn published(mut self) {
        if let Some(published) = self.published.take() {
            let _ = published.send(());
        }
    }
}

#[derive(Debug)]
pub(super) enum EncodeError {
    Codec(EncoderError),
    InstructionsTooLarge { size: usize, limit: usize },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "{error}"),
            Self::InstructionsTooLarge { size, limit } => write!(
                formatter,
                "QPACK encoder instructions require {size} bytes; limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}

struct PendingRelease {
    stream_id: u64,
    block: Bytes,
    response: oneshot::Sender<Result<Encoded, EncodeError>>,
}

struct PendingPublication {
    stream_id: u64,
    published: oneshot::Receiver<()>,
}

pub(crate) struct Driver {
    commands: mpsc::Receiver<EncodeCommand>,
    ready: watch::Sender<bool>,
    instructions: BytesMut,
    pending_release: Option<PendingRelease>,
    publications: Vec<PendingPublication>,
    commands_closed: bool,
    configuration: Option<(usize, usize)>,
    /// The encoder stream type, while it is deferred. Nothing is written
    /// until a field section is prepared while instructions are queued; the
    /// type then precedes every queued instruction, the table capacity
    /// included.
    held_header: Option<Bytes>,
}

impl Driver {
    pub(crate) fn configure(
        &mut self,
        encoder: &mut Encoder,
        table_capacity: u64,
        blocked_streams: u64,
    ) -> Result<(), ConfigureError> {
        let table_capacity = effective_table_capacity(table_capacity);
        let blocked_streams = effective_blocked_streams(blocked_streams);

        if let Some((current_capacity, current_blocked)) = self.configuration {
            if table_capacity < current_capacity || blocked_streams < current_blocked {
                return Err(ConfigureError::ReducedLimit);
            }
            if table_capacity > current_capacity {
                encoder
                    .set_max_table_capacity(table_capacity, &mut self.instructions)
                    .map_err(ConfigureError::Codec)?;
            }
            if blocked_streams > current_blocked {
                encoder
                    .set_max_blocked_streams(blocked_streams)
                    .map_err(ConfigureError::Codec)?;
            }
            self.configuration = Some((table_capacity, blocked_streams));
            return Ok(());
        }

        if table_capacity != 0 {
            encoder
                .set_max_table_capacity(table_capacity, &mut self.instructions)
                .map_err(ConfigureError::Codec)?;
        }
        encoder
            .set_max_blocked_streams(blocked_streams)
            .map_err(ConfigureError::Codec)?;
        self.configuration = Some((table_capacity, blocked_streams));
        Ok(())
    }

    pub(crate) fn mark_ready(&self) {
        self.ready.send_replace(true);
    }

    /// Defers `header`, the encoder stream type, until the first field
    /// section is prepared with encoder instructions.
    pub(crate) fn hold_stream_header(&mut self, header: Bytes) {
        self.held_header = Some(header);
    }

    /// Writes the held stream type ahead of the queued instructions once a
    /// prepared field section depends on them.
    fn release_stream_header(&mut self) {
        if self.pending_release.is_none() || self.instructions.is_empty() {
            return;
        }
        if let Some(header) = self.held_header.take() {
            let mut instructions = BytesMut::with_capacity(header.len() + self.instructions.len());
            instructions.put(header);
            instructions.put(self.instructions.split());
            self.instructions = instructions;
        }
    }

    pub(crate) fn poll<S, B>(
        &mut self,
        encoder: &mut Encoder,
        send: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), PollError>>
    where
        S: SendStreamUnframed<B>,
        B: Buf,
    {
        self.poll_publications(encoder, cx)?;
        let mut sent = 0;
        let mut commands = 0;

        loop {
            self.release_stream_header();
            // While the stream type is held, instructions wait for a field
            // section that needs them.
            let writable = self.held_header.is_none();
            while writable && self.instructions.has_remaining() && sent < MAX_INSTRUCTION_BYTES {
                match send.poll_send(cx, &mut self.instructions) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(PollError::WriteZero)),
                    Poll::Ready(Ok(written)) => sent = sent.saturating_add(written),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(PollError::Stream(error))),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if writable && self.instructions.has_remaining() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            if let Some(pending) = self.pending_release.take() {
                self.release_block(encoder, pending)?;
                self.poll_publications(encoder, cx)?;
                commands += 1;
                if commands == MAX_COMMANDS_PER_POLL {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                continue;
            }

            if self.configuration.is_none() || self.commands_closed {
                return Poll::Pending;
            }

            let command = match self.commands.poll_recv(cx) {
                Poll::Ready(Some(command)) => command,
                Poll::Ready(None) => {
                    self.commands_closed = true;
                    return Poll::Pending;
                }
                Poll::Pending => return Poll::Pending,
            };
            if command.response.is_closed() {
                continue;
            }
            self.prepare_block(encoder, command);
        }
    }

    fn prepare_block(&mut self, encoder: &mut Encoder, command: EncodeCommand) {
        let mut candidate = encoder.clone();
        let mut block = BytesMut::new();
        let mut instructions = BytesMut::new();
        let result = candidate.encode(
            command.stream_id,
            &mut block,
            &mut instructions,
            command.fields,
        );
        if let Err(error) = result {
            let _ = command.response.send(Err(EncodeError::Codec(error)));
            return;
        }
        if instructions.len() > MAX_INSTRUCTION_BYTES {
            let _ = command
                .response
                .send(Err(EncodeError::InstructionsTooLarge {
                    size: instructions.len(),
                    limit: MAX_INSTRUCTION_BYTES,
                }));
            return;
        }

        *encoder = candidate;
        self.instructions.put(instructions);
        self.pending_release = Some(PendingRelease {
            stream_id: command.stream_id,
            block: block.freeze(),
            response: command.response,
        });
    }

    fn release_block(
        &mut self,
        encoder: &mut Encoder,
        pending: PendingRelease,
    ) -> Result<(), PollError> {
        let (published, publication) = oneshot::channel();
        let encoded = Encoded {
            block: pending.block,
            publication: Publication {
                published: Some(published),
            },
        };
        if pending.response.send(Ok(encoded)).is_err() {
            encoder
                .cancel_stream(pending.stream_id)
                .map_err(PollError::Codec)?;
            return Ok(());
        }
        self.publications.push(PendingPublication {
            stream_id: pending.stream_id,
            published: publication,
        });
        Ok(())
    }

    fn poll_publications(
        &mut self,
        encoder: &mut Encoder,
        cx: &mut Context<'_>,
    ) -> Result<(), PollError> {
        let mut index = 0;
        while index < self.publications.len() {
            match Pin::new(&mut self.publications[index].published).poll(cx) {
                Poll::Ready(Ok(())) => {
                    self.publications.swap_remove(index);
                }
                Poll::Ready(Err(_)) => {
                    let publication = self.publications.swap_remove(index);
                    encoder
                        .cancel_stream(publication.stream_id)
                        .map_err(PollError::Codec)?;
                }
                Poll::Pending => index += 1,
            }
        }
        Ok(())
    }
}

fn effective_table_capacity(peer: u64) -> usize {
    usize::try_from(peer)
        .unwrap_or(usize::MAX)
        .min(LOCAL_MAX_TABLE_CAPACITY)
}

fn effective_blocked_streams(peer: u64) -> usize {
    usize::try_from(peer)
        .unwrap_or(usize::MAX)
        .min(LOCAL_MAX_BLOCKED_STREAMS)
}

#[derive(Debug)]
pub(crate) enum ConfigureError {
    Codec(EncoderError),
    ReducedLimit,
}

impl std::fmt::Display for ConfigureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "{error}"),
            Self::ReducedLimit => formatter.write_str("peer QPACK limits were reduced"),
        }
    }
}

pub(crate) enum PollError {
    Codec(EncoderError),
    Stream(StreamErrorIncoming),
    WriteZero,
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::task::noop_waker_ref;

    use crate::{
        quic::{SendStream, StreamId},
        stream::WriteBuf,
    };

    #[derive(Default)]
    struct RecordingSend {
        written: Vec<u8>,
    }

    impl SendStream<Bytes> for RecordingSend {
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
            Poll::Ready(Ok(()))
        }

        fn send_data<T: Into<WriteBuf<Bytes>>>(
            &mut self,
            _data: T,
        ) -> Result<(), StreamErrorIncoming> {
            Ok(())
        }

        fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
            Poll::Ready(Ok(()))
        }

        fn reset(&mut self, _reset_code: u64) {}

        fn send_id(&self) -> StreamId {
            StreamId::try_from(10).unwrap()
        }
    }

    impl SendStreamUnframed<Bytes> for RecordingSend {
        fn poll_send<D: Buf>(
            &mut self,
            _cx: &mut Context<'_>,
            buf: &mut D,
        ) -> Poll<Result<usize, StreamErrorIncoming>> {
            let written = buf.remaining();
            self.written.extend_from_slice(&buf.copy_to_bytes(written));
            Poll::Ready(Ok(written))
        }

        fn poll_stopped(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Option<u64>, StreamErrorIncoming>> {
            Poll::Pending
        }
    }

    #[test]
    fn a_held_stream_type_is_written_with_the_first_field_section_instructions() {
        let (mut driver, sender) = channel();
        driver.hold_stream_header(Bytes::from_static(&[0x02]));
        let mut encoder = Encoder::default();
        let mut send = RecordingSend::default();
        let mut cx = Context::from_waker(noop_waker_ref());

        // The table capacity instruction is queued but not written: a
        // connection that encodes no field section leaves the stream unused.
        driver.configure(&mut encoder, 4096, 16).unwrap();
        assert!(driver.poll(&mut encoder, &mut send, &mut cx).is_pending());
        assert!(send.written.is_empty());

        let fields = vec![HeaderField::new("x-phantom", "held")];
        let mut expected_encoder = Encoder::default();
        let mut expected = vec![0x02];
        expected_encoder
            .set_max_table_capacity(4096, &mut expected)
            .unwrap();
        expected_encoder.set_max_blocked_streams(16).unwrap();
        let mut expected_block = Vec::new();
        expected_encoder
            .encode(0, &mut expected_block, &mut expected, fields.clone())
            .unwrap();

        let (command, mut response) = EncodeCommand::new(0, fields);
        sender.commands.try_send(command).ok().unwrap();
        assert!(driver.poll(&mut encoder, &mut send, &mut cx).is_pending());
        assert_eq!(send.written, expected);
        let encoded = response.try_recv().unwrap().unwrap();
        assert_eq!(encoded.block, expected_block);
        encoded.publication.published();

        // Later instructions follow without a second stream type.
        let fields = vec![HeaderField::new("x-next", "1")];
        let mut expected_block = Vec::new();
        expected_encoder
            .encode(4, &mut expected_block, &mut expected, fields.clone())
            .unwrap();
        let (command, mut response) = EncodeCommand::new(4, fields);
        sender.commands.try_send(command).ok().unwrap();
        assert!(driver.poll(&mut encoder, &mut send, &mut cx).is_pending());
        assert_eq!(send.written, expected);
        assert_eq!(response.try_recv().unwrap().unwrap().block, expected_block);
    }

    #[test]
    fn peer_blocked_stream_limit_is_clamped() {
        assert_eq!(
            effective_blocked_streams(u64::MAX),
            LOCAL_MAX_BLOCKED_STREAMS
        );
    }

    #[test]
    fn peer_table_capacity_is_clamped_to_local_ceiling() {
        assert_eq!(
            effective_table_capacity((1_u64 << 62) - 1),
            LOCAL_MAX_TABLE_CAPACITY
        );
        assert_eq!(effective_table_capacity(4096), 4096);
    }

    #[test]
    fn peer_limits_may_increase_but_not_decrease() {
        let (mut driver, _sender) = channel();
        let mut encoder = Encoder::default();

        driver.configure(&mut encoder, 32, 2).unwrap();
        driver.configure(&mut encoder, 64, 3).unwrap();
        assert_eq!(driver.configuration, Some((64, 3)));
        assert!(matches!(
            driver.configure(&mut encoder, 32, 3),
            Err(ConfigureError::ReducedLimit)
        ));
    }

    #[tokio::test]
    async fn publication_drop_is_observable() {
        let (published, publication) = oneshot::channel();
        drop(Publication {
            published: Some(published),
        });
        assert!(publication.await.is_err());
    }

    #[tokio::test]
    async fn publication_success_is_observable() {
        let (published, publication) = oneshot::channel();
        Publication {
            published: Some(published),
        }
        .published();
        assert!(publication.await.is_ok());
    }
}
