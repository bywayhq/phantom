use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use http_body::{Body, Frame, SizeHint};
use phantom_net::request::RequestTrailerName;

use super::{BufferedAttempt, NoReplay, ReplayBuffer};

/// A body that yields scripted frames and then ends.
struct Scripted {
    frames: VecDeque<Result<Frame<Bytes>, io::Error>>,
    exact: Option<u64>,
}

impl Scripted {
    fn data(chunks: &[&'static str]) -> Self {
        Self {
            exact: Some(chunks.iter().map(|chunk| chunk.len() as u64).sum()),
            frames: chunks
                .iter()
                .map(|chunk| Ok(Frame::data(Bytes::from_static(chunk.as_bytes()))))
                .collect(),
        }
    }
}

impl Body for Scripted {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        Poll::Ready(self.frames.pop_front())
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        self.exact.map_or_else(SizeHint::new, SizeHint::with_exact)
    }
}

/// What one poll of a cursor returned.
#[derive(Debug, Eq, PartialEq)]
enum Polled {
    Data(Bytes),
    Trailers,
    End,
    Error,
    Pending,
}

fn poll(cursor: &mut BufferedAttempt) -> Polled {
    let mut context = Context::from_waker(Waker::noop());
    match Pin::new(cursor).poll_frame(&mut context) {
        Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
            Ok(data) => Polled::Data(data),
            Err(_) => Polled::Trailers,
        },
        Poll::Ready(Some(Err(_))) => Polled::Error,
        Poll::Ready(None) => Polled::End,
        Poll::Pending => Polled::Pending,
    }
}

fn data(chunk: &'static str) -> Polled {
    Polled::Data(Bytes::from_static(chunk.as_bytes()))
}

fn start(buffer: &ReplayBuffer) -> BufferedAttempt {
    match buffer.start() {
        Ok(cursor) => cursor,
        Err(NoReplay::Failed) => panic!("the source failed"),
        Err(NoReplay::Exhausted) => panic!("the replay limit was exceeded"),
    }
}

#[test]
fn a_replay_sends_the_kept_frames_and_then_reads_on_from_the_source() {
    let buffer = ReplayBuffer::new(Scripted::data(&["ab", "cd", "ef"]), Vec::new(), 64);
    let mut first = start(&buffer);
    assert_eq!(poll(&mut first), data("ab"));

    let mut second = start(&buffer);
    assert_eq!(poll(&mut second), data("ab"));
    assert_eq!(poll(&mut second), data("cd"));
    assert_eq!(poll(&mut second), data("ef"));
    assert_eq!(poll(&mut second), Polled::End);
    // The superseded attempt fails rather than ending its request.
    assert_eq!(poll(&mut first), Polled::Error);

    let mut third = start(&buffer);
    for chunk in ["ab", "cd", "ef"] {
        assert_eq!(poll(&mut third), data(chunk));
    }
    assert_eq!(poll(&mut third), Polled::End);
}

#[test]
fn the_limit_is_inclusive_and_a_body_past_it_is_sent_once() {
    let within = ReplayBuffer::new(Scripted::data(&["ab", "cd"]), Vec::new(), 4);
    let mut cursor = start(&within);
    while poll(&mut cursor) != Polled::End {}
    assert!(within.no_replay().is_none());

    let past = ReplayBuffer::new(Scripted::data(&["ab", "cde"]), Vec::new(), 4);
    let mut cursor = start(&past);
    assert_eq!(poll(&mut cursor), data("ab"));
    // The attempt in progress still sends the whole body.
    assert_eq!(poll(&mut cursor), data("cde"));
    assert_eq!(poll(&mut cursor), Polled::End);
    assert!(matches!(past.no_replay(), Some(NoReplay::Exhausted)));
    assert!(matches!(past.next_attempt(), Err(NoReplay::Exhausted)));
}

#[test]
fn every_attempt_reports_the_original_exact_length() {
    let buffer = ReplayBuffer::new(Scripted::data(&["ab", "cd"]), Vec::new(), 64);
    let mut first = start(&buffer);
    assert_eq!(first.size_hint().exact(), Some(4));
    assert_eq!(poll(&mut first), data("ab"));
    assert_eq!(first.size_hint().exact(), Some(2));
    let second = start(&buffer);
    assert_eq!(second.size_hint().exact(), Some(4));
    for attempt in [buffer.next_attempt(), buffer.next_attempt()] {
        let Ok(body) = attempt else {
            panic!("the buffered body cannot be sent again");
        };
        assert_eq!(body.metadata().exact_length(), Some(4));
    }
    assert_eq!(buffer.metadata_body().metadata().exact_length(), Some(4));
}

#[test]
fn an_unknown_length_stays_unknown_and_an_empty_body_ends_at_once() {
    let mut unknown = Scripted::data(&["ab"]);
    unknown.exact = None;
    let buffer = ReplayBuffer::new(unknown, Vec::new(), 64);
    assert_eq!(start(&buffer).size_hint().exact(), None);

    let empty = ReplayBuffer::new(Scripted::data(&[]), Vec::new(), 0);
    let cursor = start(&empty);
    assert!(cursor.is_end_stream());
    assert_eq!(cursor.size_hint().exact(), Some(0));
}

#[test]
fn empty_source_frames_pass_through_without_retained_replay_metadata() {
    let body = Scripted::data(&vec![""; 4096]);
    let buffer = ReplayBuffer::new(body, Vec::new(), 0);
    let mut first = start(&buffer);
    for _ in 0..4096 {
        assert_eq!(poll(&mut first), data(""));
        assert_eq!(first.size_hint().exact(), Some(0));
        let shared = super::lock(&buffer.shared);
        assert!(shared.frames.is_empty(), "empty frames must not accumulate");
        assert_eq!(shared.kept_bytes, 0);
    }
    assert!(first.is_end_stream());
    assert_eq!(poll(&mut first), Polled::End);
    assert!(buffer.no_replay().is_none());
    let mut replay = start(&buffer);
    assert!(replay.is_end_stream());
    assert_eq!(poll(&mut replay), Polled::End);
}

#[test]
fn replay_omits_read_empty_frames_and_preserves_data_and_trailers() {
    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", HeaderValue::from_static("1"));
    let mut body = Scripted::data(&["", "ab", "", "", "cd", ""]);
    body.frames.push_back(Ok(Frame::trailers(trailers.clone())));
    let buffer = ReplayBuffer::new(body, vec![RequestTrailerName::new("x-checksum")], 4);
    let mut first = start(&buffer);
    for chunk in ["", "ab", ""] {
        assert_eq!(poll(&mut first), data(chunk));
    }
    assert_eq!(first.size_hint().exact(), Some(2));

    let mut second = start(&buffer);
    assert_eq!(poll(&mut first), Polled::Error);
    // The next empty frame is still unread in the source.
    for chunk in ["ab", "", "cd", ""] {
        assert_eq!(poll(&mut second), data(chunk));
    }
    assert_eq!(second.size_hint().exact(), Some(0));
    assert!(!second.is_end_stream());
    assert_trailers(&mut second, &trailers);
    assert!(second.is_end_stream());
    assert_eq!(poll(&mut second), Polled::End);
    assert!(buffer.no_replay().is_none());
    assert_eq!(super::lock(&buffer.shared).frames.len(), 2);

    let mut replay = start(&buffer);
    assert_eq!(replay.size_hint().exact(), Some(4));
    assert_eq!(poll(&mut replay), data("ab"));
    assert_eq!(poll(&mut replay), data("cd"));
    assert_trailers(&mut replay, &trailers);
    assert!(replay.is_end_stream());
    assert_eq!(poll(&mut replay), Polled::End);
}

fn assert_trailers(cursor: &mut BufferedAttempt, expected: &HeaderMap) {
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Some(Ok(frame))) = Pin::new(cursor).poll_frame(&mut context) else {
        panic!("the trailer frame was not returned");
    };
    let Ok(trailers) = frame.into_trailers() else {
        panic!("the returned frame was not trailers");
    };
    assert_eq!(&trailers, expected);
}

#[test]
fn trailers_are_sent_again_after_the_data() {
    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", HeaderValue::from_static("1"));
    let mut body = Scripted::data(&["ab"]);
    body.frames.push_back(Ok(Frame::trailers(trailers)));
    let buffer = ReplayBuffer::new(body, vec![RequestTrailerName::new("x-checksum")], 64);
    assert!(buffer.has_trailers());
    for _ in 0..2 {
        let mut cursor = start(&buffer);
        assert_eq!(poll(&mut cursor), data("ab"));
        assert!(!cursor.is_end_stream());
        assert_eq!(poll(&mut cursor), Polled::Trailers);
        assert!(cursor.is_end_stream());
        assert_eq!(poll(&mut cursor), Polled::End);
    }
}

#[test]
fn a_source_error_ends_replays() {
    let mut body = Scripted::data(&["ab"]);
    body.frames
        .push_back(Err(io::Error::other("source failed")));
    let buffer = ReplayBuffer::new(body, Vec::new(), 64);
    let mut cursor = start(&buffer);
    assert_eq!(poll(&mut cursor), data("ab"));
    assert_eq!(poll(&mut cursor), Polled::Error);
    assert!(matches!(buffer.no_replay(), Some(NoReplay::Failed)));
}

#[test]
fn the_source_error_is_in_the_error_chain() {
    let mut body = Scripted::data(&[]);
    body.frames
        .push_back(Err(io::Error::other("source failed")));
    let buffer = ReplayBuffer::new(body, Vec::new(), 64);
    let mut cursor = start(&buffer);
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Some(Err(error))) = Pin::new(&mut cursor).poll_frame(&mut context) else {
        panic!("the source error was not returned");
    };
    let source = std::error::Error::source(&error).map(ToString::to_string);
    assert_eq!(source.as_deref(), Some("source failed"));
}

#[test]
fn dropping_the_owner_frees_kept_frames_as_the_active_attempt_reads() {
    let buffer = ReplayBuffer::new(Scripted::data(&["ab", "cd", "ef"]), Vec::new(), 64);
    let mut first = start(&buffer);
    assert_eq!(poll(&mut first), data("ab"));
    assert_eq!(poll(&mut first), data("cd"));
    let mut replay = start(&buffer);
    let shared = std::sync::Arc::clone(&buffer.shared);
    drop(buffer);
    assert_eq!(poll(&mut replay), data("ab"));
    assert_eq!(super::lock(&shared).frames.len(), 1);
    assert_eq!(poll(&mut replay), data("cd"));
    assert_eq!(poll(&mut replay), data("ef"));
    assert_eq!(poll(&mut replay), Polled::End);
    assert!(super::lock(&shared).frames.is_empty());
}

#[test]
fn dropping_the_owner_at_the_newest_frame_frees_every_kept_frame() {
    let buffer = ReplayBuffer::new(Scripted::data(&["ab", "cd", "ef"]), Vec::new(), 64);
    let mut cursor = start(&buffer);
    assert_eq!(poll(&mut cursor), data("ab"));
    assert_eq!(poll(&mut cursor), data("cd"));
    let shared = std::sync::Arc::clone(&buffer.shared);
    drop(buffer);
    assert!(super::lock(&shared).frames.is_empty());
    assert_eq!(super::lock(&shared).kept_bytes, 0);
    assert_eq!(poll(&mut cursor), data("ef"));
    assert!(super::lock(&shared).frames.is_empty());
}

#[test]
fn dropping_the_owner_mid_replay_frees_the_frames_already_sent() {
    let buffer = ReplayBuffer::new(Scripted::data(&["ab", "cd", "ef"]), Vec::new(), 64);
    let mut first = start(&buffer);
    for chunk in ["ab", "cd", "ef"] {
        assert_eq!(poll(&mut first), data(chunk));
    }
    let mut replay = start(&buffer);
    assert_eq!(poll(&mut replay), data("ab"));
    assert_eq!(poll(&mut replay), data("cd"));
    let shared = std::sync::Arc::clone(&buffer.shared);
    drop(buffer);
    // Only the frame the replay has yet to send is still held.
    assert_eq!(super::lock(&shared).frames.len(), 1);
    assert_eq!(poll(&mut replay), data("ef"));
    assert_eq!(poll(&mut replay), Polled::End);
    assert!(super::lock(&shared).frames.is_empty());
}

#[test]
fn a_replay_that_crosses_the_limit_finishes_and_ends_replays() {
    let buffer = ReplayBuffer::new(Scripted::data(&["ab", "cde"]), Vec::new(), 4);
    let mut first = start(&buffer);
    assert_eq!(poll(&mut first), data("ab"));
    let mut second = start(&buffer);
    assert_eq!(poll(&mut second), data("ab"));
    assert_eq!(poll(&mut second), data("cde"));
    assert_eq!(poll(&mut second), Polled::End);
    assert!(matches!(buffer.no_replay(), Some(NoReplay::Exhausted)));
}

/// A body that is not ready once before each frame.
struct Slow {
    inner: Scripted,
    ready: bool,
}

impl Body for Slow {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if !self.ready {
            self.ready = true;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.ready = false;
        Pin::new(&mut self.inner).poll_frame(context)
    }
}

#[test]
fn a_source_that_is_not_ready_is_waited_for() {
    let slow = Slow {
        inner: Scripted::data(&["ab"]),
        ready: false,
    };
    let buffer = ReplayBuffer::new(slow, Vec::new(), 64);
    let mut cursor = start(&buffer);
    assert_eq!(poll(&mut cursor), Polled::Pending);
    assert_eq!(poll(&mut cursor), data("ab"));
    // A later attempt takes over while the source is not ready.
    assert_eq!(poll(&mut cursor), Polled::Pending);
    let mut replay = start(&buffer);
    assert_eq!(poll(&mut cursor), Polled::Error);
    assert_eq!(poll(&mut replay), data("ab"));
    assert_eq!(poll(&mut replay), Polled::End);
}

#[test]
fn empty_frames_preserve_pending_takeover_and_owner_drop_cleanup() {
    let slow = Slow {
        inner: Scripted::data(&["", "ab", "", "", "cd"]),
        ready: false,
    };
    let buffer = ReplayBuffer::new(slow, Vec::new(), 4);
    let mut first = start(&buffer);
    assert_eq!(poll(&mut first), Polled::Pending);
    assert_eq!(poll(&mut first), data(""));
    assert_eq!(poll(&mut first), Polled::Pending);
    let mut second = start(&buffer);
    assert_eq!(poll(&mut first), Polled::Error);
    assert_eq!(poll(&mut second), data("ab"));
    assert_eq!(poll(&mut second), Polled::Pending);
    assert_eq!(poll(&mut second), data(""));

    let mut replay = start(&buffer);
    let shared = std::sync::Arc::clone(&buffer.shared);
    drop(buffer);
    assert_eq!(poll(&mut second), Polled::Error);
    assert_eq!(poll(&mut replay), data("ab"));
    assert!(super::lock(&shared).frames.is_empty());
    assert_eq!(super::lock(&shared).kept_bytes, 0);
    assert_eq!(poll(&mut replay), Polled::Pending);
    assert_eq!(poll(&mut replay), data(""));
    assert!(super::lock(&shared).frames.is_empty());
    assert_eq!(poll(&mut replay), Polled::Pending);
    assert_eq!(poll(&mut replay), data("cd"));
    assert_eq!(poll(&mut replay), Polled::Pending);
    assert_eq!(poll(&mut replay), Polled::End);
    assert!(replay.is_end_stream());
    assert!(super::lock(&shared).frames.is_empty());
}
