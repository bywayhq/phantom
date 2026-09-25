//! Reuse of an HTTP/1.1 proxy connection after a `407` challenge.
//!
//! Chromium 154 (`HttpProxyClientSocket::PrepareForAuthRestart`) and Firefox
//! 156 send the credentialed CONNECT on the connection that carried the
//! challenge when the `407` leaves it open: the response keeps the connection
//! alive, delimits its body, and the body can be read to its end.

use std::{
    io,
    pin::Pin,
    task::{Context, Waker},
};

use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

/// Largest `407` body read so the challenged proxy connection can carry the
/// credentialed replay.
///
/// A `407` body that is longer, including chunk framing and trailers, is not
/// read further: the connection is closed and the replay opens a new one.
/// Chromium and Firefox read the whole body without a limit; typical proxy
/// challenge pages are a few kilobytes.
pub const MAX_CHALLENGE_BODY_BYTES: usize = 64 * 1024;

const READ_CHUNK_BYTES: usize = 4096;

/// How the body of a `407` ends, when the connection may outlive it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChallengeBody {
    /// `Content-Length` bytes follow the head.
    Length(u64),
    /// The final transfer coding is `chunked`.
    Chunked,
}

impl ChallengeBody {
    /// Returns how the body of this `407` ends, or `None` when the proxy
    /// closes the connection after it.
    ///
    /// Any `close` token in `Connection` or `Proxy-Connection` closes the
    /// connection, as in Firefox, which prefers `close` when both tokens are
    /// present. HTTP/1.0 keeps the connection only with a `keep-alive` token.
    /// A body delimited by the connection close, conflicting or invalid
    /// `Content-Length` values, and `Transfer-Encoding` beside
    /// `Content-Length` also close it.
    pub(super) fn from_head(version: u8, headers: &[httparse::Header<'_>]) -> Option<Self> {
        let mut keep_alive = false;
        let mut content_length = None;
        let mut transfer_encoding = None;
        for header in headers {
            let name = header.name;
            if name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("proxy-connection")
            {
                for token in tokens(header.value) {
                    if token.eq_ignore_ascii_case(b"close") {
                        return None;
                    }
                    keep_alive |= token.eq_ignore_ascii_case(b"keep-alive");
                }
            } else if name.eq_ignore_ascii_case("content-length") {
                let value = parse_content_length(header.value)?;
                if content_length.is_some_and(|existing| existing != value) {
                    return None;
                }
                content_length = Some(value);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                transfer_encoding = tokens(header.value).last().or(transfer_encoding);
            }
        }
        if version == 0 && !keep_alive {
            return None;
        }
        match (transfer_encoding, content_length) {
            (Some(_), Some(_)) => None,
            (Some(coding), None) => coding
                .eq_ignore_ascii_case(b"chunked")
                .then_some(Self::Chunked),
            (None, Some(length)) => Some(Self::Length(length)),
            (None, None) => None,
        }
    }
}

/// Reads the rest of a `407` body and reports whether `stream` is left at the
/// start of the next response.
///
/// `buffered` holds the bytes read after the head. The connection is not
/// reusable when the body exceeds [`MAX_CHALLENGE_BODY_BYTES`], is malformed,
/// ends early, or is followed by bytes the replay did not ask for.
pub(super) async fn drain<S>(stream: &mut S, body: ChallengeBody, buffered: &[u8]) -> bool
where
    S: AsyncRead + Unpin,
{
    let mut decoder = match body {
        ChallengeBody::Length(length) => {
            match usize::try_from(length) {
                Ok(length) if length <= MAX_CHALLENGE_BODY_BYTES => {}
                _ => return false,
            }
            Decoder::Length(length)
        }
        ChallengeBody::Chunked => Decoder::Chunked(Chunked::Size { size: 0, digits: 0 }),
    };
    let mut consumed = 0_usize;
    let mut next = buffered;
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        match decoder.feed(next) {
            Fed::Done { used } => return used == next.len() && is_idle(stream),
            Fed::Invalid => return false,
            Fed::More => {}
        }
        consumed += next.len();
        if consumed >= MAX_CHALLENGE_BODY_BYTES {
            return false;
        }
        let limit = (MAX_CHALLENGE_BODY_BYTES - consumed).min(chunk.len());
        let read = match stream.read(&mut chunk[..limit]).await {
            Ok(0) | Err(_) => return false,
            Ok(read) => read,
        };
        next = &chunk[..read];
    }
}

/// Reports whether `stream` has nothing to read yet, without waiting.
///
/// A proxy that closed the connection after the `407`, or sent bytes after
/// its body, leaves it unfit for the replay. This is the check of Chromium's
/// `HttpProxyClientSocket::DidDrainBodyForAuthRestart`, which requires the
/// socket to be connected and idle. A proxy that closes the connection later
/// is handled when the replay fails.
fn is_idle<S>(stream: &mut S) -> bool
where
    S: AsyncRead + Unpin,
{
    let mut context = Context::from_waker(Waker::noop());
    let mut byte = [0_u8; 1];
    let mut buffer = ReadBuf::new(&mut byte);
    Pin::new(stream)
        .poll_read(&mut context, &mut buffer)
        .is_pending()
}

/// Reports an I/O failure that shows the proxy closed a reused connection.
pub(super) fn is_connection_close(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
    )
}

enum Decoder {
    Length(u64),
    Chunked(Chunked),
}

enum Fed {
    /// The body ended after `used` bytes of the input.
    Done {
        used: usize,
    },
    /// The input ended inside the body.
    More,
    Invalid,
}

impl Decoder {
    fn feed(&mut self, input: &[u8]) -> Fed {
        match self {
            Self::Length(remaining) => {
                let available = input.len() as u64;
                if available >= *remaining {
                    // Bounded by MAX_CHALLENGE_BODY_BYTES before any read.
                    let used = usize::try_from(*remaining).unwrap_or(usize::MAX);
                    *remaining = 0;
                    Fed::Done { used }
                } else {
                    *remaining -= available;
                    Fed::More
                }
            }
            Self::Chunked(state) => state.feed(input),
        }
    }
}

/// RFC 9112 section 7.1 chunked body parser that keeps no data.
enum Chunked {
    Size { size: u64, digits: u8 },
    Extension { size: u64 },
    SizeLineFeed { size: u64 },
    Data { remaining: u64 },
    DataCarriageReturn,
    DataLineFeed,
    TrailerStart,
    Trailer,
    TrailerLineFeed { last: bool },
}

impl Chunked {
    fn feed(&mut self, input: &[u8]) -> Fed {
        let mut index = 0;
        while index < input.len() {
            if let Self::Data { remaining } = self {
                let available = (input.len() - index) as u64;
                let take = available.min(*remaining);
                *remaining -= take;
                // `take` is at most the remaining input length.
                index += usize::try_from(take).unwrap_or(usize::MAX);
                if *remaining == 0 {
                    *self = Self::DataCarriageReturn;
                }
                continue;
            }
            let byte = input[index];
            index += 1;
            *self = match (&*self, byte) {
                (Self::Size { size, digits }, byte) if byte.is_ascii_hexdigit() => {
                    if *digits == 16 {
                        return Fed::Invalid;
                    }
                    let digit = u64::from(hex_value(byte));
                    Self::Size {
                        size: (size << 4) | digit,
                        digits: digits + 1,
                    }
                }
                (Self::Size { size, digits }, b';' | b' ' | b'\t') if *digits > 0 => {
                    Self::Extension { size: *size }
                }
                (Self::Size { size, digits }, b'\r') if *digits > 0 => {
                    Self::SizeLineFeed { size: *size }
                }
                (Self::Extension { size }, b'\r') => Self::SizeLineFeed { size: *size },
                (Self::Extension { size }, byte) if byte == b'\t' || !byte.is_ascii_control() => {
                    Self::Extension { size: *size }
                }
                (Self::SizeLineFeed { size: 0 }, b'\n') => Self::TrailerStart,
                (Self::SizeLineFeed { size }, b'\n') => Self::Data { remaining: *size },
                (Self::DataCarriageReturn, b'\r') => Self::DataLineFeed,
                (Self::DataLineFeed, b'\n') => Self::Size { size: 0, digits: 0 },
                (Self::TrailerStart, b'\r') => Self::TrailerLineFeed { last: true },
                (Self::Trailer, b'\r') => Self::TrailerLineFeed { last: false },
                (Self::TrailerStart | Self::Trailer, byte)
                    if byte == b'\t' || !byte.is_ascii_control() =>
                {
                    Self::Trailer
                }
                (Self::TrailerLineFeed { last: true }, b'\n') => return Fed::Done { used: index },
                (Self::TrailerLineFeed { last: false }, b'\n') => Self::TrailerStart,
                _ => return Fed::Invalid,
            };
        }
        Fed::More
    }
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => byte - b'A' + 10,
    }
}

fn tokens(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(|byte| *byte == b',')
        .map(<[u8]>::trim_ascii)
        .filter(|token| !token.is_empty())
}

fn parse_content_length(value: &[u8]) -> Option<u64> {
    let value = value.trim_ascii();
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}
