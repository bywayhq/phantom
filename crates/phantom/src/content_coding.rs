//! Opt-in streaming decoding of caller-advertised response content codings.
//!
//! Decoding is a facade body concern above every transport. It never adds,
//! removes, or reorders request fields: the caller's own ordered
//! `Accept-Encoding` fields decide which codings a response may use.

mod brotli_stream;
mod field;
mod gzip;
mod inflate;
mod zstd_stream;

#[cfg(test)]
mod tests;

use std::error::Error as StdError;

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, Method, StatusCode, header};
use phantom_net::request::RequestHeader;

use crate::{HttpProtocol, RequestError};

use brotli_stream::BrotliDecoder;
use field::{ContentEncodingList, parse_accept_encoding, parse_content_encoding};
use gzip::GzipDecoder;
use inflate::DeflateDecoder;
use zstd_stream::ZstdDecoder;

pub(crate) use field::AdvertisedContentCodings;

/// Largest decoded data frame yielded by a decoding response body.
const DECODED_FRAME_BYTES: usize = 16 * 1024;

/// A response content coding Phantom can decode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ContentCoding {
    /// `gzip` (and its `x-gzip` alias): one RFC 1952 member.
    Gzip,
    /// `deflate`: an RFC 1950 zlib stream, or a raw RFC 1951 stream when the
    /// body does not start with a zlib header.
    Deflate,
    /// `br`: one RFC 7932 Brotli stream.
    Brotli,
    /// `zstd`: RFC 8878 frames with at most an 8 MiB window (RFC 9659).
    Zstd,
}

impl ContentCoding {
    const ALL: [Self; 4] = [Self::Gzip, Self::Deflate, Self::Brotli, Self::Zstd];

    fn from_token(token: &str) -> Option<Self> {
        if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
            Some(Self::Gzip)
        } else if token.eq_ignore_ascii_case("deflate") {
            Some(Self::Deflate)
        } else if token.eq_ignore_ascii_case("br") {
            Some(Self::Brotli)
        } else if token.eq_ignore_ascii_case("zstd") {
            Some(Self::Zstd)
        } else {
            None
        }
    }
}

/// Opt-in policy for decoding caller-advertised response content codings.
///
/// Phantom never writes `Accept-Encoding`. With [`Self::advertised`], a
/// response may use only codings the request's own ordered `Accept-Encoding`
/// fields advertise; any other coding, an unknown coding, `identity` mixed
/// with a coding, more than three stacked codings, or malformed coded data
/// fails the body with
/// [`RequestErrorKind::ContentDecoding`](crate::RequestErrorKind::ContentDecoding).
/// Response fields, including `Content-Encoding` and `Content-Length`, remain
/// the wire view.
///
/// # Examples
///
/// ```no_run
/// # use phantom::{Client, ContentDecoding, HttpProtocol, RequestError, RequestHeader};
/// # async fn example(client: &Client) -> Result<(), RequestError> {
/// let response = client
///     .get(HttpProtocol::Http2, "https://example.com/")?
///     .header(RequestHeader::new("accept-encoding", "gzip, br"))
///     .content_decoding(ContentDecoding::advertised(8 << 20))
///     .send()
///     .await?;
/// let decoded = response.into_body().collect_with_limit(8 << 20).await?;
/// # let _ = decoded;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContentDecoding {
    maximum_decoded_bytes: Option<u64>,
}

impl ContentDecoding {
    /// Returns response bodies exactly as received. This is the default.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            maximum_decoded_bytes: None,
        }
    }

    /// Decodes codings advertised by the request's `Accept-Encoding` fields.
    ///
    /// `maximum_decoded_bytes` is an inclusive cap on the decoded stream.
    /// Producing more fails the body with
    /// [`RequestErrorKind::ResponseBodyLimit`](crate::RequestErrorKind::ResponseBodyLimit)
    /// and cancels the incomplete response.
    #[must_use]
    pub const fn advertised(maximum_decoded_bytes: u64) -> Self {
        Self {
            maximum_decoded_bytes: Some(maximum_decoded_bytes),
        }
    }

    /// Returns the inclusive decoded-byte cap, or `None` when decoding is disabled.
    #[must_use]
    pub const fn maximum_decoded_bytes(self) -> Option<u64> {
        self.maximum_decoded_bytes
    }

    pub(crate) const fn is_enabled(self) -> bool {
        self.maximum_decoded_bytes.is_some()
    }
}

impl AdvertisedContentCodings {
    /// Reads the caller's ordered `Accept-Encoding` request fields.
    pub(crate) fn from_request_headers(headers: &[RequestHeader]) -> Result<Self, RequestError> {
        parse_accept_encoding(
            headers
                .iter()
                .filter(|header| header.name().eq_ignore_ascii_case("accept-encoding"))
                .map(RequestHeader::value),
        )
        .map_err(RequestError::invalid_accept_encoding)
    }
}

/// The final response's decoding decision.
pub(crate) enum ContentDecodingPlan {
    Passthrough,
    Decode(ContentDecoder, Box<[ContentCoding]>),
    Reject(RequestError),
}

/// Decides how the final response body is exposed.
///
/// Bodyless responses are never validated or decoded.
pub(crate) fn plan(
    policy: ContentDecoding,
    advertised: AdvertisedContentCodings,
    method: &Method,
    status: StatusCode,
    headers: &HeaderMap,
    body_is_empty: bool,
    protocol: HttpProtocol,
) -> ContentDecodingPlan {
    let Some(maximum_decoded_bytes) = policy.maximum_decoded_bytes else {
        return ContentDecodingPlan::Passthrough;
    };
    if method == Method::HEAD
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || body_is_empty
    {
        return ContentDecodingPlan::Passthrough;
    }
    let values = headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .map(http::HeaderValue::as_bytes);
    let codings = match parse_content_encoding(values) {
        Ok(ContentEncodingList::Identity) => return ContentDecodingPlan::Passthrough,
        Ok(ContentEncodingList::Codings(codings)) => codings,
        Err(message) => {
            return ContentDecodingPlan::Reject(RequestError::content_decoding(
                protocol, message, None,
            ));
        }
    };
    if codings.iter().any(|coding| !advertised.contains(*coding)) {
        return ContentDecodingPlan::Reject(RequestError::content_decoding(
            protocol,
            "response uses a content coding the request did not advertise",
            None,
        ));
    }
    match ContentDecoder::new(&codings, maximum_decoded_bytes, protocol) {
        Ok(decoder) => ContentDecodingPlan::Decode(decoder, codings.into_boxed_slice()),
        Err(error) => ContentDecodingPlan::Reject(error),
    }
}

/// Result of driving a [`ContentDecoder`] as far as its buffered input allows.
#[derive(Debug)]
pub(crate) enum Pump {
    /// One decoded data frame of at most [`DECODED_FRAME_BYTES`].
    Data(Bytes),
    /// Every buffered byte is consumed; the next wire frame is needed.
    NeedInput,
    /// The wire body ended and every stage completed.
    Finished,
}

/// Bounded pipeline of decoding stages, applied in reverse application order.
pub(crate) struct ContentDecoder {
    protocol: HttpProtocol,
    stages: Vec<Stage>,
    /// `buffers[index]` holds output of `stages[index]` awaiting `stages[index + 1]`.
    buffers: Vec<StageBuffer>,
    wire: Bytes,
    wire_ended: bool,
    decoded_bytes: u64,
    maximum_decoded_bytes: u64,
}

impl ContentDecoder {
    fn new(
        codings: &[ContentCoding],
        maximum_decoded_bytes: u64,
        protocol: HttpProtocol,
    ) -> Result<Self, RequestError> {
        let stages = codings
            .iter()
            .rev()
            .map(|coding| Stage::new(*coding))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.into_request_error(protocol))?;
        let buffers = (1..stages.len()).map(|_| StageBuffer::new()).collect();
        Ok(Self {
            protocol,
            stages,
            buffers,
            wire: Bytes::new(),
            wire_ended: false,
            decoded_bytes: 0,
            maximum_decoded_bytes,
        })
    }

    /// Appends one encoded wire data frame.
    pub(crate) fn push(&mut self, data: Bytes) {
        if self.wire.is_empty() {
            self.wire = data;
        } else {
            let mut combined = BytesMut::with_capacity(self.wire.len() + data.len());
            combined.extend_from_slice(&self.wire);
            combined.extend_from_slice(&data);
            self.wire = combined.freeze();
        }
    }

    /// Records that the wire body has no further data.
    pub(crate) fn end_input(&mut self) {
        self.wire_ended = true;
    }

    /// Decodes buffered input into at most one bounded data frame.
    pub(crate) fn pump(&mut self) -> Result<Pump, RequestError> {
        let remaining = self
            .maximum_decoded_bytes
            .saturating_sub(self.decoded_bytes);
        // One byte past the cap is enough to observe an over-limit stream.
        let capacity = usize::try_from(remaining.saturating_add(1))
            .map_or(DECODED_FRAME_BYTES, |bound| bound.min(DECODED_FRAME_BYTES));
        let mut output = BytesMut::zeroed(capacity);
        let mut written = 0;

        loop {
            let mut progressed = false;
            for index in (0..self.stages.len()).rev() {
                let (stage_progressed, produced) = self
                    .run_stage(index, &mut output[written..])
                    .map_err(|error| error.into_request_error(self.protocol))?;
                progressed |= stage_progressed;
                written += produced;
            }
            if written == capacity || !progressed {
                break;
            }
        }

        if written > 0 {
            self.decoded_bytes = self
                .decoded_bytes
                .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
            if self.decoded_bytes > self.maximum_decoded_bytes {
                return Err(RequestError::decoded_body_limit(self.protocol));
            }
            output.truncate(written);
            return Ok(Pump::Data(output.freeze()));
        }
        if !self.wire.is_empty() || self.buffers.iter().any(|buffer| !buffer.is_empty()) {
            return Err(RequestError::content_decoding(
                self.protocol,
                "content decoder stopped making progress",
                None,
            ));
        }
        if !self.wire_ended {
            return Ok(Pump::NeedInput);
        }
        if self.stages.iter().all(Stage::is_complete) {
            Ok(Pump::Finished)
        } else {
            Err(RequestError::content_decoding(
                self.protocol,
                "content-coded response ended before its stream completed",
                None,
            ))
        }
    }

    /// Runs one stage step and returns `(progressed, produced_into_final_output)`.
    fn run_stage(
        &mut self,
        index: usize,
        final_output: &mut [u8],
    ) -> Result<(bool, usize), StageError> {
        let last = index + 1 == self.stages.len();
        let (before, after) = self.buffers.split_at_mut(index);
        let input: &[u8] = match index
            .checked_sub(1)
            .and_then(|previous| before.get(previous))
        {
            Some(buffer) => buffer.pending(),
            None => &self.wire,
        };
        let output: &mut [u8] = if last {
            final_output
        } else {
            let Some(buffer) = after.first_mut() else {
                return Ok((false, 0));
            };
            if !buffer.is_empty() {
                return Ok((false, 0));
            }
            buffer.reset();
            &mut buffer.bytes
        };
        if output.is_empty() {
            return Ok((false, 0));
        }
        let Some(stage) = self.stages.get_mut(index) else {
            return Ok((false, 0));
        };
        let step = stage.decode(input, output)?;

        match index
            .checked_sub(1)
            .and_then(|previous| self.buffers.get_mut(previous))
        {
            Some(buffer) => buffer.start += step.consumed,
            None => self.wire.advance(step.consumed),
        }
        if !last {
            if let Some(buffer) = self.buffers.get_mut(index) {
                buffer.end = step.produced;
            }
        }
        let progressed = step.consumed > 0 || step.produced > 0;
        Ok((progressed, if last { step.produced } else { 0 }))
    }
}

struct StageBuffer {
    bytes: Box<[u8]>,
    start: usize,
    end: usize,
}

impl StageBuffer {
    fn new() -> Self {
        Self {
            bytes: vec![0; DECODED_FRAME_BYTES].into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }

    fn pending(&self) -> &[u8] {
        self.bytes.get(self.start..self.end).unwrap_or_default()
    }

    const fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    fn reset(&mut self) {
        self.start = 0;
        self.end = 0;
    }
}

enum Stage {
    Gzip(Box<GzipDecoder>),
    Deflate(DeflateDecoder),
    Brotli(BrotliDecoder),
    Zstd(Box<ZstdDecoder>),
}

impl Stage {
    fn new(coding: ContentCoding) -> Result<Self, StageError> {
        Ok(match coding {
            ContentCoding::Gzip => Self::Gzip(Box::new(GzipDecoder::new())),
            ContentCoding::Deflate => Self::Deflate(DeflateDecoder::new()),
            ContentCoding::Brotli => Self::Brotli(BrotliDecoder::new()),
            ContentCoding::Zstd => Self::Zstd(Box::new(ZstdDecoder::new()?)),
        })
    }

    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step, StageError> {
        match self {
            Self::Gzip(decoder) => decoder.decode(input, output),
            Self::Deflate(decoder) => decoder.decode(input, output),
            Self::Brotli(decoder) => decoder.decode(input, output),
            Self::Zstd(decoder) => decoder.decode(input, output),
        }
    }

    fn is_complete(&self) -> bool {
        match self {
            Self::Gzip(decoder) => decoder.is_complete(),
            Self::Deflate(decoder) => decoder.is_complete(),
            Self::Brotli(decoder) => decoder.is_complete(),
            Self::Zstd(decoder) => decoder.is_complete(),
        }
    }
}

/// Bytes one stage step read from its input and wrote to its output.
#[derive(Clone, Copy, Debug)]
struct Step {
    consumed: usize,
    produced: usize,
}

impl Step {
    const fn new(consumed: usize, produced: usize) -> Self {
        Self { consumed, produced }
    }
}

/// Failure of one decoding stage before protocol attribution.
#[derive(Debug)]
struct StageError {
    message: &'static str,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl StageError {
    const fn new(message: &'static str) -> Self {
        Self {
            message,
            source: None,
        }
    }

    fn with_source(message: &'static str, source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            message,
            source: Some(Box::new(source)),
        }
    }

    fn into_request_error(self, protocol: HttpProtocol) -> RequestError {
        RequestError::content_decoding(protocol, self.message, self.source)
    }
}
