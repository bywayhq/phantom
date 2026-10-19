use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame};
use phantom_net::request::RequestBody;
use tokio::io::{AsyncRead, ReadBuf};

use super::{
    BodyBuffer, MAX_MULTIPART_PARTS, MultipartPart, PreparedBodyError, PreparedBodyErrorKind,
};

/// One ordered multipart field whose contents can be read on demand.
///
/// Byte fields and readers default to `application/octet-stream`. Text fields
/// normalize newlines like [`MultipartPart::text`] and have no content type.
/// Names, filenames and content types follow [`MultipartPart`]'s limits.
pub struct StreamingMultipartPart {
    name: Box<str>,
    filename: Option<Box<str>>,
    content_type: Option<Box<str>>,
    body: RequestBody,
}

impl StreamingMultipartPart {
    /// Keeps already-owned bytes without copying their contents.
    ///
    /// # Errors
    /// Returns [`PreparedBodyError`] for an invalid or oversized field name.
    pub fn bytes(name: &str, data: Bytes) -> Result<Self, PreparedBodyError> {
        MultipartPart::bytes(name, &[])?;
        Ok(Self::new(name, RequestBody::from_bytes(data)))
    }

    /// Buffers and normalizes a UTF-8 text field within `maximum_bytes`.
    ///
    /// The bound covers the normalized value, before multipart framing.
    ///
    /// # Errors
    /// Returns [`PreparedBodyError`] for invalid metadata or a value past the bound.
    pub fn text(name: &str, value: &str, maximum_bytes: usize) -> Result<Self, PreparedBodyError> {
        MultipartPart::text(name, value)?;
        let mut output = BodyBuffer::new(maximum_bytes);
        super::write_text(&mut output, value.as_bytes())?;
        let mut part = Self::new(name, RequestBody::from_bytes(output.bytes.into()));
        part.content_type = None;
        Ok(part)
    }

    /// Streams an async reader, including a Tokio file, in chunks of at most 8 KiB.
    ///
    /// No read occurs until the body is polled. Dropping the body drops the
    /// reader. Buffering inside your reader is outside this helper's bound.
    ///
    /// # Errors
    /// Returns [`PreparedBodyError`] for an invalid or oversized field name.
    pub fn reader<R: AsyncRead + Send + 'static>(
        name: &str,
        reader: R,
    ) -> Result<Self, PreparedBodyError> {
        Self::stream(
            name,
            ReaderBody {
                reader: Box::pin(reader),
            },
        )
    }

    /// Streams one pull body. Trailer frames are rejected.
    ///
    /// The source controls frame size. Frames are passed through without
    /// collecting the complete part or copying their contents.
    ///
    /// # Errors
    /// Returns [`PreparedBodyError`] for an invalid or oversized field name.
    pub fn stream<B>(name: &str, body: B) -> Result<Self, PreparedBodyError>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Error + Send + Sync + 'static,
    {
        MultipartPart::bytes(name, &[])?;
        Ok(Self::new(name, RequestBody::streaming(body)))
    }

    fn new(name: &str, body: RequestBody) -> Self {
        Self {
            name: name.into(),
            filename: None,
            content_type: Some("application/octet-stream".into()),
            body,
        }
    }

    /// Adds a caller-selected filename without opening or renaming a file.
    ///
    /// # Errors
    /// Returns [`PreparedBodyError`] under [`MultipartPart::with_filename`]'s rules.
    pub fn with_filename(mut self, filename: &str) -> Result<Self, PreparedBodyError> {
        MultipartPart::bytes("", &[])?.with_filename(filename)?;
        self.filename = Some(filename.into());
        Ok(self)
    }

    /// Sets a part's exact `token/token` media type.
    ///
    /// # Errors
    /// Returns [`PreparedBodyError`] under [`MultipartPart::with_content_type`]'s rules.
    pub fn with_content_type(mut self, content_type: &str) -> Result<Self, PreparedBodyError> {
        MultipartPart::bytes("", &[])?.with_content_type(content_type)?;
        self.content_type = Some(content_type.into());
        Ok(self)
    }
}

impl fmt::Debug for StreamingMultipartPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingMultipartPart")
            .field("has_filename", &self.filename.is_some())
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

/// A bounded, one-shot multipart upload with an explicit boundary.
///
/// Fields retain their supplied order and duplicate names. Metadata is prepared
/// up front; readers are pulled one at a time with transport backpressure.
/// Buffered text and metadata are retained, but file contents are not collected.
/// No browser-specific boundary is generated.
///
/// Use [`crate::RequestBuilder::multipart_body`] to retain content-type placement
/// checks. The body has an unknown total size: HTTP/1.1 uses chunked coding,
/// while HTTP/2 and HTTP/3 omit `Content-Length`. It cannot be replayed.
///
/// The byte cap includes headers, delimiters and contents. A cap violation,
/// boundary collision or source failure ends the body and drops all remaining
/// sources. Such an error can occur after earlier upload bytes were sent.
pub struct StreamingMultipartBody {
    parts: VecDeque<EncodedPart>,
    closing: Option<Bytes>,
    content_type: Box<str>,
    remaining: usize,
    scan: BoundaryScan,
    finished: bool,
}

struct EncodedPart {
    header: Option<Bytes>,
    body: RequestBody,
}

impl StreamingMultipartBody {
    /// Prepares at most 1024 fields without polling their contents.
    ///
    /// The boundary and metadata use [`crate::PreparedRequestBody::multipart`]'s
    /// rules. Any occurrence of `--` followed by the boundary in a field is
    /// rejected, including occurrences split across source frames.
    ///
    /// # Errors
    /// Returns [`PreparedBodyError`] for an invalid boundary, too many parts,
    /// or metadata and delimiters that exceed `maximum_bytes`.
    ///
    /// ```
    /// use phantom::{StreamingMultipartBody, StreamingMultipartPart};
    /// # fn example() -> Result<(), phantom::PreparedBodyError> {
    /// let fields = [
    ///     StreamingMultipartPart::text("tag", "first", 1024)?,
    ///     StreamingMultipartPart::reader("file", std::io::Cursor::new(b"contents"))?
    ///         .with_filename("upload.txt")?,
    /// ];
    /// let body = StreamingMultipartBody::new("caller-boundary", fields, 1024 * 1024)?;
    /// assert_eq!(body.content_type(), "multipart/form-data; boundary=caller-boundary");
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        boundary: &str,
        parts: impl IntoIterator<Item = StreamingMultipartPart>,
        maximum_bytes: usize,
    ) -> Result<Self, PreparedBodyError> {
        let content_type = super::multipart_content_type(boundary)?;
        let delimiter = format!("--{boundary}");
        let closing = Bytes::from(format!("{delimiter}--\r\n"));
        let mut metadata_bytes = closing.len();
        let mut encoded = VecDeque::new();
        if metadata_bytes > maximum_bytes {
            return Err(PreparedBodyError::new(PreparedBodyErrorKind::TooLarge));
        }
        for (index, part) in parts.into_iter().enumerate() {
            if index == MAX_MULTIPART_PARTS {
                return Err(PreparedBodyError::new(PreparedBodyErrorKind::TooManyParts));
            }
            let mut header = BodyBuffer::new(maximum_bytes - metadata_bytes);
            super::write_multipart_header(
                &mut header,
                &delimiter,
                &MultipartPart {
                    name: &part.name,
                    data: &[],
                    filename: part.filename.as_deref(),
                    content_type: part.content_type.as_deref(),
                    normalize_text: false,
                },
            )?;
            metadata_bytes = metadata_bytes
                .checked_add(header.bytes.len())
                .and_then(|n| n.checked_add(2))
                .filter(|n| *n <= maximum_bytes)
                .ok_or_else(|| PreparedBodyError::new(PreparedBodyErrorKind::TooLarge))?;
            encoded.push_back(EncodedPart {
                header: Some(header.bytes.into()),
                body: part.body,
            });
        }
        Ok(Self {
            parts: encoded,
            closing: Some(closing),
            content_type,
            remaining: maximum_bytes,
            scan: BoundaryScan {
                delimiter: delimiter.into_bytes(),
                tail: [0; 72],
                length: 0,
            },
            finished: false,
        })
    }

    /// Returns the exact content type, including boundary quoting when needed.
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    fn emit(&mut self, data: Bytes) -> Poll<Option<Result<Frame<Bytes>, MultipartStreamError>>> {
        match self.remaining.checked_sub(data.len()) {
            Some(remaining) => {
                self.remaining = remaining;
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            None => self.fail(MultipartStreamError::Framing(PreparedBodyError::new(
                PreparedBodyErrorKind::TooLarge,
            ))),
        }
    }

    fn fail(
        &mut self,
        error: MultipartStreamError,
    ) -> Poll<Option<Result<Frame<Bytes>, MultipartStreamError>>> {
        self.finished = true;
        self.parts.clear();
        self.closing = None;
        Poll::Ready(Some(Err(error)))
    }
}

impl fmt::Debug for StreamingMultipartBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingMultipartBody")
            .field("parts", &self.parts.len())
            .field("remaining_bytes", &self.remaining)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Body for StreamingMultipartBody {
    type Data = Bytes;
    type Error = MultipartStreamError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        if let Some(part) = self.parts.front_mut() {
            if let Some(header) = part.header.take() {
                return self.emit(header);
            }
            match Pin::new(&mut part.body).poll_frame(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(error))) => {
                    return self.fail(MultipartStreamError::Source(Box::new(error)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    // RequestBody rejects source trailers before returning a frame.
                    if let Ok(data) = frame.into_data() {
                        if self.scan.collides(&data) {
                            return self.fail(MultipartStreamError::Framing(
                                PreparedBodyError::new(PreparedBodyErrorKind::BoundaryCollision),
                            ));
                        }
                        return self.emit(data);
                    }
                    return self.fail(MultipartStreamError::Source(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "multipart source returned a trailer",
                    ))));
                }
                Poll::Ready(None) => {
                    self.parts.pop_front();
                    self.scan.length = 0;
                    return self.emit(Bytes::from_static(b"\r\n"));
                }
            }
        }
        self.finished = true;
        match self.closing.take() {
            Some(closing) => self.emit(closing),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }
}

/// A multipart framing limit or a failure from one of its data sources.
///
/// Display omits payloads and metadata. The source error can contain details
/// supplied by your reader or body implementation.
#[derive(Debug)]
#[non_exhaustive]
pub enum MultipartStreamError {
    /// The encoded body exceeded its cap or contained its boundary delimiter.
    Framing(PreparedBodyError),
    /// A source body failed, including an undeclared trailer frame.
    Source(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for MultipartStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Framing(error) => write!(f, "multipart framing failed ({:?})", error.kind()),
            Self::Source(_) => f.write_str("multipart data source failed"),
        }
    }
}
impl Error for MultipartStreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match self {
            Self::Framing(error) => error,
            Self::Source(error) => error.as_ref(),
        })
    }
}

struct ReaderBody<R> {
    reader: Pin<Box<R>>,
}
impl<R: AsyncRead> Body for ReaderBody<R> {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let mut bytes = [0; 8192];
        let mut buffer = ReadBuf::new(&mut bytes);
        match self.reader.as_mut().poll_read(context, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Ready(Ok(())) if buffer.filled().is_empty() => Poll::Ready(None),
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(
                buffer.filled(),
            ))))),
        }
    }
}

struct BoundaryScan {
    delimiter: Vec<u8>,
    tail: [u8; 72],
    length: usize,
}
impl BoundaryScan {
    fn collides(&mut self, data: &[u8]) -> bool {
        let keep = self.delimiter.len() - 1;
        let prefix = data.len().min(keep);
        let mut join = [0; 144];
        join[..self.length].copy_from_slice(&self.tail[..self.length]);
        join[self.length..self.length + prefix].copy_from_slice(&data[..prefix]);
        if join[..self.length + prefix]
            .windows(self.delimiter.len())
            .any(|w| w == self.delimiter)
            || data
                .windows(self.delimiter.len())
                .any(|w| w == self.delimiter)
        {
            return true;
        }
        if data.len() >= keep {
            self.tail[..keep].copy_from_slice(&data[data.len() - keep..]);
            self.length = keep;
        } else {
            let total = self.length + prefix;
            self.length = total.min(keep);
            self.tail[..self.length].copy_from_slice(&join[total - self.length..total]);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::{
        io::Cursor,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Waker,
    };
    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    struct Frames(VecDeque<Result<Frame<Bytes>, std::io::Error>>);
    impl Body for Frames {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front())
        }
    }
    fn frames(data: impl IntoIterator<Item = Bytes>) -> Frames {
        Frames(data.into_iter().map(|data| Ok(Frame::data(data))).collect())
    }

    #[tokio::test]
    async fn bytes_match_the_existing_encoder_with_duplicate_names_and_escaping() -> TestResult {
        let expected = super::super::PreparedRequestBody::multipart(
            "a:b",
            [
                MultipartPart::text("tag", "first\nsecond")?,
                MultipartPart::bytes("tag", b"\x00\xff")?
                    .with_filename("a\"b.txt")?
                    .with_content_type("text/plain")?,
            ],
            1024,
        )?;
        let streamed = StreamingMultipartBody::new(
            "a:b",
            [
                StreamingMultipartPart::text("tag", "first\nsecond", 1024)?,
                StreamingMultipartPart::reader("tag", Cursor::new(b"\x00\xff"))?
                    .with_filename("a\"b.txt")?
                    .with_content_type("text/plain")?,
            ],
            expected.bytes().len(),
        )?;
        assert_eq!(streamed.content_type(), expected.content_type());
        assert_eq!(streamed.collect().await?.to_bytes(), *expected.bytes());
        Ok(())
    }

    #[tokio::test]
    async fn boundary_collision_is_detected_at_every_frame_split() -> TestResult {
        for boundary in ["x".to_owned(), "a".repeat(70)] {
            let payload = format!("prefix--{boundary}suffix");
            for split in 0..=payload.len() {
                let source = frames([
                    Bytes::copy_from_slice(&payload.as_bytes()[..split]),
                    Bytes::copy_from_slice(&payload.as_bytes()[split..]),
                ]);
                let body = StreamingMultipartBody::new(
                    &boundary,
                    [StreamingMultipartPart::stream("f", source)?],
                    4096,
                )?;
                assert!(
                    matches!(body.collect().await, Err(MultipartStreamError::Framing(error)) if error.kind() == PreparedBodyErrorKind::BoundaryCollision)
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn total_cap_covers_framing_and_fuses_after_failure() -> TestResult {
        let expected = super::super::PreparedRequestBody::multipart(
            "b",
            [MultipartPart::bytes("f", &[b'a'; 64])?],
            4096,
        )?;
        let part = || StreamingMultipartPart::bytes("f", Bytes::from_static(&[b'a'; 64]));
        let exact = StreamingMultipartBody::new("b", [part()?], expected.bytes().len())?;
        assert_eq!(exact.collect().await?.to_bytes(), *expected.bytes());
        let mut short = StreamingMultipartBody::new("b", [part()?], expected.bytes().len() - 1)?;
        let mut failed = false;
        while let Some(frame) = short.frame().await {
            if let Err(error) = frame {
                assert!(
                    matches!(error, MultipartStreamError::Framing(e) if e.kind() == PreparedBodyErrorKind::TooLarge)
                );
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(short.is_end_stream());
        assert!(short.frame().await.is_none());
        assert!(StreamingMultipartBody::new("b", [], 0).is_err());
        Ok(())
    }

    struct PendingReader {
        reads: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for PendingReader {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    #[test]
    fn cancellation_drops_current_and_unpolled_sources() -> TestResult {
        let reads = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let parts = (0..2).map(|_| {
            StreamingMultipartPart::reader(
                "f",
                PendingReader {
                    reads: reads.clone(),
                    drops: drops.clone(),
                },
            )
        });
        let mut body =
            StreamingMultipartBody::new("b", parts.collect::<Result<Vec<_>, _>>()?, 4096)?;
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        let mut context = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut body).poll_frame(&mut context).is_ready());
        assert!(Pin::new(&mut body).poll_frame(&mut context).is_pending());
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        drop(body);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test]
    async fn reader_chunks_are_bounded_and_binary_data_is_preserved() -> TestResult {
        let contents = vec![42; 100_000];
        let part = StreamingMultipartPart::reader("file", Cursor::new(contents.clone()))?;
        let mut body = StreamingMultipartBody::new("b", [part], 101_000)?;
        body.frame().await.ok_or("missing header")??;
        let mut actual = Vec::new();
        while actual.len() < contents.len() {
            let data = body
                .frame()
                .await
                .ok_or("missing data")??
                .into_data()
                .map_err(|_| "unexpected trailers")?;
            assert!(data.len() <= 8192);
            actual.extend_from_slice(&data);
        }
        assert_eq!(actual, contents);
        assert_eq!(
            body.frame()
                .await
                .ok_or("missing separator")??
                .into_data()
                .map_err(|_| "trailers")?,
            "\r\n"
        );
        assert_eq!(
            body.frame()
                .await
                .ok_or("missing close")??
                .into_data()
                .map_err(|_| "trailers")?,
            "--b--\r\n"
        );
        assert!(body.is_end_stream());
        Ok(())
    }

    #[tokio::test]
    async fn source_errors_and_trailers_fail_without_polling_the_next_part() -> TestResult {
        for source in [
            Frames([Err(std::io::Error::other("source failed"))].into()),
            Frames([Ok(Frame::trailers(http::HeaderMap::new()))].into()),
        ] {
            let reads = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let mut body = StreamingMultipartBody::new(
                "b",
                [
                    StreamingMultipartPart::stream("first", source)?,
                    StreamingMultipartPart::reader(
                        "later",
                        PendingReader {
                            reads: reads.clone(),
                            drops: drops.clone(),
                        },
                    )?,
                ],
                4096,
            )?;
            body.frame().await.ok_or("missing header")??;
            let error = body
                .frame()
                .await
                .ok_or("missing source error")?
                .err()
                .ok_or("source succeeded")?;
            assert!(matches!(error, MultipartStreamError::Source(_)));
            assert!(error.source().is_some());
            assert!(body.is_end_stream());
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
        Ok(())
    }
}
