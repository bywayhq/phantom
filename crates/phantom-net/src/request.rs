//! Request syntax shared by HTTP protocol implementations.

use std::{
    error::Error as StdError,
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{
    Uri,
    uri::{Authority, PathAndQuery},
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, combinators::UnsyncBoxBody};

type BoxError = Box<dyn StdError + Send + Sync>;

/// Stable category of a caller-provided request-body failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestBodyErrorKind {
    /// The caller-provided body returned an error.
    Source,
    /// The body emitted a byte count different from its exact size hint.
    LengthMismatch,
    /// The body emitted trailers, which this request slice does not support.
    TrailersUnsupported,
}

/// Error produced while pulling a caller-provided request body.
pub struct RequestBodyError {
    kind: RequestBodyErrorKind,
    source: Option<BoxError>,
}

impl RequestBodyError {
    fn source(error: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            kind: RequestBodyErrorKind::Source,
            source: Some(Box::new(error)),
        }
    }

    fn length_mismatch() -> Self {
        Self {
            kind: RequestBodyErrorKind::LengthMismatch,
            source: None,
        }
    }

    fn trailers_unsupported() -> Self {
        Self {
            kind: RequestBodyErrorKind::TrailersUnsupported,
            source: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> RequestBodyErrorKind {
        self.kind
    }
}

impl fmt::Debug for RequestBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBodyError")
            .field("kind", &self.kind)
            .field("has_source", &self.source.is_some())
            .finish()
    }
}

impl fmt::Display for RequestBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            RequestBodyErrorKind::Source => formatter.write_str("request body source failed"),
            RequestBodyErrorKind::LengthMismatch => {
                formatter.write_str("request body length did not match its exact size hint")
            }
            RequestBodyErrorKind::TrailersUnsupported => {
                formatter.write_str("request trailers are not supported")
            }
        }
    }
}

impl StdError for RequestBodyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

/// Framing metadata captured before a request body is polled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBodyMetadata {
    exact_length: Option<u64>,
}

impl RequestBodyMetadata {
    /// Returns the body's exact byte length when its initial size hint supplied one.
    #[must_use]
    pub const fn exact_length(self) -> Option<u64> {
        self.exact_length
    }
}

/// One pull-driven request body consumed by exactly one transport attempt.
///
/// The body retains at most the frame currently returned by its source. Exact
/// size hints are enforced while frames are pulled, and trailers fail
/// explicitly until Phantom has an ordered request-trailer representation.
pub struct RequestBody {
    inner: UnsyncBoxBody<Bytes, RequestBodyError>,
    exact_length: Option<u64>,
    emitted: u64,
    finished: bool,
}

impl RequestBody {
    /// Erases a caller-provided pull body for one request attempt.
    pub fn streaming<B>(body: B) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: StdError + Send + Sync + 'static,
    {
        let exact_length = body.size_hint().exact();
        Self {
            inner: body.map_err(RequestBodyError::source).boxed_unsync(),
            exact_length,
            emitted: 0,
            finished: false,
        }
    }

    /// Wraps one complete replayable byte body for a transport attempt.
    #[must_use]
    pub fn from_bytes(body: Bytes) -> Self {
        Self::streaming(http_body_util::Full::new(body))
    }

    /// Returns framing metadata without polling the body.
    #[must_use]
    pub const fn metadata(&self) -> RequestBodyMetadata {
        RequestBodyMetadata {
            exact_length: self.exact_length,
        }
    }
}

impl fmt::Debug for RequestBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBody")
            .field("exact_length", &self.exact_length)
            .field("emitted", &self.emitted)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = RequestBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let Some(emitted) = self.emitted.checked_add(data.len() as u64) else {
                        self.finished = true;
                        return Poll::Ready(Some(Err(RequestBodyError::length_mismatch())));
                    };
                    if self.exact_length.is_some_and(|expected| emitted > expected) {
                        self.finished = true;
                        return Poll::Ready(Some(Err(RequestBodyError::length_mismatch())));
                    }
                    self.emitted = emitted;
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(_frame) => {
                    self.finished = true;
                    Poll::Ready(Some(Err(RequestBodyError::trailers_unsupported())))
                }
            },
            Poll::Ready(None) => {
                self.finished = true;
                if self
                    .exact_length
                    .is_some_and(|expected| self.emitted != expected)
                {
                    Poll::Ready(Some(Err(RequestBodyError::length_mismatch())))
                } else {
                    Poll::Ready(None)
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
            || (self.inner.is_end_stream()
                && self
                    .exact_length
                    .is_none_or(|expected| self.emitted == expected))
    }

    fn size_hint(&self) -> SizeHint {
        match self.exact_length {
            Some(expected) => SizeHint::with_exact(expected.saturating_sub(self.emitted)),
            None => self.inner.size_hint(),
        }
    }
}

/// An HTTP absolute-form request target such as `http://example.test/search?q=rust`.
///
/// HTTP forward proxies receive this form instead of the origin-form used by
/// direct and tunneled requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbsoluteForm {
    uri: Uri,
    authority: Authority,
}

impl AbsoluteForm {
    /// Parses an HTTP or HTTPS absolute-form request target.
    pub fn parse(value: &str) -> Result<Self, InvalidAbsoluteForm> {
        if value.contains('#') {
            return Err(InvalidAbsoluteForm);
        }
        value
            .parse::<Uri>()
            .map_err(|_| InvalidAbsoluteForm)
            .and_then(Self::from_uri)
    }

    /// Validates an already-parsed HTTP URI as absolute-form.
    pub fn from_uri(uri: Uri) -> Result<Self, InvalidAbsoluteForm> {
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri
                .path_and_query()
                .is_none_or(|target| target.as_str().contains('#'))
        {
            return Err(InvalidAbsoluteForm);
        }
        let authority = uri.authority().cloned().ok_or(InvalidAbsoluteForm)?;
        if authority.as_str().as_bytes().contains(&b'@') {
            return Err(InvalidAbsoluteForm);
        }
        Ok(Self { uri, authority })
    }

    pub(crate) fn authority(&self) -> &str {
        self.authority.as_str()
    }

    pub(crate) fn into_uri(self) -> Uri {
        self.uri
    }
}

/// Error returned when a request target is not valid HTTP absolute-form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAbsoluteForm;

impl fmt::Display for InvalidAbsoluteForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "request target must be HTTP absolute-form with an http or https scheme and authority",
        )
    }
}

impl StdError for InvalidAbsoluteForm {}

/// An HTTP origin-form request target such as `/search?q=rust`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginForm(PathAndQuery);

impl OriginForm {
    /// Parses an origin-form request target.
    pub fn parse(value: &str) -> Result<Self, InvalidOriginForm> {
        let uri = value.parse::<Uri>().map_err(|_| InvalidOriginForm)?;
        let is_origin_form = value.starts_with('/')
            && uri.scheme().is_none()
            && uri.authority().is_none()
            && uri
                .path_and_query()
                .is_some_and(|path_and_query| path_and_query.as_str() == value);

        if !is_origin_form {
            return Err(InvalidOriginForm);
        }

        match uri.into_parts().path_and_query {
            Some(path_and_query) => Ok(Self(path_and_query)),
            None => Err(InvalidOriginForm),
        }
    }

    pub(crate) fn into_uri(self) -> Uri {
        self.0.into()
    }

    pub(crate) fn into_path_and_query(self) -> PathAndQuery {
        self.0
    }
}

/// Error returned when a request target is not valid HTTP origin-form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidOriginForm;

impl fmt::Display for InvalidOriginForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "request target must be HTTP origin-form beginning with `/` and contain no authority or fragment",
        )
    }
}

impl StdError for InvalidOriginForm {}

/// A request header retaining caller-supplied spelling, value, and position.
///
/// Each protocol validates this representation against its own wire rules.
/// HTTP/1 preserves the supplied field-name spelling; HTTP/2 and HTTP/3 require
/// lowercase field names while preserving field order and duplicate positions.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestHeader {
    name: Box<str>,
    value: Box<[u8]>,
    sensitive: bool,
}

impl RequestHeader {
    /// Creates a header to be validated when the request is sent.
    ///
    /// Construction is intentionally infallible so validation of the complete
    /// ordered header list happens once, before the supplied stream is touched.
    #[must_use]
    pub fn new(name: impl Into<Box<str>>, value: impl AsRef<[u8]>) -> Self {
        Self {
            name: name.into(),
            value: value.as_ref().into(),
            sensitive: false,
        }
    }

    /// Marks this field as sensitive for compression-layer encoding.
    ///
    /// HTTP/2 and HTTP/3 emit sensitive fields as never-indexed literals.
    /// HTTP/1 wire bytes are unchanged. Debug output redacts the value.
    #[must_use]
    pub fn sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }

    /// Returns the exact field-name spelling that will be written.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the field value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns whether compression layers must never index this field.
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        self.sensitive
    }
}

impl fmt::Debug for RequestHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RequestHeader");
        debug.field("name", &self.name);
        if self.sensitive {
            debug.field("value", &"<redacted>");
        } else {
            debug.field("value", &self.value);
        }
        debug.field("sensitive", &self.sensitive).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io, pin::Pin, task::Poll};

    use bytes::Bytes;
    use http::HeaderMap;
    use http_body::{Body, Frame, SizeHint};
    use http_body_util::BodyExt as _;

    use super::{
        AbsoluteForm, InvalidAbsoluteForm, InvalidOriginForm, OriginForm, RequestBody,
        RequestBodyErrorKind, RequestHeader,
    };

    struct TestBody {
        frames: VecDeque<Result<Frame<Bytes>, io::Error>>,
        hint: SizeHint,
    }

    impl Body for TestBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.frames.pop_front())
        }

        fn size_hint(&self) -> SizeHint {
            self.hint
        }
    }

    #[test]
    fn accepts_only_http_absolute_form_targets() -> Result<(), InvalidAbsoluteForm> {
        let target = AbsoluteForm::parse("http://example.test/path?query=yes")?;
        assert_eq!(
            target.uri,
            "http://example.test/path?query=yes"
                .parse::<http::Uri>()
                .map_err(|_| InvalidAbsoluteForm)?
        );
        let root = AbsoluteForm::parse("http://example.test")?;
        assert_eq!(root.uri.path(), "/");

        for value in [
            "/path",
            "example.test/path",
            "ftp://example.test/path",
            "http:///path",
            "http://user@example.test/path",
            "http://example.test/path#fragment",
        ] {
            assert!(AbsoluteForm::parse(value).is_err(), "accepted {value:?}");
        }
        Ok(())
    }

    #[test]
    fn accepts_only_origin_form_targets() -> Result<(), InvalidOriginForm> {
        let target = OriginForm::parse("/path?query=yes")?;
        assert_eq!(target.0.as_str(), "/path?query=yes");

        for value in ["", "*", "example.test/path", "https://example.test/path"] {
            assert!(OriginForm::parse(value).is_err(), "accepted {value:?}");
        }
        Ok(())
    }

    #[test]
    fn invalid_origin_form_error_is_specific_and_stable() -> Result<(), &'static str> {
        let error = match OriginForm::parse("https://example.test/path") {
            Ok(_) => return Err("absolute-form target was accepted"),
            Err(error) => error,
        };

        assert_eq!(error, InvalidOriginForm);
        assert_eq!(
            error.to_string(),
            "request target must be HTTP origin-form beginning with `/` and contain no authority or fragment"
        );
        Ok(())
    }

    #[test]
    fn sensitive_header_debug_output_redacts_the_value() {
        let header = RequestHeader::new("cookie", "secret=value").sensitive();
        let debug = format!("{header:?}");

        assert!(header.is_sensitive());
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret=value"));
    }

    #[tokio::test]
    async fn request_body_enforces_exact_length_and_rejects_trailers() {
        let body = TestBody {
            frames: VecDeque::from([Ok(Frame::data(Bytes::from_static(b"short")))]),
            hint: SizeHint::with_exact(8),
        };
        let mut body = RequestBody::streaming(body);
        assert_eq!(body.metadata().exact_length(), Some(8));
        assert!(body.frame().await.transpose().is_ok());
        let Err(error) = body.frame().await.transpose() else {
            panic!("short exact body must fail at end of stream");
        };
        assert_eq!(error.kind(), RequestBodyErrorKind::LengthMismatch);

        let body = TestBody {
            frames: VecDeque::from([Ok(Frame::trailers(HeaderMap::new()))]),
            hint: SizeHint::default(),
        };
        let Err(error) = RequestBody::streaming(body).frame().await.transpose() else {
            panic!("request trailers must fail explicitly");
        };
        assert_eq!(error.kind(), RequestBodyErrorKind::TrailersUnsupported);
    }
}
