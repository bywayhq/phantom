use std::{error::Error as StdError, fmt};

use bytes::Bytes;

const MAX_MULTIPART_PARTS: usize = 1024;
const MAX_METADATA_BYTES: usize = 4096;

/// Prepare replayable request bytes and their exact content type.
///
/// Every constructor requires an encoded byte limit. The limit includes
/// multipart headers and delimiters. Preparation never inserts request
/// headers, reads files, or draws a multipart boundary.
///
/// Pass this value to a request's prepared-body adapter. You must declare a
/// `Content-Type` caller slot or place a matching header yourself.
///
/// Formatting reports only the byte count. Accessors expose the body and
/// content type when you need them.
///
/// # Examples
///
/// ```
/// use phantom::PreparedRequestBody;
///
/// # fn example() -> Result<(), phantom::PreparedBodyError> {
/// let body = PreparedRequestBody::form([("tag", "first"), ("tag", "last")], 1024)?;
/// assert_eq!(body.bytes().as_ref(), b"tag=first&tag=last");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedRequestBody {
    bytes: Bytes,
    content_type: Box<str>,
}

impl PreparedRequestBody {
    /// Encodes ordered UTF-8 name-value pairs, including duplicate names.
    ///
    /// Spaces become `+`; a literal `+` becomes `%2B`. Empty names and values
    /// are retained. The content type is exactly
    /// `application/x-www-form-urlencoded;charset=UTF-8`.
    ///
    /// This follows the WHATWG URL tuple serializer used by Fetch for
    /// `URLSearchParams`. It preserves input newlines. HTML form submission
    /// has separate newline preprocessing, which this constructor does not do.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedBodyError`] if the encoded output exceeds
    /// `maximum_bytes` or its buffer cannot be allocated.
    pub fn form<I, K, V>(pairs: I, maximum_bytes: usize) -> Result<Self, PreparedBodyError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut output = BodyBuffer::new(maximum_bytes);
        let mut first = true;
        // WHATWG URL, application/x-www-form-urlencoded serializer:
        // https://url.spec.whatwg.org/#urlencoded-serializing
        for (name, value) in pairs {
            if !first {
                output.append(b"&")?;
            }
            first = false;
            for chunk in url::form_urlencoded::byte_serialize(name.as_ref().as_bytes()) {
                output.append(chunk.as_bytes())?;
            }
            output.append(b"=")?;
            for chunk in url::form_urlencoded::byte_serialize(value.as_ref().as_bytes()) {
                output.append(chunk.as_bytes())?;
            }
        }
        Ok(Self {
            bytes: output.bytes.into(),
            content_type: "application/x-www-form-urlencoded;charset=UTF-8".into(),
        })
    }

    /// Encodes a JSON value directly into a bounded output buffer.
    ///
    /// The content type is exactly `application/json`. This is serde's JSON
    /// encoding, with no claim about a browser's JSON request bytes.
    /// The output limit does not bound allocations inside your serializer.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedBodyError`] for an output limit, allocation failure,
    /// or serializer failure. [`StdError::source`] preserves the original
    /// `serde_json::Error` for a serializer failure. Its message may include
    /// text supplied by your custom serializer.
    #[cfg(feature = "json")]
    pub fn json<T: serde::Serialize + ?Sized>(
        value: &T,
        maximum_bytes: usize,
    ) -> Result<Self, PreparedBodyError> {
        let mut output = BodyBuffer::new(maximum_bytes);
        let result = serde_json::to_writer(&mut output, value);
        if let Some(kind) = output.failure {
            return Err(PreparedBodyError::new(kind));
        }
        result.map_err(|source| PreparedBodyError {
            kind: PreparedBodyErrorKind::Json,
            json: Some(source),
        })?;
        Ok(Self {
            bytes: output.bytes.into(),
            content_type: "application/json".into(),
        })
    }

    /// Encodes multipart parts in their supplied order.
    ///
    /// Duplicate names remain separate parts. Supply a boundary of 1 to 70
    /// ASCII letters, digits, or `'()+_,-./:=?`. Spaces are rejected. Token
    /// boundaries are unquoted in the content type; other accepted boundaries
    /// are quoted. No random boundary or extra header is generated.
    ///
    /// This follows the HTML UTF-8 multipart rules for text normalization and
    /// parameter escaping, and RFC 7578 for framing. Text fields have no part
    /// content type by default. Byte fields use `application/octet-stream`.
    ///
    /// At most 1024 parts are accepted. Names, filenames and part content
    /// types each allow at most 4 KiB. To avoid ambiguous delimiters, any
    /// occurrence of `--` followed by the boundary in a payload is rejected,
    /// including occurrences away from a line boundary. Choose another
    /// boundary yourself when this conservative check rejects your data.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedBodyError`] for an invalid boundary, a collision,
    /// too many parts, an encoded output limit, or allocation failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use phantom::{MultipartPart, PreparedRequestBody};
    ///
    /// # fn example() -> Result<(), phantom::PreparedBodyError> {
    /// let parts = [
    ///     MultipartPart::text("label", "upload")?,
    ///     MultipartPart::bytes("file", b"file bytes")?.with_filename("upload.bin")?,
    /// ];
    /// let body = PreparedRequestBody::multipart("caller-boundary", parts, 1024)?;
    /// # drop(body);
    /// # Ok(())
    /// # }
    /// ```
    pub fn multipart<'a, I>(
        boundary: &str,
        parts: I,
        maximum_bytes: usize,
    ) -> Result<Self, PreparedBodyError>
    where
        I: IntoIterator<Item = MultipartPart<'a>>,
    {
        if boundary.is_empty() || boundary.len() > 70 || !boundary.bytes().all(is_boundary_byte) {
            return Err(PreparedBodyError::new(
                PreparedBodyErrorKind::InvalidBoundary,
            ));
        }
        let delimiter = format!("--{boundary}");
        let mut output = BodyBuffer::new(maximum_bytes);
        for (index, part) in parts.into_iter().enumerate() {
            if index == MAX_MULTIPART_PARTS {
                return Err(PreparedBodyError::new(PreparedBodyErrorKind::TooManyParts));
            }
            if part.data.len() > maximum_bytes.saturating_sub(output.bytes.len()) {
                return Err(PreparedBodyError::new(PreparedBodyErrorKind::TooLarge));
            }
            if part
                .data
                .windows(delimiter.len())
                .any(|window| window == delimiter.as_bytes())
            {
                return Err(PreparedBodyError::new(
                    PreparedBodyErrorKind::BoundaryCollision,
                ));
            }
            // RFC 7578 sections 4.1-4.4 and 5.2:
            // https://www.rfc-editor.org/rfc/rfc7578.html#section-4.1
            output.append(delimiter.as_bytes())?;
            output.append(b"\r\nContent-Disposition: form-data; name=\"")?;
            write_parameter(&mut output, part.name.as_bytes(), true)?;
            output.append(b"\"")?;
            if let Some(filename) = part.filename {
                output.append(b"; filename=\"")?;
                write_parameter(&mut output, filename.as_bytes(), false)?;
                output.append(b"\"")?;
            }
            if let Some(content_type) = part.content_type {
                output.append(b"\r\nContent-Type: ")?;
                output.append(content_type.as_bytes())?;
            }
            output.append(b"\r\n\r\n")?;
            if part.normalize_text {
                write_text(&mut output, part.data)?;
            } else {
                output.append(part.data)?;
            }
            output.append(b"\r\n")?;
        }
        output.append(delimiter.as_bytes())?;
        output.append(b"--\r\n")?;
        let content_type = if boundary.bytes().all(is_token_byte) {
            format!("multipart/form-data; boundary={boundary}")
        } else {
            format!("multipart/form-data; boundary=\"{boundary}\"")
        };
        Ok(Self {
            bytes: output.bytes.into(),
            content_type: content_type.into(),
        })
    }

    /// Returns the replayable encoded bytes.
    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Returns the exact content-type field value.
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Returns the encoded bytes and exact content type without re-encoding.
    #[must_use]
    pub fn into_parts(self) -> (Bytes, Box<str>) {
        (self.bytes, self.content_type)
    }
}

impl fmt::Debug for PreparedRequestBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRequestBody")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// One borrowed multipart field, checked before body assembly.
///
/// Constructors retain your data without copying it. Text values normalize
/// line endings to CRLF during encoding. Byte values remain unchanged.
/// Names and filenames use UTF-8 with quotes and line breaks escaped.
/// Other control characters are rejected. Empty names and filenames are valid.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MultipartPart<'a> {
    name: &'a str,
    data: &'a [u8],
    filename: Option<&'a str>,
    content_type: Option<&'a str>,
    normalize_text: bool,
}

impl<'a> MultipartPart<'a> {
    /// Creates a UTF-8 text field with no part content-type header.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedBodyError`] if the name exceeds 4 KiB or contains
    /// a control character other than CR or LF.
    pub fn text(name: &'a str, value: &'a str) -> Result<Self, PreparedBodyError> {
        validate_parameter(name, PreparedBodyErrorKind::InvalidName)?;
        Ok(Self {
            name,
            data: value.as_bytes(),
            filename: None,
            content_type: None,
            normalize_text: true,
        })
    }

    /// Creates a byte-exact field with content type `application/octet-stream`.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedBodyError`] under the same name rules as [`Self::text`].
    pub fn bytes(name: &'a str, value: &'a [u8]) -> Result<Self, PreparedBodyError> {
        validate_parameter(name, PreparedBodyErrorKind::InvalidName)?;
        Ok(Self {
            name,
            data: value,
            filename: None,
            content_type: Some("application/octet-stream"),
            normalize_text: false,
        })
    }

    /// Adds an explicit filename without changing the field's data encoding.
    ///
    /// Use [`Self::bytes`] for file contents that must remain byte-exact.
    /// This method reads no file and removes no path components.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedBodyError`] if the filename exceeds 4 KiB or contains
    /// a control character other than CR or LF.
    pub fn with_filename(mut self, filename: &'a str) -> Result<Self, PreparedBodyError> {
        validate_parameter(filename, PreparedBodyErrorKind::InvalidFilename)?;
        self.filename = Some(filename);
        Ok(self)
    }

    /// Sets an explicit part content type without adding another part header.
    ///
    /// The value must be an ASCII `token/token` media type. Parameters and
    /// whitespace are rejected. Spelling is preserved exactly.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedBodyError`] for invalid syntax or a value over 4 KiB.
    pub fn with_content_type(mut self, content_type: &'a str) -> Result<Self, PreparedBodyError> {
        if content_type.len() > MAX_METADATA_BYTES {
            return Err(PreparedBodyError::new(PreparedBodyErrorKind::TooLarge));
        }
        let valid = content_type.split_once('/').is_some_and(|(kind, subtype)| {
            !kind.is_empty()
                && !subtype.is_empty()
                && kind.bytes().all(is_token_byte)
                && subtype.bytes().all(is_token_byte)
        });
        if !valid {
            return Err(PreparedBodyError::new(
                PreparedBodyErrorKind::InvalidContentType,
            ));
        }
        self.content_type = Some(content_type);
        Ok(self)
    }
}

impl fmt::Debug for MultipartPart<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultipartPart")
            .field("bytes", &self.data.len())
            .field("has_filename", &self.filename.is_some())
            .field("has_content_type", &self.content_type.is_some())
            .field("normalizes_text", &self.normalize_text)
            .finish_non_exhaustive()
    }
}

/// Stable category of prepared request-body failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreparedBodyErrorKind {
    /// Encoded bytes or multipart metadata exceed their limit.
    TooLarge,
    /// The bounded output buffer could not be allocated.
    Allocation,
    /// A multipart name contains an unsupported control character.
    InvalidName,
    /// A multipart filename contains an unsupported control character.
    InvalidFilename,
    /// A part content type is not an accepted media type.
    InvalidContentType,
    /// A boundary has invalid length or characters.
    InvalidBoundary,
    /// A payload contains the selected boundary delimiter.
    BoundaryCollision,
    /// The multipart body contains more than 1024 parts.
    TooManyParts,
    /// A JSON serializer failed.
    #[cfg(feature = "json")]
    Json,
}

/// Preparation failure that omits body data from its displayed diagnostics.
///
/// Formatting reports only [`Self::kind`]. For JSON serializer failures,
/// [`StdError::source`] returns the original `serde_json::Error`. Inspecting
/// that source may expose messages supplied by your serializer.
pub struct PreparedBodyError {
    kind: PreparedBodyErrorKind,
    #[cfg(feature = "json")]
    json: Option<serde_json::Error>,
}

impl PreparedBodyError {
    fn new(kind: PreparedBodyErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "json")]
            json: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> PreparedBodyErrorKind {
        self.kind
    }
}

impl fmt::Debug for PreparedBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBodyError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for PreparedBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "request body preparation failed ({:?})",
            self.kind
        )
    }
}

impl StdError for PreparedBodyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        #[cfg(feature = "json")]
        if let Some(source) = &self.json {
            return Some(source);
        }
        None
    }
}

struct BodyBuffer {
    bytes: Vec<u8>,
    maximum: usize,
    #[cfg(feature = "json")]
    failure: Option<PreparedBodyErrorKind>,
}

impl BodyBuffer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            #[cfg(feature = "json")]
            failure: None,
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), PreparedBodyError> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn reserve(&mut self, additional: usize) -> Result<(), PreparedBodyError> {
        let length = self
            .bytes
            .len()
            .checked_add(additional)
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| PreparedBodyError::new(PreparedBodyErrorKind::TooLarge))?;
        if length > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .max(64)
                .saturating_mul(2)
                .max(length)
                .min(self.maximum);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| PreparedBodyError::new(PreparedBodyErrorKind::Allocation))?;
        }
        Ok(())
    }
}

#[cfg(feature = "json")]
impl std::io::Write for BodyBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.failure.is_some() {
            return Err(std::io::Error::other("prepared body output failed"));
        }
        match self.append(bytes) {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.failure = Some(error.kind());
                Err(std::io::Error::other("prepared body output failed"))
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_parameter(value: &str, kind: PreparedBodyErrorKind) -> Result<(), PreparedBodyError> {
    if value.len() > MAX_METADATA_BYTES {
        return Err(PreparedBodyError::new(PreparedBodyErrorKind::TooLarge));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\r' | '\n'))
    {
        return Err(PreparedBodyError::new(kind));
    }
    Ok(())
}

fn is_boundary_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"'()+_,-./:=?".contains(&byte)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

// HTML multipart encoding normalizes text names and values, then escapes
// only CR, LF and quote in names and filenames. Backslashes are unchanged.
// https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart/form-data-encoding-algorithm
fn write_parameter(
    output: &mut BodyBuffer,
    value: &[u8],
    normalize_newlines: bool,
) -> Result<(), PreparedBodyError> {
    let mut start = 0;
    let mut position = 0;
    while position < value.len() {
        let byte = value[position];
        if !matches!(byte, b'\r' | b'\n' | b'"') {
            position += 1;
            continue;
        }
        output.append(&value[start..position])?;
        if normalize_newlines && matches!(byte, b'\r' | b'\n') {
            output.append(b"%0D%0A")?;
            position += if byte == b'\r' && value.get(position + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
        } else {
            output.append(match byte {
                b'\r' => b"%0D",
                b'\n' => b"%0A",
                _ => b"%22",
            })?;
            position += 1;
        }
        start = position;
    }
    output.append(&value[start..])
}

fn write_text(output: &mut BodyBuffer, value: &[u8]) -> Result<(), PreparedBodyError> {
    let mut start = 0;
    let mut position = 0;
    while position < value.len() {
        let byte = value[position];
        if !matches!(byte, b'\r' | b'\n') {
            position += 1;
            continue;
        }
        output.append(&value[start..position])?;
        output.append(b"\r\n")?;
        position += if byte == b'\r' && value.get(position + 1) == Some(&b'\n') {
            2
        } else {
            1
        };
        start = position;
    }
    output.append(&value[start..])
}

#[cfg(test)]
mod tests;
