//! Strict, bounded decoding using Encoding Standard labels and Unicode BOMs.

use encoding_rs::{DecoderResult, Encoding, UTF_8};
use http::{HeaderMap, Response, header, response::Parts};

use super::{ResponseReadCause, ResponseReadError, ResponseReadErrorKind, response_bytes};
use crate::ResponseBody;

mod content_type;

/// Reads bounded text using the response's charset or UTF-8 by default.
///
/// Enable the `charset` feature. `maximum_bytes` limits collected input bytes
/// after any enabled content decoding. `maximum_utf8_bytes` separately limits
/// the returned string's UTF-8 bytes. Conversion uses a fixed scratch buffer
/// and checks this limit before growing the output. Both limits accept zero.
/// Status, headers, version and extensions are retained on success and failure.
/// Headers remain the received metadata, including Content-Type and length.
///
/// Content-Type is validated before reading the body. A missing field or
/// charset selects UTF-8. One declared charset is matched using Encoding
/// Standard labels, including aliases such as ISO-8859-1 for Windows-1252.
/// A UTF-8, UTF-16LE or UTF-16BE byte-order mark then overrides that valid
/// selection and is removed. Invalid headers and unsupported labels fail even
/// when a BOM is present. No HTML declarations or other content are inspected.
/// Malformed byte sequences fail without replacement characters.
///
/// Uses [`response_bytes`] for input collection and body cleanup. Completed
/// trailers remain in the response extensions; partial data is discarded.
/// Dropping the future drops its owned body.
/// This helper does not check the HTTP status or enable content decoding.
///
/// ```no_run
/// # #[cfg(feature = "charset")]
/// # async fn example(response: phantom::Response<phantom::ResponseBody>) -> Result<(), Box<dyn std::error::Error>> {
/// let response = phantom::response_text_with_charset(response, 1 << 20, 3 << 20).await?;
/// println!("{}", response.body());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`ResponseReadErrorKind::InvalidContentType`] for a malformed field,
/// multiple Content-Type fields, or repeated charset parameters, even when
/// their values agree. Unknown and replacement-encoding labels return
/// [`ResponseReadErrorKind::UnsupportedCharset`]. Invalid byte sequences return
/// [`ResponseReadErrorKind::MalformedText`]. Output exceeding its byte cap or
/// failing a bounded allocation returns [`ResponseReadErrorKind::TextLimit`].
/// Input failures retain the original body error as [`ResponseReadErrorKind::Body`].
pub async fn response_text_with_charset(
    response: Response<ResponseBody>,
    maximum_bytes: usize,
    maximum_utf8_bytes: usize,
) -> Result<Response<String>, ResponseReadError> {
    let encoding = match declared_encoding(response.headers()) {
        Ok(encoding) => encoding,
        Err(error) => {
            let (mut parts, body) = response.into_parts();
            parts.extensions.insert(body.into_trailers());
            return Err(read_error(parts, error));
        }
    };
    let (parts, bytes) = response_bytes(response, maximum_bytes).await?.into_parts();
    match decode(&bytes, encoding, maximum_utf8_bytes) {
        Ok(text) => Ok(Response::from_parts(parts, text)),
        Err(error) => Err(read_error(parts, error)),
    }
}

fn read_error(parts: Parts, error: TextError) -> ResponseReadError {
    ResponseReadError {
        response: Box::new(Response::from_parts(parts, ())),
        cause: ResponseReadCause::Charset(error),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum TextError {
    InvalidContentType,
    UnsupportedCharset,
    Malformed,
    Limit,
}

impl TextError {
    pub(super) const fn kind(&self) -> ResponseReadErrorKind {
        match self {
            Self::InvalidContentType => ResponseReadErrorKind::InvalidContentType,
            Self::UnsupportedCharset => ResponseReadErrorKind::UnsupportedCharset,
            Self::Malformed => ResponseReadErrorKind::MalformedText,
            Self::Limit => ResponseReadErrorKind::TextLimit,
        }
    }
}

fn declared_encoding(headers: &HeaderMap) -> Result<&'static Encoding, TextError> {
    let mut fields = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(field) = fields.next() else {
        return Ok(UTF_8);
    };
    if fields.next().is_some() {
        return Err(TextError::InvalidContentType);
    }
    match content_type::charset(field.as_bytes())? {
        Some(label) => {
            Encoding::for_label_no_replacement(&label).ok_or(TextError::UnsupportedCharset)
        }
        None => Ok(UTF_8),
    }
}

fn decode(
    bytes: &[u8],
    declared: &'static Encoding,
    maximum_utf8_bytes: usize,
) -> Result<String, TextError> {
    // Encoding Standard §6.1: a Unicode BOM overrides the fallback encoding.
    // https://encoding.spec.whatwg.org/#decode
    let (encoding, skip) = Encoding::for_bom(bytes).unwrap_or((declared, 0));
    let mut input = &bytes[skip..];
    let mut decoder = encoding.new_decoder_without_bom_handling();
    let mut output = String::new();
    // At least four bytes are required for progress with every UTF-8 scalar.
    let mut scratch = [0_u8; 4096];
    loop {
        let (result, read, written) =
            decoder.decode_to_utf8_without_replacement(input, &mut scratch, true);
        if matches!(result, DecoderResult::Malformed(..)) {
            return Err(TextError::Malformed);
        }
        let required = output.len().checked_add(written).ok_or(TextError::Limit)?;
        if required > maximum_utf8_bytes {
            return Err(TextError::Limit);
        }
        let text = std::str::from_utf8(&scratch[..written]).map_err(|_| TextError::Malformed)?;
        if output.capacity().saturating_sub(output.len()) < written {
            // Amortize copying while clipping every requested allocation to
            // the output bound, even when doubling capacity would overflow.
            let target = required
                .max(output.capacity().saturating_mul(2))
                .min(maximum_utf8_bytes);
            output
                .try_reserve_exact(target - output.len())
                .map_err(|_| TextError::Limit)?;
        }
        output.push_str(text);
        input = &input[read..];
        if matches!(result, DecoderResult::InputEmpty) {
            return Ok(output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn header(value: &str) -> Result<HeaderMap, http::header::InvalidHeaderValue> {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, value.parse()?);
        Ok(headers)
    }

    #[test]
    fn content_type_parameters_are_parsed_without_splitting_quoted_values() -> TestResult {
        for value in [
            "Text/Plain; CHARSET=ISO-8859-1",
            "text/plain; note=\"a;b=c\"; charset=\"windows-1252\"",
            "text/plain; charset=\" UTF-8 \"",
            r#"text/plain; note="a\";charset=shift_jis"; charset="UTF\-8""#,
        ] {
            let encoding = declared_encoding(&header(value)?);
            let expected = if value.contains("UTF-8") || value.contains(r"UTF\-8") {
                UTF_8
            } else {
                encoding_rs::WINDOWS_1252
            };
            assert_eq!(encoding, Ok(expected));
        }
        assert_eq!(declared_encoding(&HeaderMap::new()), Ok(UTF_8));
        assert_eq!(
            declared_encoding(&header("text/plain; note=\"charset=shift_jis\"")?),
            Ok(UTF_8)
        );
        Ok(())
    }

    #[test]
    fn malformed_and_duplicate_content_type_fields_are_rejected() -> TestResult {
        for value in [
            "text",
            "text/",
            "text/plain; charset",
            "text/plain; charset=\"utf-8",
            "text/plain; charset=",
            "text/plain; note=; charset=utf-8",
            "text/plain; charset=utf-8, text/html",
            "text/plain; charset=utf-8; charset=UTF-8",
            "text/plain; charset=latin1; charset=windows-1252",
            "text/plain; charset=unknown-secret; charset=utf-8",
            "text/plain; charset=unknown-secret; note=",
        ] {
            assert!(
                matches!(
                    declared_encoding(&header(value)?),
                    Err(TextError::InvalidContentType)
                ),
                "{value}"
            );
        }
        let mut headers = header("text/plain; charset=utf-8")?;
        headers.append(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse()?);
        assert!(matches!(
            declared_encoding(&headers),
            Err(TextError::InvalidContentType)
        ));
        Ok(())
    }

    #[test]
    fn unknown_and_replacement_encoding_labels_are_rejected() -> TestResult {
        for label in [
            "phantom-secret",
            "replacement",
            "iso-2022-cn",
            "hz-gb-2312",
            "",
        ] {
            let headers = header(&format!("text/plain; charset=\"{label}\""))?;
            assert!(matches!(
                declared_encoding(&headers),
                Err(TextError::UnsupportedCharset)
            ));
        }
        Ok(())
    }

    #[test]
    fn bom_overrides_valid_declared_encoding_and_is_removed_only_once() {
        for (input, expected) in [
            (b"\xef\xbb\xbfcaf\xc3\xa9".as_slice(), "caf\u{e9}"),
            (b"\xff\xfeA\0=\xd8\x00\xde", "A\u{1f600}"),
            (b"\xfe\xff\0A\xd8=\xde\x00", "A\u{1f600}"),
            (b"\xef\xbb\xbf\xef\xbb\xbf", "\u{feff}"),
        ] {
            assert_eq!(
                decode(input, encoding_rs::WINDOWS_1252, 64),
                Ok(expected.to_owned())
            );
        }
        for bom in [b"\xef\xbb\xbf".as_slice(), b"\xff\xfe", b"\xfe\xff", b""] {
            assert_eq!(decode(bom, UTF_8, 0), Ok(String::new()));
        }
    }

    #[test]
    fn malformed_sequences_are_fatal_including_final_incomplete_characters() {
        for (input, encoding) in [
            (b"\xff".as_slice(), UTF_8),
            (b"\xc3", UTF_8),
            (b"\xff\xfeA", UTF_8),
            (b"\x00\xd8", encoding_rs::UTF_16LE),
            (b"\x82", encoding_rs::SHIFT_JIS),
        ] {
            assert!(matches!(
                decode(input, encoding, 64),
                Err(TextError::Malformed)
            ));
        }
    }

    #[test]
    fn utf8_output_limit_counts_expansion_and_accepts_exact_boundaries() {
        let input = [0x80; 5000];
        let expected = "\u{20ac}".repeat(input.len());
        assert_eq!(
            decode(&input, encoding_rs::WINDOWS_1252, expected.len()),
            Ok(expected.clone())
        );
        assert!(matches!(
            decode(&input, encoding_rs::WINDOWS_1252, expected.len() - 1),
            Err(TextError::Limit)
        ));
        assert!(matches!(decode(b"x", UTF_8, 0), Err(TextError::Limit)));
        assert_eq!(decode(b"x", UTF_8, usize::MAX), Ok("x".into()));
    }
}
