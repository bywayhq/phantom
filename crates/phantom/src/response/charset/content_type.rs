//! HTTP Content-Type syntax and its sole unescaped charset parameter.

use std::borrow::Cow;

use super::TextError;

// RFC9110 §§5.6.2, 5.6.4, 5.6.6 and 8.3.1. Validate the complete field
// before resolving a label. Unrelated parameters never allocate storage.
pub(super) fn charset(bytes: &[u8]) -> Result<Option<Cow<'_, [u8]>>, TextError> {
    let mut parser = Parser { bytes, offset: 0 };
    parser.whitespace();
    parser.token()?;
    parser.expect(b'/')?;
    parser.token()?;
    let mut charset: Option<Value<'_>> = None;
    loop {
        parser.whitespace();
        if parser.peek().is_none() {
            break;
        }
        parser.expect(b';')?;
        parser.whitespace();
        // The parameter production explicitly permits empty semicolon slots.
        if matches!(parser.peek(), None | Some(b';')) {
            continue;
        }
        let name = parser.token()?;
        parser.expect(b'=')?;
        let value = if parser.peek() == Some(b'"') {
            parser.quoted()?
        } else {
            Value {
                bytes: parser.token()?,
                escaped: false,
            }
        };
        if name.eq_ignore_ascii_case(b"charset") {
            if charset.is_some() {
                return Err(TextError::InvalidContentType);
            }
            charset = Some(value);
        }
    }
    charset.map(Value::unescape).transpose()
}

struct Value<'a> {
    bytes: &'a [u8],
    escaped: bool,
}

impl<'a> Value<'a> {
    fn unescape(self) -> Result<Cow<'a, [u8]>, TextError> {
        if !self.escaped {
            return Ok(Cow::Borrowed(self.bytes));
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(self.bytes.len())
            .map_err(|_| TextError::Limit)?;
        let mut bytes = self.bytes.iter();
        while let Some(&byte) = bytes.next() {
            if byte == b'\\' {
                // quoted() already validated that every escape has a byte.
                let escaped = bytes.next().ok_or(TextError::InvalidContentType)?;
                output.push(*escaped);
            } else {
                output.push(byte);
            }
        }
        Ok(Cow::Owned(output))
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.offset += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), TextError> {
        if self.peek() != Some(byte) {
            return Err(TextError::InvalidContentType);
        }
        self.offset += 1;
        Ok(())
    }

    fn token(&mut self) -> Result<&'a [u8], TextError> {
        let start = self.offset;
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            self.offset += 1;
        }
        if self.offset == start {
            return Err(TextError::InvalidContentType);
        }
        Ok(&self.bytes[start..self.offset])
    }

    fn quoted(&mut self) -> Result<Value<'a>, TextError> {
        self.expect(b'"')?;
        let start = self.offset;
        let mut escaped = false;
        loop {
            match self.peek() {
                Some(b'"') => {
                    let bytes = &self.bytes[start..self.offset];
                    self.offset += 1;
                    return Ok(Value { bytes, escaped });
                }
                Some(b'\\') => {
                    escaped = true;
                    self.offset += 1;
                    match self.peek() {
                        Some(b'\t' | b' '..=b'~' | 0x80..=0xff) => self.offset += 1,
                        _ => return Err(TextError::InvalidContentType),
                    }
                }
                Some(b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff) => {
                    self.offset += 1;
                }
                _ => return Err(TextError::InvalidContentType),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_tokens_empty_parameter_slots_and_quoted_pairs_are_accepted() {
        for header in [
            b"~text/x|custom; ~note=|value; charset=UTF-8".as_slice(),
            b"text/plain; ;\t; charset=utf-8; ;\t",
            b"\ttext/plain\t; note=\"\\\";charset=bogus\"; charset=\"utf\\-8\"\t",
            b"text/plain; note=\"\xff\\\xfe\"; charset=utf-8",
        ] {
            let label = charset(header);
            assert!(
                matches!(label.as_ref(), Ok(Some(value)) if value.eq_ignore_ascii_case(b"utf-8"))
            );
        }
        assert!(matches!(
            charset(b"text/plain; note=\"a\\b\"; charset=\"utf-8\""),
            Ok(Some(Cow::Borrowed(b"utf-8")))
        ));
        assert_eq!(charset(b"text/plain;;;"), Ok(None));
        let long_tokens = format!(
            "{}/plain; {}=x; charset=utf-8",
            "x".repeat(128),
            "n".repeat(128)
        );
        assert_eq!(
            charset(long_tokens.as_bytes()),
            Ok(Some(Cow::Borrowed(b"utf-8".as_slice())))
        );
        assert_eq!(
            charset(b"text/plain; charset=\"\""),
            Ok(Some(Cow::Borrowed(b"".as_slice())))
        );
    }

    #[test]
    fn the_whole_field_is_validated_and_controls_never_hide_behind_escapes() {
        for header in [
            b"/plain".as_slice(),
            b"text/",
            b"text /plain",
            b"text/plain; charset =utf-8",
            b"text/plain; charset= utf-8",
            b"text/plain; charset=",
            b"text/plain; charset=utf-8; note=",
            b"text/plain; charset=utf-8; note=\"unterminated",
            b"text/plain; note=\"dangling\\",
            b"text/plain; note=\"\x7f\"",
            b"text/plain; note=\"\\\x7f\"",
            b"text/plain; note=\"\\\r\"",
            b"text/plain, text/html",
            b"text/plain; charset=unknown; CHARSET=utf-8",
        ] {
            assert_eq!(
                charset(header),
                Err(TextError::InvalidContentType),
                "{header:?}"
            );
        }
    }
}
