//! Reads one run of a retained `phantom-http2-websocket-v1` browser capture.

use std::collections::BTreeMap;

use super::TestResult;

/// One HPACK field representation as the capture tool classifies it.
///
/// The two Huffman flags are `None` where the representation carries no such
/// string: an indexed field has neither, and a field named by an index has no
/// literal name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Representation {
    /// `indexed`, `incremental`, or `without-indexing`.
    pub(crate) kind: String,
    /// Static or dynamic table index; 0 for a literal name.
    pub(crate) index: usize,
    /// Whether a literal field name is Huffman-coded.
    pub(crate) name_huffman: Option<bool>,
    /// Whether the field value is Huffman-coded.
    pub(crate) value_huffman: Option<bool>,
}

/// A captured client extended CONNECT HEADERS frame.
pub(crate) struct CapturedConnect {
    pub(crate) priority: (bool, u32, u16),
    pub(crate) pseudo: Vec<(String, String, Representation)>,
    pub(crate) fields: Vec<(String, String)>,
}

/// A captured HTTP/1.1 WebSocket opening request.
pub(crate) struct CapturedUpgrade {
    pub(crate) request_line: String,
    pub(crate) fields: Vec<(String, String)>,
}

pub(crate) struct Capture {
    fields: BTreeMap<String, String>,
}

impl Capture {
    pub(crate) fn parse(input: &str) -> TestResult<Self> {
        let mut fields = BTreeMap::new();
        for line in input.lines() {
            let (key, value) = line.split_once('=').ok_or("capture line is missing `=`")?;
            if fields.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(format!("capture repeats {key}").into());
            }
        }
        let capture = Self { fields };
        // `fixtures/proxy/` records H1 requests in the same shape.
        if !matches!(
            capture.value("format")?,
            "phantom-http2-websocket-v1" | "phantom-proxy-route-v1"
        ) {
            return Err("unexpected capture format".into());
        }
        Ok(capture)
    }

    pub(crate) fn value(&self, key: &str) -> TestResult<&str> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("capture omitted {key}").into())
    }

    fn record_count(&self, key: &str) -> TestResult<usize> {
        let count = self.value(key)?.parse()?;
        // Each counted record needs at least one field in the retained input.
        if count > self.fields.len() {
            return Err(format!("capture count {key} exceeds its field count").into());
        }
        Ok(count)
    }

    /// Returns the ALPN offer of the connection that carried the WebSocket.
    pub(crate) fn websocket_alpn_offer(&self) -> TestResult<&str> {
        let connection = match self.first_connect()? {
            Some((connection, _)) => connection,
            None => {
                self.first_request("websocket")?
                    .ok_or("capture has no WebSocket")?
                    .0
            }
        };
        attribute(
            self.value(&format!("run_0_connection_{connection}"))?,
            "alpn_offer",
        )
    }

    /// Returns the first extended CONNECT of run 0.
    pub(crate) fn connect(&self) -> TestResult<CapturedConnect> {
        let (_, key) = self
            .first_connect()?
            .ok_or("capture has no extended CONNECT")?;
        let record = self.value(&key)?;
        let mut pseudo = Vec::new();
        let mut fields = Vec::new();
        for (name, value, representation) in self.block(&key)? {
            if name.starts_with(':') {
                pseudo.push((name, value, representation));
            } else {
                fields.push((name, value));
            }
        }
        Ok(CapturedConnect {
            priority: (
                attribute(record, "priority:exclusive")? == "true",
                attribute(record, "depends_on")?.parse()?,
                attribute(record, "weight")?.parse()?,
            ),
            pseudo,
            fields,
        })
    }

    /// Returns the first HTTP/1.1 WebSocket opening of run 0.
    pub(crate) fn upgrade(&self) -> TestResult<CapturedUpgrade> {
        let (_, prefix) = self
            .first_request("websocket")?
            .ok_or("capture has no H1 WebSocket")?;
        self.h1_request(&prefix)
    }

    /// Returns the first H1 CONNECT a `proxy_route.py` capture recorded for
    /// the page's own origin.
    pub(crate) fn tunnel_connect(&self) -> TestResult<CapturedUpgrade> {
        let (_, prefix) = self
            .first_request("connect")?
            .ok_or("capture has no page CONNECT")?;
        self.h1_request(&prefix)
    }

    fn h1_request(&self, prefix: &str) -> TestResult<CapturedUpgrade> {
        let request_line = decode_hex(self.value(&format!("{prefix}_line_hex"))?)?;
        let mut fields = Vec::new();
        for index in 0..self.record_count(&format!("{prefix}_header_count"))? {
            let line = decode_hex(self.value(&format!("{prefix}_header_{index}"))?)?;
            let (name, value) = line.split_once(": ").ok_or("H1 field has no `: `")?;
            fields.push((name.to_owned(), value.to_owned()));
        }
        Ok(CapturedUpgrade {
            request_line,
            fields,
        })
    }

    fn first_connect(&self) -> TestResult<Option<(usize, String)>> {
        let connections = self.record_count("run_0_connection_count")?;
        for connection in 0..connections {
            let prefix = format!("run_0_connection_{connection}");
            let count_key = format!("{prefix}_headers_count");
            let count = if self.fields.contains_key(&count_key) {
                self.record_count(&count_key)?
            } else {
                0
            };
            for index in 0..count {
                let key = format!("{prefix}_headers_{index}");
                if self
                    .block(&key)?
                    .iter()
                    .any(|(name, value, _)| name == ":method" && value == "CONNECT")
                {
                    return Ok(Some((connection, key)));
                }
            }
        }
        Ok(None)
    }

    fn first_request(&self, kind: &str) -> TestResult<Option<(usize, String)>> {
        if !self.fields.contains_key("run_0_request_count") {
            return Ok(None);
        }
        for index in 0..self.record_count("run_0_request_count")? {
            let prefix = format!("run_0_request_{index}");
            let record = self.value(&prefix)?;
            if attribute(record, "kind")? == kind {
                return Ok(Some((attribute(record, "connection")?.parse()?, prefix)));
            }
        }
        Ok(None)
    }

    fn block(&self, key: &str) -> TestResult<Vec<(String, String, Representation)>> {
        let count = self.record_count(&format!("{key}_field_count"))?;
        let mut block = Vec::with_capacity(count);
        for index in 0..count {
            let field = self.value(&format!("{key}_field_{index}"))?;
            let kind = attribute(field, "repr")?;
            if kind == "size-update" {
                continue;
            }
            block.push((
                decode_hex(attribute(field, "name_hex")?)?,
                decode_hex(attribute(field, "value_hex")?)?,
                Representation {
                    kind: kind.to_owned(),
                    index: attribute(field, "index")?.parse()?,
                    name_huffman: huffman_flag(field, "name_huffman")?,
                    value_huffman: huffman_flag(field, "value_huffman")?,
                },
            ));
        }
        Ok(block)
    }
}

/// Returns `name:value` from a comma-separated capture record.
fn attribute<'a>(record: &'a str, name: &str) -> TestResult<&'a str> {
    record
        .split(',')
        .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
        .ok_or_else(|| format!("capture record omitted {name}").into())
}

/// Reads one `name_huffman` or `value_huffman` attribute.
fn huffman_flag(record: &str, name: &str) -> TestResult<Option<bool>> {
    match attribute(record, name)? {
        "none" => Ok(None),
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        other => Err(format!("capture recorded {name} as {other}").into()),
    }
}

fn decode_hex(value: &str) -> TestResult<String> {
    if !value.len().is_multiple_of(2) {
        return Err("odd-length hexadecimal value".into());
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(u8::from_str_radix(pair, 16)?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_hex_returns_an_error_without_panicking() {
        for value in ["abc", "gg", "é", "a€", "😀", "ff"] {
            assert!(decode_hex(value).is_err(), "accepted {value:?}");
        }
        assert_eq!(decode_hex("48656c6c6f20c3a9").unwrap(), "Hello é");
        assert_eq!(decode_hex("4A4b").unwrap(), "JK");
        assert_eq!(decode_hex("").unwrap(), "");
    }

    #[test]
    fn repeated_capture_keys_are_rejected() {
        assert!(Capture::parse("format=phantom-http2-websocket-v1\nformat=other").is_err());
    }

    #[test]
    fn impossible_counts_fail_before_allocating_or_iterating() {
        let input = format!(
            "format=phantom-http2-websocket-v1\nrun_0_connection_count={}\n\
             run_0_request_count={}\nrecord_field_count={}\nrecord_header_count={}\n\
             record_line_hex=474554202f20485454502f312e31",
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX
        );
        let capture = Capture::parse(&input).unwrap();
        assert!(capture.first_connect().is_err());
        assert!(capture.first_request("websocket").is_err());
        assert!(capture.block("record").is_err());
        assert!(capture.h1_request("record").is_err());
    }

    #[test]
    fn valid_counted_header_block_keeps_fields_and_representation() {
        let capture = Capture::parse(
            "format=phantom-http2-websocket-v1\nrecord_field_count=1\n\
             record_field_0=repr:without-indexing,name_hex:78,value_hex:79,index:0,\
             name_huffman:false,value_huffman:true",
        )
        .unwrap();
        assert_eq!(
            capture.block("record").unwrap(),
            vec![(
                "x".into(),
                "y".into(),
                Representation {
                    kind: "without-indexing".into(),
                    index: 0,
                    name_huffman: Some(false),
                    value_huffman: Some(true),
                }
            )]
        );
    }
}
