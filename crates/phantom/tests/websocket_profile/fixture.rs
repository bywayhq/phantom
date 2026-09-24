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
            fields.insert(key.to_owned(), value.to_owned());
        }
        let capture = Self { fields };
        if capture.value("format")? != "phantom-http2-websocket-v1" {
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

    /// Returns the ALPN offer of the connection that carried the WebSocket.
    pub(crate) fn websocket_alpn_offer(&self) -> TestResult<&str> {
        let connection = match self.first_connect()? {
            Some((connection, _)) => connection,
            None => self.first_upgrade()?.ok_or("capture has no WebSocket")?.0,
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
        let (_, prefix) = self.first_upgrade()?.ok_or("capture has no H1 WebSocket")?;
        let request_line = decode_hex(self.value(&format!("{prefix}_line_hex"))?)?;
        let mut fields = Vec::new();
        for index in 0..self
            .value(&format!("{prefix}_header_count"))?
            .parse::<usize>()?
        {
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
        let connections: usize = self.value("run_0_connection_count")?.parse()?;
        for connection in 0..connections {
            let prefix = format!("run_0_connection_{connection}");
            let count = self
                .fields
                .get(&format!("{prefix}_headers_count"))
                .map_or(Ok(0), |count| count.parse::<usize>())?;
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

    fn first_upgrade(&self) -> TestResult<Option<(usize, String)>> {
        let Some(count) = self.fields.get("run_0_request_count") else {
            return Ok(None);
        };
        for index in 0..count.parse::<usize>()? {
            let prefix = format!("run_0_request_{index}");
            let record = self.value(&prefix)?;
            if attribute(record, "kind")? == "websocket" {
                return Ok(Some((attribute(record, "connection")?.parse()?, prefix)));
            }
        }
        Ok(None)
    }

    fn block(&self, key: &str) -> TestResult<Vec<(String, String, Representation)>> {
        let count: usize = self.value(&format!("{key}_field_count"))?.parse()?;
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
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(String::from_utf8(bytes)?)
}
