//! Reads ordinary request fields from retained browser captures.
//!
//! Three capture formats carry complete request fields: the HTTP/1.1
//! requests of `phantom-sse-reconnect-v1` and `phantom-http2-websocket-v1`,
//! the HTTP/2 HEADERS blocks of `phantom-http2-websocket-v1`, and the H3
//! request of `phantom-http3-*` startup captures.

use std::collections::BTreeMap;

use crate::Http2Priority;

pub(crate) type CaptureResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Ordered `(name, value)` fields of one request, without `Host` and
/// pseudo-header fields.
pub(crate) type Fields = Vec<(String, String)>;

pub(crate) struct Capture<'a> {
    fields: BTreeMap<&'a str, &'a str>,
}

impl<'a> Capture<'a> {
    pub(crate) fn parse(input: &'a str) -> CaptureResult<Self> {
        let mut fields = BTreeMap::new();
        for line in input.lines() {
            let (key, value) = line.split_once('=').ok_or("capture line is missing `=`")?;
            if fields.insert(key, value).is_some() {
                return Err(format!("capture repeats {key}").into());
            }
        }
        Ok(Self { fields })
    }

    pub(crate) fn value(&self, key: &str) -> CaptureResult<&'a str> {
        self.fields
            .get(key)
            .copied()
            .ok_or_else(|| format!("capture omitted {key}").into())
    }

    /// Returns every HTTP/1.1 request of `kind` (`page`, `done`, ...) in
    /// every run.
    pub(crate) fn http1_requests(&self, kind: &str) -> CaptureResult<Vec<Fields>> {
        let mut requests = Vec::new();
        for (key, record) in &self.fields {
            let Some(prefix) = key.strip_prefix("run_") else {
                continue;
            };
            let is_request_record = prefix
                .split_once("_request_")
                .is_some_and(|(run, index)| is_number(run) && is_number(index));
            if !is_request_record || attribute(record, "kind") != Some(kind) {
                continue;
            }
            let count: usize = self.value(&format!("{key}_header_count"))?.parse()?;
            let mut fields = Vec::with_capacity(count);
            for index in 0..count {
                let line = decode_hex(self.value(&format!("{key}_header_{index}"))?)?;
                let (name, value) = line.split_once(": ").ok_or("H1 field has no `: `")?;
                if !name.eq_ignore_ascii_case("host") {
                    fields.push((name.to_owned(), value.to_owned()));
                }
            }
            requests.push(fields);
        }
        Ok(requests)
    }

    /// Returns every HTTP/2 GET HEADERS block whose `sec-fetch-dest` is
    /// `destination`, in every run and connection.
    pub(crate) fn http2_requests(&self, destination: &str) -> CaptureResult<Vec<Fields>> {
        Ok(self
            .http2_blocks(destination)?
            .into_iter()
            .map(|(_, fields)| fields)
            .collect())
    }

    /// Returns the HEADERS priority of every block [`Self::http2_requests`]
    /// returns, or `None` for a block without priority fields.
    pub(crate) fn http2_priorities(
        &self,
        destination: &str,
    ) -> CaptureResult<Vec<Option<Http2Priority>>> {
        let mut priorities = Vec::new();
        for (key, _) in self.http2_blocks(destination)? {
            let record = self.value(key)?;
            let Some((_, priority)) = record.split_once("priority:") else {
                priorities.push(None);
                continue;
            };
            priorities.push(Some(Http2Priority {
                exclusive: attribute(priority, "exclusive").ok_or("no exclusive flag")? == "true",
                dependency_stream_id: attribute(priority, "depends_on")
                    .ok_or("no dependency")?
                    .parse()?,
                weight: attribute(priority, "weight").ok_or("no weight")?.parse()?,
            }));
        }
        Ok(priorities)
    }

    fn http2_blocks(&self, destination: &str) -> CaptureResult<Vec<(&'a str, Fields)>> {
        let mut requests = Vec::new();
        for key in self.fields.keys() {
            let Some((connection, index)) = key.split_once("_headers_") else {
                continue;
            };
            if !connection.starts_with("run_") || !is_number(index) {
                continue;
            }
            let count: usize = self.value(&format!("{key}_field_count"))?.parse()?;
            let mut method = None;
            let mut fields = Vec::with_capacity(count);
            for field in 0..count {
                let record = self.value(&format!("{key}_field_{field}"))?;
                if attribute(record, "repr") == Some("size-update") {
                    continue;
                }
                let name = decode_hex(attribute(record, "name_hex").ok_or("field has no name")?)?;
                let value =
                    decode_hex(attribute(record, "value_hex").ok_or("field has no value")?)?;
                if name == ":method" {
                    method = Some(value);
                } else if !name.starts_with(':') {
                    fields.push((name, value));
                }
            }
            let matches_destination = fields
                .iter()
                .any(|(name, value)| name == "sec-fetch-dest" && value == destination);
            if method.as_deref() == Some("GET") && matches_destination {
                requests.push((*key, fields));
            }
        }
        Ok(requests)
    }

    /// Returns the request of an HTTP/3 startup capture.
    pub(crate) fn http3_request(&self) -> CaptureResult<Fields> {
        let count: usize = self.value("request_header_count")?.parse()?;
        let mut fields = Vec::with_capacity(count);
        for index in 0..count {
            let (name, value) = self
                .value(&format!("request_header_{index}"))?
                .split_once(':')
                .ok_or("H3 field has no `:`")?;
            let name = decode_hex(name)?;
            if !name.starts_with(':') {
                fields.push((name, decode_hex(value)?));
            }
        }
        Ok(fields)
    }
}

/// Returns `name:value` from a comma-separated capture record.
fn attribute<'a>(record: &'a str, name: &str) -> Option<&'a str> {
    record
        .split(',')
        .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
}

fn is_number(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

fn decode_hex(value: &str) -> CaptureResult<String> {
    if value.len() % 2 != 0 {
        return Err("odd-length hexadecimal value".into());
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(String::from_utf8(bytes)?)
}
