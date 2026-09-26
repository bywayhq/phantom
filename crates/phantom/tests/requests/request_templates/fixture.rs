//! Reads one ordinary request from a retained browser capture.
//!
//! The HTTP/1.1 and HTTP/2 requests come from `phantom-http2-websocket-v1`
//! captures, HTTP/1.1 EventSource requests from `phantom-sse-reconnect-v1`
//! captures, and the HTTP/3 request from a `phantom-http3-*` startup capture.
//! `Host` and pseudo-header fields are left out.

use std::collections::BTreeMap;

use crate::request_templates::{TestResult, wire::Priority};

/// Ordered `(name, value)` request fields.
pub(crate) type Fields = Vec<(String, String)>;

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
        Ok(Self { fields })
    }

    fn value(&self, key: &str) -> TestResult<&str> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("capture omitted {key}").into())
    }

    /// Returns run 0's first HTTP/1.1 request of `kind` (`page` or `done`).
    pub(crate) fn http1_request(&self, kind: &str) -> TestResult<Fields> {
        self.http1_requests(kind)?
            .into_iter()
            .next()
            .ok_or_else(|| format!("capture has no {kind} request").into())
    }

    /// Returns run 0's HTTP/1.1 requests of `kind` (such as `page`, `done`,
    /// or `sse`) in capture order.
    pub(crate) fn http1_requests(&self, kind: &str) -> TestResult<Vec<Fields>> {
        let count: usize = self.value("run_0_request_count")?.parse()?;
        let mut requests = Vec::new();
        for index in 0..count {
            let prefix = format!("run_0_request_{index}");
            if attribute(self.value(&prefix)?, "kind") != Some(kind) {
                continue;
            }
            let mut fields = Vec::new();
            for field in 0..self
                .value(&format!("{prefix}_header_count"))?
                .parse::<usize>()?
            {
                let line = decode_hex(self.value(&format!("{prefix}_header_{field}"))?)?;
                let (name, value) = line.split_once(": ").ok_or("H1 field has no `: `")?;
                if !name.eq_ignore_ascii_case("host") {
                    fields.push((name.to_owned(), value.to_owned()));
                }
            }
            requests.push(fields);
        }
        Ok(requests)
    }

    /// Returns run 0's first HTTP/2 GET whose `sec-fetch-dest` is `destination`.
    pub(crate) fn http2_request(&self, destination: &str) -> TestResult<Fields> {
        Ok(self.http2_block(destination)?.1)
    }

    /// Returns the HEADERS priority of [`Self::http2_request`]'s block, or
    /// `None` when it had no priority fields.
    pub(crate) fn http2_priority(&self, destination: &str) -> TestResult<Option<Priority>> {
        let (key, _) = self.http2_block(destination)?;
        let Some((_, priority)) = self.value(&key)?.split_once("priority:") else {
            return Ok(None);
        };
        Ok(Some((
            attribute(priority, "exclusive").ok_or("no exclusive flag")? == "true",
            attribute(priority, "depends_on")
                .ok_or("no dependency")?
                .parse()?,
            attribute(priority, "weight").ok_or("no weight")?.parse()?,
        )))
    }

    fn http2_block(&self, destination: &str) -> TestResult<(String, Fields)> {
        let connections: usize = self.value("run_0_connection_count")?.parse()?;
        for connection in 0..connections {
            let prefix = format!("run_0_connection_{connection}");
            let Some(count) = self.fields.get(&format!("{prefix}_headers_count")) else {
                continue;
            };
            for block in 0..count.parse::<usize>()? {
                let key = format!("{prefix}_headers_{block}");
                let mut method = String::new();
                let mut fields = Vec::new();
                for field in 0..self
                    .value(&format!("{key}_field_count"))?
                    .parse::<usize>()?
                {
                    let record = self.value(&format!("{key}_field_{field}"))?;
                    if attribute(record, "repr") == Some("size-update") {
                        continue;
                    }
                    let name = decode_hex(attribute(record, "name_hex").ok_or("no name")?)?;
                    let value = decode_hex(attribute(record, "value_hex").ok_or("no value")?)?;
                    if name == ":method" {
                        method = value;
                    } else if !name.starts_with(':') {
                        fields.push((name, value));
                    }
                }
                let matches = fields
                    .iter()
                    .any(|(name, value)| name == "sec-fetch-dest" && value == destination);
                if method == "GET" && matches {
                    return Ok((key, fields));
                }
            }
        }
        Err(format!("capture has no {destination} HTTP/2 request").into())
    }

    /// Returns the request of an HTTP/3 startup capture.
    pub(crate) fn http3_request(&self) -> TestResult<Fields> {
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
