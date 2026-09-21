//! Reads navigation HTTP/2 settings from retained browser session captures.
//!
//! `scripts/capture/http2_session.py` records every client frame and HPACK
//! block of a loopback H2 session (`format=phantom-http2-websocket-v1`). The
//! page load on that session is an ordinary navigation, so its connection
//! preface frames and first HEADERS frame carry the settings a recipe models.

use std::collections::BTreeMap;

use crate::http2::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings};

type CaptureResult<T> = Result<T, Box<dyn std::error::Error>>;

const FORMAT: &str = "phantom-http2-websocket-v1";
const INITIAL_CONNECTION_WINDOW: u32 = 65_535;
const METHOD_HEX: &str = "3a6d6574686f64";
const GET_HEX: &str = "474554";

/// One retained `format=phantom-http2-websocket-v1` session capture.
pub(crate) struct SessionCapture<'a> {
    fields: BTreeMap<&'a str, &'a str>,
}

impl<'a> SessionCapture<'a> {
    pub(crate) fn parse(input: &'a str) -> CaptureResult<Self> {
        let mut fields = BTreeMap::new();
        for line in input.lines() {
            let (key, value) = line.split_once('=').ok_or("capture line is missing `=`")?;
            if fields.insert(key, value).is_some() {
                return Err(format!("capture repeats {key}").into());
            }
        }
        let capture = Self { fields };
        if capture.value("format")? != FORMAT {
            return Err("unexpected session capture format".into());
        }
        Ok(capture)
    }

    pub(crate) fn value(&self, key: &str) -> CaptureResult<&'a str> {
        self.fields
            .get(key)
            .copied()
            .ok_or_else(|| format!("capture omitted {key}").into())
    }

    /// Returns the settings observed on each run's navigation connection.
    ///
    /// The navigation connection is the one whose first client HEADERS block
    /// is a `GET`; its client SETTINGS and connection WINDOW_UPDATE precede
    /// that request on the same connection.
    pub(crate) fn navigation_settings(&self) -> CaptureResult<Vec<Http2Settings>> {
        let runs: usize = self.value("repeat_count")?.parse()?;
        (0..runs)
            .map(|run| self.run_navigation_settings(run))
            .collect()
    }

    fn run_navigation_settings(&self, run: usize) -> CaptureResult<Http2Settings> {
        let connections: usize = self
            .value(&format!("run_{run}_connection_count"))?
            .parse()?;
        let mut observed = Vec::new();
        for connection in 0..connections {
            let prefix = format!("run_{run}_connection_{connection}");
            if self.first_request_method(&prefix)? != Some(GET_HEX) {
                continue;
            }
            observed.push(self.connection_settings(&prefix)?);
        }
        match <[Http2Settings; 1]>::try_from(observed) {
            Ok([settings]) => Ok(settings),
            Err(_) => Err(format!("run {run} must have exactly one navigation connection").into()),
        }
    }

    /// Returns the hex `:method` of the connection's first client HEADERS.
    ///
    /// Representations such as a dynamic table size update can precede the
    /// first field, so the method is found by name rather than position.
    fn first_request_method(&self, prefix: &str) -> CaptureResult<Option<&'a str>> {
        let Some(count) = self
            .fields
            .get(format!("{prefix}_headers_0_field_count").as_str())
        else {
            return Ok(None);
        };
        for index in 0..count.parse::<usize>()? {
            let field = self.value(&format!("{prefix}_headers_0_field_{index}"))?;
            if field_attribute(field, "name_hex")? == METHOD_HEX {
                return field_attribute(field, "value_hex").map(Some);
            }
        }
        Err(format!("{prefix} first HEADERS omitted :method").into())
    }

    fn connection_settings(&self, prefix: &str) -> CaptureResult<Http2Settings> {
        let frames: usize = self.value(&format!("{prefix}_frame_count"))?.parse()?;
        let mut initial_settings = None;
        let mut window_increment = None;
        for index in 0..frames {
            let frame = self.value(&format!("{prefix}_frame_{index}"))?;
            if field_attribute(frame, "dir")? != "client"
                || field_attribute(frame, "stream")? != "0"
            {
                continue;
            }
            match field_attribute(frame, "type")? {
                "SETTINGS" if field_attribute(frame, "flags")? == "0x00" => {
                    if initial_settings.is_none() {
                        initial_settings =
                            Some(parse_settings(field_attribute(frame, "settings")?)?);
                    }
                }
                "WINDOW_UPDATE" if window_increment.is_none() => {
                    window_increment = Some(field_attribute(frame, "increment")?.parse::<u32>()?);
                }
                "HEADERS" => break,
                _ => {}
            }
        }
        let headers = self.value(&format!("{prefix}_headers_0"))?;
        let headers_priority = Http2Priority {
            dependency_stream_id: field_attribute(headers, "depends_on")?.parse()?,
            weight: field_attribute(headers, "weight")?.parse()?,
            exclusive: field_attribute(headers, "priority:exclusive")? == "true",
        };
        let order = self.value(&format!("{prefix}_headers_0_field_order"))?;
        let pseudo_header_order = order
            .split(',')
            .filter(|name| name.starts_with(':'))
            .map(parse_pseudo_header)
            .collect::<CaptureResult<Vec<_>>>()?;
        let increment = window_increment.ok_or("connection omitted a WINDOW_UPDATE")?;
        Ok(Http2Settings {
            initial_settings: initial_settings.ok_or("connection omitted client SETTINGS")?,
            initial_connection_window_size: INITIAL_CONNECTION_WINDOW
                .checked_add(increment)
                .ok_or("connection window overflow")?,
            pseudo_header_order,
            extended_connect_pseudo_header_order: None,
            extended_connect_priority: None,
            headers_priority: Some(headers_priority),
        })
    }
}

/// Returns `name:value` from a comma-separated capture record.
///
/// Priority attributes are nested as `priority:exclusive:true`, so a composite
/// name is matched as a prefix of the whole item.
fn field_attribute<'a>(record: &'a str, name: &str) -> CaptureResult<&'a str> {
    record
        .split(',')
        .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
        .ok_or_else(|| format!("capture record omitted {name}").into())
}

fn parse_settings(value: &str) -> CaptureResult<Vec<Http2Setting>> {
    value
        .split(';')
        .map(|pair| {
            let (id, value) = pair.split_once('=').ok_or("invalid SETTINGS pair")?;
            let value = value.parse::<u32>()?;
            let flag = |value: u32| match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(format!("invalid boolean SETTINGS value {value}")),
            };
            Ok(match id {
                "1" => Http2Setting::HeaderTableSize(value),
                "2" => Http2Setting::EnablePush(flag(value)?),
                "3" => Http2Setting::MaxConcurrentStreams(value),
                "4" => Http2Setting::InitialWindowSize(value),
                "5" => Http2Setting::MaxFrameSize(value),
                "6" => Http2Setting::MaxHeaderListSize(value),
                "8" => Http2Setting::EnableConnectProtocol(flag(value)?),
                "9" => Http2Setting::NoRfc7540Priorities(flag(value)?),
                _ => return Err(format!("unsupported SETTINGS identifier {id}").into()),
            })
        })
        .collect()
}

fn parse_pseudo_header(name: &str) -> CaptureResult<Http2PseudoHeader> {
    match name {
        ":method" => Ok(Http2PseudoHeader::Method),
        ":authority" => Ok(Http2PseudoHeader::Authority),
        ":scheme" => Ok(Http2PseudoHeader::Scheme),
        ":path" => Ok(Http2PseudoHeader::Path),
        ":protocol" => Ok(Http2PseudoHeader::Protocol),
        _ => Err(format!("unsupported pseudo-header {name}").into()),
    }
}
