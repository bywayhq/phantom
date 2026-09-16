use std::time::Duration;

use bytes::Bytes;

use super::{SseError, SseErrorKind, SseEvent, SseLimits};

pub(super) struct Decoder {
    pub(super) limits: SseLimits,
    chunk: Bytes,
    offset: usize,
    pub(super) line: Vec<u8>,
    skip_lf: bool,
    stream_start: bool,
    pub(super) data: String,
    event_type: String,
    pub(super) id_buffer: String,
    pub(super) last_event_id: String,
    pub(super) retry_delay: Option<Duration>,
    pub(super) event_bytes: usize,
}

impl Decoder {
    pub(super) fn new(limits: SseLimits) -> Self {
        Self {
            limits,
            chunk: Bytes::new(),
            offset: 0,
            line: Vec::new(),
            skip_lf: false,
            stream_start: true,
            data: String::new(),
            event_type: String::new(),
            id_buffer: String::new(),
            last_event_id: String::new(),
            retry_delay: None,
            event_bytes: 0,
        }
    }

    pub(super) fn replace_chunk(&mut self, chunk: Bytes) {
        debug_assert_eq!(self.offset, self.chunk.len());
        self.chunk = chunk;
        self.offset = 0;
    }

    pub(super) fn decode_available(&mut self) -> Result<Option<SseEvent>, SseError> {
        while self.offset < self.chunk.len() {
            let byte = self.chunk[self.offset];
            self.offset += 1;

            if self.skip_lf {
                self.skip_lf = false;
                if byte == b'\n' {
                    continue;
                }
            }

            match byte {
                b'\r' => {
                    self.skip_lf = true;
                    if let Some(event) = self.finish_line()? {
                        return Ok(Some(event));
                    }
                }
                b'\n' => {
                    if let Some(event) = self.finish_line()? {
                        return Ok(Some(event));
                    }
                }
                _ if self.line.len() == self.limits.max_line_bytes => {
                    return Err(SseError::without_source(
                        SseErrorKind::LineTooLong,
                        "SSE line exceeded the configured byte limit",
                    ));
                }
                _ => self.line.push(byte),
            }
        }
        Ok(None)
    }

    fn finish_line(&mut self) -> Result<Option<SseEvent>, SseError> {
        let mut line = std::mem::take(&mut self.line);
        if self.stream_start {
            self.stream_start = false;
            if line.starts_with(&[0xef, 0xbb, 0xbf]) {
                line.drain(..3);
            }
        }

        if line.is_empty() {
            self.event_bytes = 0;
            return Ok(self.dispatch());
        }

        self.event_bytes = self
            .event_bytes
            .checked_add(line.len())
            .filter(|size| *size <= self.limits.max_event_bytes)
            .ok_or_else(|| {
                SseError::without_source(
                    SseErrorKind::EventTooLarge,
                    "SSE event exceeded the configured byte limit",
                )
            })?;

        let line = String::from_utf8_lossy(&line);
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = line
            .split_once(':')
            .map_or((line.as_ref(), ""), |(field, value)| {
                (field, value.strip_prefix(' ').unwrap_or(value))
            });

        match field {
            "event" => self.event_type = value.to_owned(),
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
            }
            "id" if !value.contains('\0') => self.id_buffer = value.to_owned(),
            "retry" if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
                if let Ok(milliseconds) = value.parse() {
                    self.retry_delay = Some(Duration::from_millis(milliseconds));
                }
            }
            _ => {}
        }
        Ok(None)
    }

    fn dispatch(&mut self) -> Option<SseEvent> {
        self.last_event_id.clone_from(&self.id_buffer);
        if self.data.is_empty() {
            self.event_type.clear();
            return None;
        }

        self.data.pop();
        Some(SseEvent {
            data: std::mem::take(&mut self.data),
            event: match std::mem::take(&mut self.event_type) {
                event if event.is_empty() => "message".to_owned(),
                event => event,
            },
            id: self.last_event_id.clone(),
        })
    }

    pub(super) fn discard_pending(&mut self) {
        self.chunk = Bytes::new();
        self.offset = 0;
        self.line.clear();
        self.data.clear();
        self.event_type.clear();
        self.id_buffer.clone_from(&self.last_event_id);
        self.event_bytes = 0;
    }
}
