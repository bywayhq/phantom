//! Fixed HTTP/1 response parsing limits.

use wreq_proto::{conn::http1, http1::Http1Options};

pub(super) const MAX_RESPONSE_HEAD_BYTES: usize = 32 * 1024;
pub(super) const MAX_RESPONSE_HEADERS: usize = 100;
pub(super) const MAX_CHUNK_SIZE_LINE_BYTES: usize = 16 * 1024;

pub(super) fn connection_builder() -> http1::Builder {
    let options = Http1Options::builder()
        .max_headers(MAX_RESPONSE_HEADERS)
        .max_buf_size(MAX_RESPONSE_HEAD_BYTES)
        .max_chunk_size_line_bytes(MAX_CHUNK_SIZE_LINE_BYTES)
        .build();
    http1::Builder::default().options(options)
}
