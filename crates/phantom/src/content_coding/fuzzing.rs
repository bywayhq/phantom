//! Bounded access to the production content-coding pipeline for fuzz targets.

use http::HeaderValue;

use super::{
    AdvertisedContentCodings, Bytes, ContentDecoding, ContentDecodingPlan, HeaderMap, HttpProtocol,
    Method, Pump, RequestHeader, StatusCode, header, plan,
};
use crate::RequestErrorKind;

const MAXIMUM_BYTES: usize = 64 * 1024;
const MAXIMUM_HEADER_BYTES: usize = 1024;
const MAXIMUM_PUMPS: usize = 4096;

/// Outcome of one bounded content-coding fuzz invocation, not supported API.
#[derive(Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum FuzzContentDecode {
    /// The production policy or response fields select an unchanged body.
    Passthrough,
    /// Every decoding stage completed at EOF.
    Complete {
        /// Decoded bytes, limited to 64 KiB.
        data: Vec<u8>,
        /// Largest decoded frame, in bytes.
        largest_frame: usize,
    },
    /// A response field cannot be represented by `http::HeaderValue`.
    InvalidResponseField,
    /// The production request parser, response plan or decoder rejected input.
    Failed(RequestErrorKind),
    /// The harness stopped before a terminal decoder result; inconclusive.
    WorkLimit,
}

/// Drives production coding-field parsing and decoding for a streaming GET/200.
///
/// This is a fuzzing seam, not supported API. Error kinds use HTTP/2 attribution.
/// Request and response values are separate ordered field lines. Positive chunk
/// sizes cycle until the input is consumed. Work-limit exhaustion discards the
/// decoder without claiming EOF or successful decoding.
///
/// # Errors
///
/// Returns a harness error for input or decoded limits over 64 KiB, more than
/// four field values per direction or 1 KiB of aggregate fields, an empty or
/// invalid chunk plan, a pump budget over 4096, or output over the harness bound.
/// Production failures remain in the successful result.
#[doc(hidden)]
pub fn fuzz_content_decode(
    request_values: &[&[u8]],
    response_values: &[&[u8]],
    input: &[u8],
    chunk_sizes: &[usize],
    policy: ContentDecoding,
    maximum_pumps: usize,
) -> Result<FuzzContentDecode, &'static str> {
    if input.len() > MAXIMUM_BYTES
        || policy
            .maximum_decoded_bytes()
            .is_some_and(|maximum| maximum > MAXIMUM_BYTES as u64)
        || request_values.len() > 4
        || response_values.len() > 4
        || request_values
            .iter()
            .chain(response_values)
            .try_fold(0_usize, |total, value| total.checked_add(value.len()))
            .is_none_or(|total| total > MAXIMUM_HEADER_BYTES)
        || chunk_sizes.is_empty()
        || chunk_sizes.len() > 64
        || chunk_sizes
            .iter()
            .any(|size| *size == 0 || *size > MAXIMUM_BYTES)
        || maximum_pumps > MAXIMUM_PUMPS
    {
        return Err("invalid content-coding fuzz input bounds");
    }

    let request_headers: Vec<_> = request_values
        .iter()
        .map(|value| RequestHeader::new("accept-encoding", value))
        .collect();
    let advertised = match AdvertisedContentCodings::from_request_headers(&request_headers) {
        Ok(advertised) => advertised,
        Err(error) => return Ok(FuzzContentDecode::Failed(error.kind())),
    };
    let mut response_headers = HeaderMap::new();
    for value in response_values {
        let Ok(value) = HeaderValue::from_bytes(value) else {
            return Ok(FuzzContentDecode::InvalidResponseField);
        };
        response_headers.append(header::CONTENT_ENCODING, value);
    }
    let mut decoder = match plan(
        policy,
        advertised,
        &Method::GET,
        StatusCode::OK,
        &response_headers,
        false,
        HttpProtocol::Http2,
    ) {
        ContentDecodingPlan::Passthrough => return Ok(FuzzContentDecode::Passthrough),
        ContentDecodingPlan::Reject(error) => return Ok(FuzzContentDecode::Failed(error.kind())),
        ContentDecodingPlan::Decode(decoder, _) => decoder,
    };
    let mut remaining = input;
    let mut chunks = chunk_sizes.iter().cycle();
    let mut data = Vec::new();
    let mut largest_frame = 0;
    for _ in 0..maximum_pumps {
        match decoder.pump() {
            Err(error) => return Ok(FuzzContentDecode::Failed(error.kind())),
            Ok(Pump::Finished) => {
                return Ok(FuzzContentDecode::Complete {
                    data,
                    largest_frame,
                });
            }
            Ok(Pump::Yield) => {}
            Ok(Pump::Data(frame)) => {
                if frame.len() > MAXIMUM_BYTES.saturating_sub(data.len()) {
                    return Err("content decoder exceeded the fuzz output bound");
                }
                largest_frame = largest_frame.max(frame.len());
                data.extend_from_slice(&frame);
            }
            Ok(Pump::NeedInput) if remaining.is_empty() => decoder.end_input(),
            Ok(Pump::NeedInput) => {
                let size = *chunks
                    .next()
                    .ok_or("content-coding fuzz chunk plan is empty")?;
                let (chunk, rest) = remaining.split_at(size.min(remaining.len()));
                decoder.push(Bytes::copy_from_slice(chunk));
                remaining = rest;
            }
        }
    }
    Ok(FuzzContentDecode::WorkLimit)
}
