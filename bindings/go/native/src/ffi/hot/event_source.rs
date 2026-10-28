//! Optional EventSource ABI 1. Inputs are copied before asynchronous admission.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    time::Duration,
};

use phantom::{HttpProtocol, SseHeader};

use super::{Field, Reply, Span, Timeout, fields, sse, submitted, text, timeout};
use crate::{
    client,
    error::Failure,
    operations::{self, event_source},
    timeouts,
};

#[repr(C)]
struct Header {
    kind: u64,
    field: Field,
}
#[repr(C)]
struct Opening {
    client: u64,
    url: Span,
    protocol: u64,
    headers: *const Header,
    header_count: usize,
    headers_present: u64,
    line: u64,
    event: u64,
    flags: u64,
    idle: u64,
    initial_retry: u64,
    min_retry: u64,
    maximum: u64,
    timeouts: [Timeout; 5],
    proxy: Span,
    username: Span,
    password: Span,
}
#[repr(C)]
#[derive(Default)]
struct ResultData {
    event: sse::Event,
    retry_milliseconds: u64,
    reconnects: u64,
    closed: u64,
}

// SAFETY: This pointer-free symbol negotiates the independent optional ABI.
#[unsafe(no_mangle)]
extern "C" fn phantom_go_event_source_version() -> u64 {
    1
}

// SAFETY: All pointers lend aligned readable descriptors and bounded spans for
// this call only. Every nested value is copied before native work is admitted.
unsafe fn opening(value: &Opening) -> Result<event_source::Opening, Failure> {
    if value.flags & !63 != 0
        || value.headers_present > 1
        || value.header_count > 256
        || (value.header_count != 0 && value.headers.is_null())
        || (value.headers_present == 0 && value.header_count != 0)
    {
        return Err(Failure::new("invalid_event_source_options"));
    }
    let protocol = match value.protocol {
        1 => HttpProtocol::Http1,
        2 => HttpProtocol::Http2,
        3 => HttpProtocol::Http3,
        _ => return Err(Failure::new("invalid_event_source_protocol")),
    };
    let mut remaining = operations::MAX_COMMAND;
    // SAFETY: All spans follow the entry point's synchronous readable contract.
    let (url, proxy, username, password) = unsafe {
        (
            text(value.url, &mut remaining)?,
            text(value.proxy, &mut remaining)?,
            text(value.username, &mut remaining)?,
            text(value.password, &mut remaining)?,
        )
    };
    let headers = if value.headers_present == 1 {
        let values = if value.header_count == 0 {
            &[][..]
        } else {
            // SAFETY: The caller lends header_count aligned Header descriptors.
            unsafe { slice::from_raw_parts(value.headers, value.header_count) }
        };
        let mut headers = Vec::with_capacity(values.len());
        for header in values {
            // SAFETY: The field and nested spans live through this call. fields
            // copies bytes and subtracts them from the shared input allowance.
            let field = unsafe { fields(&header.field, 1, &mut remaining)? }
                .pop()
                .ok_or_else(|| Failure::new("internal"))?;
            headers.push(match header.kind {
                1 => SseHeader::field(field.into_request()),
                2 if field.value.is_empty() && !field.sensitive => {
                    SseHeader::last_event_id(field.name)
                }
                _ => return Err(Failure::new("invalid_event_source_header")),
            });
        }
        Some(headers)
    } else {
        None
    };
    if value.timeouts[3].mode != 0 || value.timeouts[3].nanoseconds != 0 {
        return Err(Failure::new("event_source_read_idle_unsupported"));
    }
    let timeouts = timeouts::Timeouts {
        pool_admission: timeout(value.timeouts[0])?,
        connect: timeout(value.timeouts[1])?,
        response_head: timeout(value.timeouts[2])?,
        read_idle: timeout(value.timeouts[3])?,
        total: timeout(value.timeouts[4])?,
    };
    for (flag, duration) in [
        (1, value.idle),
        (2, value.initial_retry),
        (4, value.min_retry),
        (8, value.maximum),
    ] {
        if value.flags & flag == 0 && duration != 0 {
            return Err(Failure::new("invalid_event_source_options"));
        }
    }
    if (value.flags & 16 == 0 && !proxy.is_empty())
        || (value.flags & 32 == 0 && (!username.is_empty() || !password.is_empty()))
        || (value.flags & 32 != 0 && (value.flags & 16 == 0 || proxy.is_empty()))
    {
        return Err(Failure::new("invalid_proxy_credentials"));
    }
    let route = if value.flags & 16 != 0 {
        let credentials =
            (value.flags & 32 != 0).then(|| client::ProxyCredentials::new(username, password));
        Some(client::route(
            (!proxy.is_empty()).then_some(proxy.as_str()),
            credentials,
        )?)
    } else {
        None
    };
    Ok(event_source::Opening {
        client: value.client,
        url,
        protocol,
        headers,
        limits: operations::sse::Limits {
            line: usize::try_from(value.line).map_err(|_| Failure::new("invalid_sse_limits"))?,
            event: usize::try_from(value.event).map_err(|_| Failure::new("invalid_sse_limits"))?,
        },
        idle: (value.flags & 1 != 0).then(|| Duration::from_nanos(value.idle)),
        initial_retry: (value.flags & 2 != 0).then(|| Duration::from_nanos(value.initial_retry)),
        min_retry: (value.flags & 4 != 0).then(|| Duration::from_nanos(value.min_retry)),
        maximum: if value.flags & 8 != 0 {
            Some(
                usize::try_from(value.maximum)
                    .map_err(|_| Failure::new("invalid_event_source_options"))?,
            )
        } else {
            None
        },
        timeouts,
        route,
    })
}

// SAFETY: Opening borrows all nested input and reply lends one aligned writable
// result. No foreign pointer survives this synchronous decode and submission.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_event_source_open(value: *const Opening, reply: *mut Reply) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller lends one aligned Opening and its nested input.
        let opening = unsafe { opening(&*value)? };
        event_source::open(opening)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller lends one aligned writable reply for this call.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: Scalar verbs select next, close or cancel-next. Reply lends one
// aligned writable descriptor. All resulting work owns its Rust inputs.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_event_source_operation(
    verb: u64,
    handle: u64,
    reply: *mut Reply,
) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| match verb {
        1 => event_source::next(handle),
        2 => event_source::close(handle),
        3 => event_source::cancel_next(handle),
        _ => Err(Failure::new("invalid_command")),
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: One aligned writable reply is borrowed for the entire call.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: Result and disjoint output storage are aligned and writable for this
// call. Zero capacity probes; the operation retains payload ownership until ack.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_event_source_result(
    operation: u64,
    value: *mut ResultData,
    output: *mut u8,
    capacity: usize,
) -> u64 {
    if value.is_null()
        || (output.is_null() && capacity != 0)
        || capacity > operations::sse::MAX_RESULT
    {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let result = event_source::result(operation)?;
        // SAFETY: Capacity/nulls checked above; caller guarantees writable output.
        let event = unsafe { sse::project(&result.read, output, capacity)? };
        Ok::<_, Failure>(ResultData {
            event,
            retry_milliseconds: result.state.retry_milliseconds,
            reconnects: result.state.reconnects,
            closed: u64::from(result.state.closed),
        })
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    let result = result.unwrap_or_else(|error| ResultData {
        event: sse::Event::from_failure(error),
        ..ResultData::default()
    });
    // SAFETY: The caller lends one aligned writable result descriptor.
    unsafe {
        ptr::write(value, result);
    }
    1
}
#[cfg(test)]
mod tests {
    use super::*;

    fn wire(url: &[u8]) -> Opening {
        let empty = Span {
            pointer: ptr::null(),
            length: 0,
        };
        Opening {
            client: 1,
            url: Span {
                pointer: url.as_ptr(),
                length: url.len(),
            },
            protocol: 2,
            headers: ptr::null(),
            header_count: 0,
            headers_present: 0,
            line: 65536,
            event: 1048576,
            flags: 0,
            idle: 0,
            initial_retry: 0,
            min_retry: 0,
            maximum: 0,
            timeouts: [Timeout {
                mode: 0,
                nanoseconds: 0,
            }; 5],
            proxy: empty,
            username: empty,
            password: empty,
        }
    }

    #[test]
    fn source_copies_ordered_fields_and_preserves_the_id_slot() -> Result<(), Failure> {
        let mut url = b"https://example.test/events".to_vec();
        let mut secret = [255, 0, 1];
        let headers = [
            Header {
                kind: 1,
                field: Field {
                    name: Span {
                        pointer: b"x-token".as_ptr(),
                        length: 7,
                    },
                    value: Span {
                        pointer: secret.as_ptr(),
                        length: secret.len(),
                    },
                    sensitive: 1,
                },
            },
            Header {
                kind: 2,
                field: Field {
                    name: Span {
                        pointer: b"last-event-id".as_ptr(),
                        length: 13,
                    },
                    value: Span {
                        pointer: ptr::null(),
                        length: 0,
                    },
                    sensitive: 0,
                },
            },
        ];
        let mut value = wire(&url);
        value.headers = headers.as_ptr();
        value.header_count = headers.len();
        value.headers_present = 1;
        // SAFETY: All descriptors and nested storage are valid through decode.
        let owned = unsafe { opening(&value)? };
        url.fill(b'x');
        secret.fill(0);
        assert_eq!(owned.url, "https://example.test/events");
        let fields = owned
            .headers
            .ok_or_else(|| Failure::new("test_missing_headers"))?;
        assert!(
            matches!(&fields[0],SseHeader::Field(header) if header.name()=="x-token" && header.value()==[255,0,1] && header.is_sensitive())
        );
        assert!(
            matches!(&fields[1],SseHeader::LastEventId { name } if name.as_ref()=="last-event-id")
        );
        Ok(())
    }

    #[test]
    fn foreign_invalid_arrays_and_ignored_read_idle_are_rejected() {
        let mut value = wire(b"https://example.test/events");
        value.headers_present = 1;
        value.header_count = 1;
        // SAFETY: The null nonempty array is rejected before dereferencing it.
        let invalid = unsafe { opening(&value) }.err().map(|error| error.kind);
        assert_eq!(invalid, Some("invalid_event_source_options"));
        value.header_count = 0;
        value.timeouts[3].mode = 1;
        // SAFETY: All spans are valid and empty arrays are never dereferenced.
        let invalid = unsafe { opening(&value) }.err().map(|error| error.kind);
        assert_eq!(invalid, Some("event_source_read_idle_unsupported"));
    }
}
