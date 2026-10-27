//! Typed request/completion ABI. All borrowed input is copied before admission.
//! Output spans address the caller's byte arena, never Rust or Go object storage.

use super::{input, output};
use crate::{
    client::Header,
    error::Failure,
    operations::{self, Command, Completed},
    policy, retry, timeouts,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct Span {
    pointer: *const u8,
    length: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Field {
    name: Span,
    value: Span,
    sensitive: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Timeout {
    mode: u64,
    nanoseconds: u64,
}
#[repr(C)]
struct Retry {
    flags: u64,
    connection_maximum: u64,
    connection_delay: u64,
    connection_maximum_delay: u64,
    statuses: *const u16,
    status_count: usize,
    status_maximum: u64,
    status_delay: u64,
    status_maximum_delay: u64,
    retry_after: u64,
    unprocessed: u64,
    maximum: u64,
}
#[repr(C)]
struct Request {
    client: u64,
    method: Span,
    url: Span,
    headers: *const Field,
    header_count: usize,
    trailers: *const Field,
    trailer_count: usize,
    flags: u64,
    expect_continue: u64,
    budget: u64,
    transfer: u64,
    diagnostics: u64,
    prepared_body: u64,
    upload: u64,
    timeouts: [Timeout; 5],
    decoded_maximum: u64,
    redirect_maximum: u64,
    credential_headers: *const Span,
    credential_header_count: usize,
    redirect_history: u64,
    retry: *const Retry,
}
#[repr(C)]
struct Error {
    kind: [u8; 64],
    protocol: [u8; 64],
    timeout_phase: [u8; 64],
}
impl Default for Error {
    fn default() -> Self {
        Self {
            kind: [0; 64],
            protocol: [0; 64],
            timeout_phase: [0; 64],
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Reply {
    operation: u64,
    error: Error,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Slice {
    offset: u64,
    length: u64,
}
#[repr(C)]
#[derive(Default)]
struct OutputField {
    name: Slice,
    value: Slice,
    sensitive: u64,
}
#[repr(C)]
#[derive(Default)]
struct Hop {
    from: Slice,
    to: Slice,
    method: Slice,
    next_method: Slice,
    status: u64,
}
#[repr(C)]
#[derive(Default)]
struct Event {
    operation: u64,
    kind: u64,
    body: u64,
    status: u64,
    protocol: u64,
    redirects: u64,
    setup_retries: u64,
    history_present: u64,
    history_omitted: u64,
    part: u64,
    trailer_state: u64,
    field_count: u64,
    hop_count: u64,
    coding_count: u64,
    arena_length: u64,
    data_length: u64,
    effective_url: Slice,
    error: Error,
}

impl From<Failure> for Error {
    fn from(error: Failure) -> Self {
        fn copy(destination: &mut [u8; 64], source: &str) {
            let count = source.len().min(destination.len() - 1);
            destination[..count].copy_from_slice(&source.as_bytes()[..count]);
        }
        let mut result = Self::default();
        copy(&mut result.kind, error.kind);
        copy(&mut result.protocol, error.protocol.unwrap_or_default());
        copy(
            &mut result.timeout_phase,
            error.timeout_phase.unwrap_or_default(),
        );
        result
    }
}

unsafe fn bytes<'a>(value: Span, maximum: usize) -> Result<&'a [u8], Failure> {
    if value.length > maximum || (value.pointer.is_null() && value.length != 0) {
        return Err(Failure::new("input_limit"));
    }
    // SAFETY: The caller lends readable storage for the call; bounds/nulls checked.
    Ok(unsafe { input(value.pointer, value.length) })
}
unsafe fn text(value: Span, remaining: &mut usize) -> Result<String, Failure> {
    // SAFETY: The entry point's borrowed storage contract is checked by bytes.
    let bytes = unsafe { bytes(value, *remaining)? };
    *remaining -= bytes.len();
    String::from_utf8(bytes.to_vec()).map_err(|_| Failure::new("invalid_command"))
}
unsafe fn fields(
    pointer: *const Field,
    count: usize,
    remaining: &mut usize,
) -> Result<Vec<Header>, Failure> {
    if count > 256 || (pointer.is_null() && count != 0) {
        return Err(Failure::new("input_limit"));
    }
    let values = if count == 0 {
        &[]
    } else {
        // SAFETY: The caller supplies count aligned Field values for this call.
        unsafe { slice::from_raw_parts(pointer, count) }
    };
    values
        .iter()
        .map(|field| {
            if field.sensitive > 1 {
                return Err(Failure::new("invalid_command"));
            }
            // SAFETY: Nested spans follow the same call-scoped input contract.
            let name = unsafe { text(field.name, remaining)? };
            // SAFETY: Nested spans follow the same call-scoped input contract.
            let value = unsafe { bytes(field.value, *remaining)? }.to_vec();
            *remaining -= value.len();
            Ok(Header {
                name,
                value,
                sensitive: field.sensitive != 0,
            })
        })
        .collect()
}
fn timeout(value: Timeout) -> Result<timeouts::Timeout, Failure> {
    match value.mode {
        0 if value.nanoseconds == 0 => Ok(timeouts::Timeout::Inherit {}),
        1 if value.nanoseconds == 0 => Ok(timeouts::Timeout::Disabled {}),
        2 => Ok(timeouts::Timeout::Limit {
            nanoseconds: value.nanoseconds,
        }),
        _ => Err(Failure::new("invalid_timeout")),
    }
}
unsafe fn retries(pointer: *const Retry) -> Result<Option<retry::RetryPolicy>, Failure> {
    if pointer.is_null() {
        return Ok(None);
    }
    // SAFETY: Non-null input points to one aligned call-scoped Retry value.
    let value = unsafe { &*pointer };
    let flags = value.flags;
    if flags & !2047 != 0
        || value.status_count > 7
        || (value.statuses.is_null() && value.status_count != 0)
    {
        return Err(Failure::new("invalid_retry_policy"));
    }
    let statuses = if value.status_count == 0 {
        Vec::new()
    } else {
        // SAFETY: The caller lends the bounded statuses array during this call.
        unsafe { slice::from_raw_parts(value.statuses, value.status_count) }.to_vec()
    };
    Ok(Some(retry::RetryPolicy {
        connection: (flags & 1 != 0).then_some(retry::ConnectionRetry {
            maximum: value.connection_maximum,
            delay_ns: value.connection_delay,
            maximum_delay_ns: (flags & 2 != 0).then_some(value.connection_maximum_delay),
            full_jitter: flags & 4 != 0,
        }),
        status: (flags & 8 != 0).then_some(retry::StatusRetry {
            statuses,
            maximum: value.status_maximum,
            delay_ns: value.status_delay,
            maximum_delay_ns: (flags & 16 != 0).then_some(value.status_maximum_delay),
            full_jitter: flags & 32 != 0,
            retry_after_limit_ns: (flags & 64 != 0).then_some(value.retry_after),
        }),
        reused_connection_replay: flags & 128 != 0,
        unprocessed_replays: (flags & 256 != 0).then_some(value.unprocessed),
        maximum_retries: (flags & 512 != 0).then_some(value.maximum),
        http2_fallback: flags & 1024 != 0,
    }))
}
unsafe fn request(value: &Request) -> Result<Command, Failure> {
    if value.flags & !31 != 0
        || value.trailer_count > 256
        || value.header_count > 256 - value.trailer_count
        || value.credential_header_count > 256
        || (value.credential_headers.is_null() && value.credential_header_count != 0)
    {
        return Err(Failure::new("input_limit"));
    }
    let mut remaining = operations::MAX_COMMAND;
    // SAFETY: Every nested span is lent only for this call; helpers copy it.
    let (method, url, headers, trailers) = unsafe {
        (
            text(value.method, &mut remaining)?,
            text(value.url, &mut remaining)?,
            fields(value.headers, value.header_count, &mut remaining)?,
            fields(value.trailers, value.trailer_count, &mut remaining)?,
        )
    };
    let credentials = if value.credential_header_count == 0 {
        &[]
    } else {
        // SAFETY: The caller supplies the bounded aligned span array for the call.
        unsafe { slice::from_raw_parts(value.credential_headers, value.credential_header_count) }
    };
    let credential_headers = credentials
        .iter()
        .map(|span| {
            // SAFETY: text validates/copies this call-scoped nested span.
            unsafe { text(*span, &mut remaining) }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Command::Request {
        client: value.client,
        method,
        url,
        headers,
        trailers,
        expect_continue_nanoseconds: (value.flags & 2 != 0).then_some(value.expect_continue),
        budget: (value.budget != 0).then_some(value.budget),
        transfer: (value.transfer != 0).then_some(value.transfer),
        diagnostics: (value.diagnostics != 0).then_some(value.diagnostics),
        timeouts: timeouts::Timeouts {
            pool_admission: timeout(value.timeouts[0])?,
            connect: timeout(value.timeouts[1])?,
            response_head: timeout(value.timeouts[2])?,
            read_idle: timeout(value.timeouts[3])?,
            total: timeout(value.timeouts[4])?,
        },
        content_decoding: if value.flags & 4 != 0 {
            policy::ContentDecoding::Advertised {
                maximum_decoded_bytes: value.decoded_maximum,
            }
        } else {
            policy::ContentDecoding::None {}
        },
        redirect_policy: (value.flags & 8 != 0).then_some(policy::RedirectPolicy {
            maximum_hops: value.redirect_maximum,
            credential_headers,
        }),
        redirect_history_limit: (value.flags & 16 != 0).then_some(value.redirect_history),
        // SAFETY: Optional retry input is copied before returning from this call.
        retry_policy: unsafe { retries(value.retry)? },
        has_body: value.flags & 1 != 0,
        prepared_body: (value.prepared_body != 0).then_some(value.prepared_body),
        upload: (value.upload != 0).then_some(value.upload),
    })
}
fn submitted(result: Result<operations::Execution, Failure>) -> Reply {
    match result {
        Ok(operations::Execution::Operation(operation)) => Reply {
            operation,
            error: Error::default(),
        },
        Ok(operations::Execution::Complete) => Reply::default(),
        Ok(operations::Execution::Json(_)) => Reply {
            operation: 0,
            error: Failure::new("internal").into(),
        },
        Err(error) => Reply {
            operation: 0,
            error: error.into(),
        },
    }
}

// SAFETY: The caller lends a valid aligned request, bounded body and writable
// reply. Nested request storage is copied before asynchronous work is admitted.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_request(
    value: *const Request,
    body: *const u8,
    length: usize,
    reply: *mut Reply,
) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller lends one aligned Request for this call.
        let command = unsafe { request(&*value)? };
        // SAFETY: bytes validates null/length and the caller's readable storage.
        let body = unsafe {
            bytes(
                Span {
                    pointer: body,
                    length,
                },
                operations::MAX_UPLOAD,
            )?
        };
        operations::execute(command, body)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller lends one writable aligned Reply and no pointer escapes.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: Data is borrowed only for this call; reply is one writable aligned
// value. Only owned commands/bytes reach the runtime and its tasks.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_operation(
    kind: u64,
    id: u64,
    argument: u64,
    data: *const u8,
    length: usize,
    reply: *mut Reply,
) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let command = match kind {
            1 => Command::Read {
                body: id,
                maximum: usize::try_from(argument).map_err(|_| Failure::new("chunk_size"))?,
            },
            2 if argument <= 2 => Command::WriteUpload {
                upload: id,
                end: (argument != 0).then_some(argument == 2),
            },
            3 => Command::WaitUpload { upload: id },
            4 => Command::WaitUploadPart { upload: id },
            5 => Command::Cancel { operation: id },
            6 => Command::Ack { operation: id },
            7 => Command::CloseBody { body: id },
            8 => Command::CloseUpload { upload: id },
            _ => return Err(Failure::new("invalid_command")),
        };
        // SAFETY: bytes validates null/length under the call-scoped contract.
        let data = unsafe {
            bytes(
                Span {
                    pointer: data,
                    length,
                },
                operations::MAX_UPLOAD,
            )?
        };
        operations::execute(command, data)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller supplies one aligned writable Reply.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

struct Arena<'a> {
    bytes: &'a mut [u8],
    used: usize,
}
impl Arena<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<Slice, Failure> {
        let end = self
            .used
            .checked_add(bytes.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| Failure::new("metadata_limit"))?;
        self.bytes[self.used..end].copy_from_slice(bytes);
        let span = Slice {
            offset: self.used as u64,
            length: bytes.len() as u64,
        };
        self.used = end;
        Ok(span)
    }
    fn fields(&mut self, input: &[Header], output: &mut [OutputField]) -> Result<u64, Failure> {
        if input.len() > output.len() {
            return Err(Failure::new("metadata_limit"));
        }
        for (source, target) in input.iter().zip(output) {
            *target = OutputField {
                name: self.put(source.name.as_bytes())?,
                value: self.put(&source.value)?,
                sensitive: u64::from(source.sensitive),
            };
        }
        Ok(input.len() as u64)
    }
}

// SAFETY: All output buffers are caller-owned, aligned, writable and mutually
// nonoverlapping for the whole blocking call. No pointer is retained afterward.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_wait_event(
    event: *mut Event,
    fields: *mut OutputField,
    field_capacity: usize,
    hops: *mut Hop,
    hop_capacity: usize,
    arena: *mut u8,
    arena_capacity: usize,
    data: *mut u8,
    data_capacity: usize,
) -> u64 {
    if event.is_null()
        || fields.is_null()
        || hops.is_null()
        || arena.is_null()
        || data.is_null()
        || field_capacity != operations::MAX_METADATA / size_of::<OutputField>()
        || hop_capacity != operations::MAX_METADATA / size_of::<Hop>()
        || arena_capacity != operations::MAX_METADATA
        || data_capacity != operations::MAX_CHUNK
    {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let completion = operations::wait()?;
        let mut result = Event {
            operation: completion.operation,
            data_length: completion.data.len() as u64,
            ..Event::default()
        };
        // SAFETY: Capacities/nulls checked above; caller guarantees writable arrays.
        let (fields, hops, bytes) = unsafe {
            (
                slice::from_raw_parts_mut(fields, field_capacity),
                slice::from_raw_parts_mut(hops, hop_capacity),
                slice::from_raw_parts_mut(arena, arena_capacity),
            )
        };
        let mut arena = Arena { bytes, used: 0 };
        let projection = (|| {
            match completion.result {
                Err(error) => result.error = error.into(),
                Ok(Completed::Complete) => result.kind = 1,
                Ok(Completed::Data) => result.kind = 2,
                Ok(Completed::End(trailers)) => {
                    result.kind = 3;
                    result.trailer_state = match trailers.state {
                        "complete" => 1,
                        "unavailable" => 2,
                        _ => return Err(Failure::new("unsupported_response_trailers")),
                    };
                    result.field_count = arena.fields(&trailers.headers, fields)?;
                }
                Ok(Completed::Part(part)) => {
                    result.kind = 4;
                    result.part = part as u64;
                }
                Ok(Completed::Head(head)) => {
                    result.kind = 5;
                    result.body = head.body;
                    result.status = u64::from(head.status);
                    result.protocol = match head.protocol {
                        "h1" => 1,
                        "h2" => 2,
                        "h3" => 3,
                        _ => return Err(Failure::new("native_abi")),
                    };
                    result.effective_url = arena.put(head.effective_url.as_bytes())?;
                    result.redirects = head.redirects_followed as u64;
                    result.setup_retries = head.connection_setup_retries as u64;
                    result.field_count = arena.fields(&head.headers, fields)?;
                    if head.decoded_content_codings.len() > fields.len() - head.headers.len() {
                        return Err(Failure::new("metadata_limit"));
                    }
                    result.coding_count = head.decoded_content_codings.len() as u64;
                    for (name, field) in head
                        .decoded_content_codings
                        .iter()
                        .zip(&mut fields[head.headers.len()..])
                    {
                        *field = OutputField {
                            name: arena.put(name.as_bytes())?,
                            ..OutputField::default()
                        };
                    }
                    if let Some(history) = head.redirect_history {
                        if history.entries.len() > hops.len() {
                            return Err(Failure::new("metadata_limit"));
                        }
                        result.history_present = 1;
                        result.history_omitted = history.omitted_hops as u64;
                        result.hop_count = history.entries.len() as u64;
                        for (source, target) in history.entries.iter().zip(hops) {
                            *target = Hop {
                                from: arena.put(source.from_url.as_bytes())?,
                                to: arena.put(source.to_url.as_bytes())?,
                                method: arena.put(source.method.as_bytes())?,
                                next_method: arena.put(source.next_method.as_bytes())?,
                                status: u64::from(source.status),
                            };
                        }
                    }
                }
            }
            Ok::<_, Failure>(())
        })();
        if let Err(error) = projection {
            let error = operations::discard_response(completion.operation)
                .err()
                .unwrap_or(error);
            result.error = error.into();
            result.data_length = 0;
        }
        result.arena_length = arena.used as u64;
        if result.error.kind[0] == 0 {
            // SAFETY: The task's data is <=MAX_CHUNK and caller capacity is checked.
            unsafe {
                output(data, &completion.data);
            }
        }
        Ok::<_, Failure>(result)
    }));
    let result = match result {
        Ok(Ok(result)) => result,
        _ => return 0,
    };
    // SAFETY: Caller supplies one aligned writable Event for the complete call.
    unsafe {
        ptr::write(event, result);
    }
    1
}
