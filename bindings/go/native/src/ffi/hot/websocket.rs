//! Optional WebSocket ABI 1; ordinary HTTP and SSE layouts are unchanged.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    time::Duration,
};

use super::{Error, Field, Reply, Span, Timeout, bytes, fields, submitted, text};
use crate::{
    error::Failure,
    operations::{self, websocket},
};

#[repr(C)]
struct TemplateField {
    kind: u64,
    field: Field,
}
#[repr(C)]
struct DeflateParameter {
    kind: u64,
    bits: u64,
}
#[repr(C)]
struct Deflate {
    parameters: *const DeflateParameter,
    count: usize,
    flags: u64,
    window: u64,
    level: u64,
}
#[repr(C)]
struct Opening {
    client: u64,
    url: Span,
    protocol: u64,
    headers: *const Field,
    header_count: usize,
    template: *const TemplateField,
    template_count: usize,
    template_present: u64,
    frame: u64,
    message: u64,
    fragments: u64,
    timeout: Timeout,
    retries: u64,
    retry_delay: u64,
    deflate: *const Deflate,
}
#[repr(C)]
#[derive(Default)]
struct Message {
    kind: u64,
    length: u64,
    code: u64,
    compression: u64,
    server_window: u64,
    client_window: u64,
    error: Error,
}

// SAFETY: This pointer-free symbol negotiates the independently versioned ABI.
#[unsafe(no_mangle)]
extern "C" fn phantom_go_websocket_version() -> u64 {
    1
}

// SAFETY: All spans are call-scoped and bounded. The write path copies message
// bytes before admission; read/abort require empty bytes. No pointer is retained.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_websocket_operation(
    verb: u64,
    socket: u64,
    kind: u64,
    code: u64,
    input: *const u8,
    length: usize,
    reply: *mut Reply,
) -> u64 {
    if reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: bytes validates the caller's readable bounded span.
        let input = unsafe {
            bytes(
                Span {
                    pointer: input,
                    length,
                },
                websocket::MAX_MESSAGE,
            )?
        };
        match verb {
            1 if input.is_empty() && kind == 0 && code == 0 => websocket::read(socket),
            2 => websocket::write(
                socket,
                kind,
                u16::try_from(code).map_err(|_| Failure::new("invalid_websocket_close"))?,
                input,
            ),
            3 if input.is_empty() && kind == 0 && code == 0 => websocket::abort(socket),
            _ => Err(Failure::new("invalid_websocket_operation")),
        }
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller lends an aligned writable Reply.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: The caller lends a writable descriptor and disjoint writable buffer.
// Capacity zero probes exact length. The result remains operation-owned through
// ack/cancel; an Arc holds it during this synchronous copy.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_websocket_result(
    operation: u64,
    message: *mut Message,
    output: *mut u8,
    capacity: usize,
) -> u64 {
    if message.is_null() || (output.is_null() && capacity != 0) || capacity > websocket::MAX_MESSAGE
    {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let value = websocket::result(operation)?;
        if value.bytes.len() > websocket::MAX_MESSAGE
            || (capacity != 0 && capacity < value.bytes.len())
        {
            return Err(Failure::new("websocket_result_capacity"));
        }
        if capacity != 0 {
            // SAFETY: The checked output capacity covers this owned byte slice.
            unsafe {
                super::super::output(output, &value.bytes);
            }
        }
        Ok(Message {
            kind: value.kind,
            length: value.bytes.len() as u64,
            code: value.code,
            compression: value.compression[0],
            server_window: value.compression[1],
            client_window: value.compression[2],
            error: Error::default(),
        })
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    let result = result.unwrap_or_else(|error| Message {
        error: error.into(),
        ..Message::default()
    });
    // SAFETY: One aligned writable result descriptor is lent for this call.
    unsafe {
        ptr::write(message, result);
    }
    1
}

unsafe fn deflate(value: *const Deflate) -> Result<Option<phantom::PerMessageDeflate>, Failure> {
    use phantom::PerMessageDeflateOfferParameter as Parameter;
    if value.is_null() {
        return Ok(None);
    }
    // SAFETY: The entry point lends one aligned descriptor for this call.
    let value = unsafe { &*value };
    if value.flags & !3 != 0
        || value.count > 4
        || (value.count != 0 && value.parameters.is_null())
        || (value.flags & 1 == 0 && value.count != 0)
    {
        return Err(Failure::new("invalid_websocket_deflate"));
    }
    let mut policy = phantom::PerMessageDeflate::new()
        .client_max_window_bits(
            u8::try_from(value.window).map_err(|_| Failure::new("invalid_websocket_deflate"))?,
        )
        .map_err(|_| Failure::new("invalid_websocket_deflate"))?
        .compression_level(
            u8::try_from(value.level).map_err(|_| Failure::new("invalid_websocket_deflate"))?,
        )
        .map_err(|_| Failure::new("invalid_websocket_deflate"))?
        .compress_empty_messages(value.flags & 2 != 0);
    if value.flags & 1 != 0 {
        let parameters = if value.count == 0 {
            &[]
        } else {
            // SAFETY: The caller lends the bounded aligned parameter array.
            unsafe { slice::from_raw_parts(value.parameters, value.count) }
        };
        let parameters = parameters
            .iter()
            .map(|parameter| {
                Ok(match (parameter.kind, parameter.bits) {
                    (1, 0) => Parameter::ServerNoContextTakeover,
                    (2, 0) => Parameter::ClientNoContextTakeover,
                    (3, bits @ 8..=15) => Parameter::ServerMaxWindowBits(bits as u8),
                    (4, 0) => Parameter::ClientMaxWindowBits(None),
                    (4, bits @ 8..=15) => Parameter::ClientMaxWindowBits(Some(bits as u8)),
                    _ => return Err(Failure::new("invalid_websocket_deflate")),
                })
            })
            .collect::<Result<Vec<_>, Failure>>()?;
        policy = policy
            .offer_parameters(parameters)
            .map_err(|_| Failure::new("invalid_websocket_deflate"))?;
    }
    Ok(Some(policy))
}

unsafe fn opening(value: &Opening) -> Result<websocket::Opening, Failure> {
    if value.template_present > 1
        || value.header_count > 256
        || value.template_count > 256 - value.header_count
        || (value.template_present == 0 && value.template_count != 0)
        || (value.template_count != 0 && value.template.is_null())
    {
        return Err(Failure::new("input_limit"));
    }
    let mut remaining = operations::MAX_COMMAND;
    // SAFETY: All nested spans are validated and copied during this call.
    let (url, headers) = unsafe {
        (
            text(value.url, &mut remaining)?,
            fields(value.headers, value.header_count, &mut remaining)?,
        )
    };
    let template = if value.template_present == 0 {
        None
    } else {
        let values = if value.template_count == 0 {
            &[]
        } else {
            // SAFETY: The caller lends the bounded aligned template array.
            unsafe { slice::from_raw_parts(value.template, value.template_count) }
        };
        Some(
            values
                .iter()
                .map(|entry| {
                    // SAFETY: Each nested Field is checked and copied by fields.
                    let field = unsafe { fields(&entry.field, 1, &mut remaining)? }
                        .into_iter()
                        .next()
                        .ok_or_else(|| Failure::new("internal"))?;
                    if !matches!(entry.kind, 5 | 6) && (!field.value.is_empty() || field.sensitive)
                    {
                        return Err(Failure::new("invalid_websocket_template"));
                    }
                    Ok(match entry.kind {
                        1 => phantom::WebSocketHeader::authority(field.name),
                        2 => phantom::WebSocketHeader::key(field.name),
                        3 => phantom::WebSocketHeader::client_cookies(field.name),
                        4 => phantom::WebSocketHeader::caller_field(field.name),
                        5 => phantom::WebSocketHeader::field(field.into_request()),
                        6 => phantom::WebSocketHeader::default_field(field.into_request()),
                        7 => phantom::WebSocketHeader::permessage_deflate(field.name),
                        _ => return Err(Failure::new("invalid_websocket_template")),
                    })
                })
                .collect::<Result<Vec<_>, Failure>>()?,
        )
    };
    let timeout = match (value.timeout.mode, value.timeout.nanoseconds) {
        (0, 0) => None,
        (1, 0) => Some(None),
        (2, nanos) => Some(Some(Duration::from_nanos(nanos))),
        _ => return Err(Failure::new("invalid_timeout")),
    };
    // SAFETY: Optional compression storage is borrowed and copied here.
    let deflate = unsafe { deflate(value.deflate)? };
    Ok(websocket::Opening {
        client: value.client,
        url,
        protocol: value.protocol,
        headers,
        template,
        limits: websocket::limits(value.frame, value.message, value.fragments)?,
        timeout,
        retries: usize::try_from(value.retries)
            .map_err(|_| Failure::new("invalid_websocket_retry"))?,
        retry_delay: Duration::from_nanos(value.retry_delay),
        deflate,
    })
}

// SAFETY: The caller lends one aligned opening descriptor and writable reply;
// every nested byte/field/parameter input is copied before async admission.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_websocket_open(value: *const Opening, reply: *mut Reply) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller lends one aligned Opening, decoded synchronously.
        websocket::open(unsafe { opening(&*value)? })
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller lends an aligned writable Reply.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(url: &[u8]) -> Opening {
        Opening {
            client: 1,
            url: Span {
                pointer: url.as_ptr(),
                length: url.len(),
            },
            protocol: 0,
            headers: ptr::null(),
            header_count: 0,
            template: ptr::null(),
            template_count: 0,
            template_present: 0,
            frame: 16 * 1024 * 1024,
            message: 64 * 1024 * 1024,
            fragments: 131_072,
            timeout: Timeout {
                mode: 0,
                nanoseconds: 0,
            },
            retries: 0,
            retry_delay: 0,
            deflate: ptr::null(),
        }
    }

    #[test]
    fn opening_owns_nested_input_before_asynchronous_admission() -> Result<(), Failure> {
        let mut url = b"wss://example.test/socket".to_vec();
        let mut binary = vec![255, 0, 1];
        let fields = [Field {
            name: Span {
                pointer: b"X-Token".as_ptr(),
                length: 7,
            },
            value: Span {
                pointer: binary.as_ptr(),
                length: binary.len(),
            },
            sensitive: 1,
        }];
        let mut value = wire(&url);
        value.headers = fields.as_ptr();
        value.header_count = fields.len();
        // SAFETY: All nested storage is valid for this synchronous conversion.
        let owned = unsafe { opening(&value)? };
        url.fill(b'x');
        binary.fill(0);
        assert_eq!(owned.url, "wss://example.test/socket");
        assert_eq!(owned.headers[0].name, "X-Token");
        assert_eq!(owned.headers[0].value, [255, 0, 1]);
        assert!(owned.headers[0].sensitive);
        Ok(())
    }

    #[test]
    fn malformed_foreign_arrays_are_rejected_before_access() {
        let mut value = wire(b"wss://example.test/");
        value.template_present = 1;
        value.template_count = 1;
        // SAFETY: A null nonempty array is rejected before forming a slice.
        assert_eq!(
            unsafe { opening(&value) }.err().map(|error| error.kind),
            Some("input_limit")
        );
        let policy = Deflate {
            parameters: ptr::null(),
            count: 1,
            flags: 1,
            window: 15,
            level: 6,
        };
        // SAFETY: The bounded descriptor is valid; its null array is rejected.
        assert_eq!(
            unsafe { deflate(&policy) }.err().map(|error| error.kind),
            Some("invalid_websocket_deflate")
        );
    }
}
