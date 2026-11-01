//! Optional typed state transfer ABI 1. Every foreign input is call-borrowed.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

use zeroize::Zeroizing;

use super::{Error, Reply, Span, bytes, submitted, text};
use crate::{
    client,
    error::Failure,
    operations,
    state_transfer::{self, Alternative, Cookie, Input},
};

#[repr(C)]
struct Route {
    proxy: Span,
    username: Span,
    password: Span,
    credentials: u64,
}

#[repr(C)]
struct Transfer {
    client: u64,
    kind: u64,
    cookies: *const Cookie,
    cookie_count: usize,
    alternatives: *const Alternative,
    alternative_count: usize,
    arena: Span,
    key: Span,
    routes: *const Route,
    route_count: usize,
}

#[repr(C)]
#[derive(Default)]
struct ResultData {
    kind: u64,
    enabled: u64,
    cookie_count: u64,
    alternative_count: u64,
    arena_length: u64,
    // Zero means absent; otherwise the one-based failing entry index.
    entry: u64,
    error: Error,
}

// SAFETY: This scalar-only negotiation retains no caller storage.
#[unsafe(no_mangle)]
extern "C" fn phantom_go_state_transfer_version() -> u64 {
    1
}

// SAFETY: The entry point lends all descriptors and their spans for this call.
// This function copies strings, ciphertext and key before any task admission.
unsafe fn decode(value: &Transfer) -> Result<Input, Failure> {
    if value.cookie_count > state_transfer::MAX_COOKIES
        || value.alternative_count > state_transfer::MAX_ALTERNATIVES
        || value.route_count > 256
        || (value.cookie_count != 0 && value.cookies.is_null())
        || (value.alternative_count != 0 && value.alternatives.is_null())
        || (value.route_count != 0 && value.routes.is_null())
        || (!matches!(value.kind, 2) && value.cookie_count != 0)
        || (!matches!(value.kind, 4) && value.alternative_count != 0)
        || (value.kind != 6 && value.route_count != 0)
        || (!matches!(value.kind, 2 | 4 | 6) && value.arena.length != 0)
        || (!matches!(value.kind, 5 | 6) && value.key.length != 0)
    {
        return Err(Failure::new("invalid_state_snapshot"));
    }
    let maximum = if value.kind == 6 {
        state_transfer::MAX_TICKETS
    } else {
        state_transfer::MAX_TEXT
    };
    // SAFETY: The caller supplies the bounded readable byte spans.
    let arena = unsafe { bytes(value.arena, maximum)? };
    match value.kind {
        1 => Ok(Input::ExportCookies),
        2 => {
            let rows = if value.cookie_count == 0 {
                &[]
            } else {
                // SAFETY: Count/null checked above; caller lends aligned rows.
                unsafe { slice::from_raw_parts(value.cookies, value.cookie_count) }
            };
            Ok(Input::ImportCookies(state_transfer::cookies(rows, arena)?))
        }
        3 => Ok(Input::ExportAltSvc),
        4 => {
            let rows = if value.alternative_count == 0 {
                &[]
            } else {
                // SAFETY: Count/null checked above; caller lends aligned rows.
                unsafe { slice::from_raw_parts(value.alternatives, value.alternative_count) }
            };
            Ok(Input::ImportAltSvc(state_transfer::alternatives(
                rows, arena,
            )?))
        }
        5 | 6 => {
            // SAFETY: Key is borrowed only for this synchronous exact-size copy.
            let secret = unsafe { bytes(value.key, 32)? };
            let mut key = Zeroizing::new([0; 32]);
            if secret.len() != key.len() {
                return Err(Failure::new("invalid_session_key"));
            }
            key.copy_from_slice(secret);
            if value.kind == 5 {
                return Ok(Input::ExportTickets(key));
            }
            let snapshot = phantom::SessionTicketSnapshot::from_bytes(arena)
                .map_err(|error| state_transfer::ticket_error(error.kind()))?;
            let rows = if value.route_count == 0 {
                &[]
            } else {
                // SAFETY: Count/null checked above; caller lends aligned routes.
                unsafe { slice::from_raw_parts(value.routes, value.route_count) }
            };
            let mut remaining = operations::MAX_COMMAND;
            let mut routes = Vec::with_capacity(rows.len());
            for row in rows {
                if row.credentials > 1 {
                    return Err(Failure::new("invalid_proxy_credentials"));
                }
                // SAFETY: Each nested span remains readable through this call.
                let (proxy, username, password) = unsafe {
                    (
                        text(row.proxy, &mut remaining)?,
                        text(row.username, &mut remaining)?,
                        text(row.password, &mut remaining)?,
                    )
                };
                if row.credentials == 0 && (!username.is_empty() || !password.is_empty()) {
                    return Err(Failure::new("invalid_proxy_credentials"));
                }
                let credentials = (row.credentials == 1)
                    .then(|| client::ProxyCredentials::new(username, password));
                routes.push(client::route(
                    (!proxy.is_empty()).then_some(proxy.as_str()),
                    credentials,
                )?);
            }
            Ok(Input::ImportTickets(snapshot, key, routes))
        }
        _ => Err(Failure::new("invalid_command")),
    }
}

// SAFETY: Value and reply are aligned readable/writable descriptors; nested
// input is copied synchronously. No Go pointer survives the call.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_state_transfer_submit(
    value: *const Transfer,
    reply: *mut Reply,
) -> u64 {
    if value.is_null() || reply.is_null() {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: One complete Transfer descriptor is borrowed for this call.
        let value = unsafe { &*value };
        // SAFETY: Nested storage follows this entry point's readable contract.
        operations::state_transfer::submit(value.client, unsafe { decode(value)? })
            .map(operations::Execution::Operation)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    // SAFETY: The caller supplies one aligned writable reply.
    unsafe {
        ptr::write(reply, submitted(result));
    }
    1
}

// SAFETY: All outputs are disjoint, aligned writable storage of stated capacity.
// Zero capacities probe; the operation retains immutable payload until ack.
#[unsafe(no_mangle)]
unsafe extern "C" fn phantom_go_state_transfer_result(
    operation: u64,
    value: *mut ResultData,
    cookies: *mut Cookie,
    cookie_capacity: usize,
    alternatives: *mut Alternative,
    alternative_capacity: usize,
    arena: *mut u8,
    arena_capacity: usize,
) -> u64 {
    if value.is_null()
        || cookie_capacity > state_transfer::MAX_COOKIES
        || alternative_capacity > state_transfer::MAX_ALTERNATIVES
        || arena_capacity > state_transfer::MAX_TEXT
        || (cookie_capacity != 0 && cookies.is_null())
        || (alternative_capacity != 0 && alternatives.is_null())
        || (arena_capacity != 0 && arena.is_null())
    {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut value = ResultData::default();
        match operations::state_transfer::result(operation) {
            Err(error) => value.error = error.into(),
            Ok(result) => {
                value.kind = result.kind;
                value.enabled = u64::from(result.enabled);
                value.cookie_count = result.cookies.len() as u64;
                value.alternative_count = result.alternatives.len() as u64;
                value.arena_length = result.arena.len() as u64;
                value.entry = result.entry.map_or(0, |entry| entry as u64 + 1);
                if let Some(error) = &result.error {
                    value.error = error.clone().into();
                }
                let probe =
                    cookie_capacity == 0 && alternative_capacity == 0 && arena_capacity == 0;
                if !probe {
                    if cookie_capacity != result.cookies.len()
                        || alternative_capacity != result.alternatives.len()
                        || arena_capacity != result.arena.len()
                    {
                        return Err(Failure::new("native_abi"));
                    }
                    // SAFETY: Nonzero destinations were checked above and each
                    // exact capacity matches the owned immutable source length.
                    unsafe {
                        if cookie_capacity != 0 {
                            ptr::copy_nonoverlapping(
                                result.cookies.as_ptr(),
                                cookies,
                                cookie_capacity,
                            );
                        }
                        if alternative_capacity != 0 {
                            ptr::copy_nonoverlapping(
                                result.alternatives.as_ptr(),
                                alternatives,
                                alternative_capacity,
                            );
                        }
                        if arena_capacity != 0 {
                            ptr::copy_nonoverlapping(result.arena.as_ptr(), arena, arena_capacity);
                        }
                    }
                }
            }
        }
        Ok::<_, Failure>(value)
    }))
    .unwrap_or_else(|_| Err(Failure::new("internal")));
    let result = match result {
        Ok(value) => value,
        Err(error) => ResultData {
            error: error.into(),
            ..ResultData::default()
        },
    };
    // SAFETY: The caller lends one aligned writable result descriptor.
    unsafe {
        ptr::write(value, result);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_state_submission_copies_cookie_text_and_secret_before_admission() -> Result<(), Failure>
    {
        let mut arena = b"idsecret.example/".to_vec();
        let row = Cookie {
            name: state_transfer::Text {
                offset: 0,
                length: 2,
            },
            value: state_transfer::Text {
                offset: 2,
                length: 6,
            },
            domain: state_transfer::Text {
                offset: 8,
                length: 8,
            },
            path: state_transfer::Text {
                offset: 16,
                length: 1,
            },
            flags: 1,
            source_scheme: 2,
            ..Cookie::default()
        };
        let mut value = Transfer {
            client: 1,
            kind: 2,
            cookies: &row,
            cookie_count: 1,
            alternatives: ptr::null(),
            alternative_count: 0,
            arena: Span {
                pointer: arena.as_ptr(),
                length: arena.len(),
            },
            key: Span {
                pointer: ptr::null(),
                length: 0,
            },
            routes: ptr::null(),
            route_count: 0,
        };
        // SAFETY: All descriptors and the complete arena are live and readable.
        let input = unsafe { decode(&value)? };
        arena.fill(b'x');
        let Input::ImportCookies(snapshot) = input else {
            return Err(Failure::new("test_input"));
        };
        assert_eq!(snapshot.entries()[0].value(), "secret");

        let mut key = [42; 32];
        value.kind = 5;
        value.cookies = ptr::null();
        value.cookie_count = 0;
        value.arena = Span {
            pointer: ptr::null(),
            length: 0,
        };
        value.key = Span {
            pointer: key.as_ptr(),
            length: key.len(),
        };
        // SAFETY: The key is readable for its exact span during this call.
        let input = unsafe { decode(&value)? };
        key.fill(0);
        let Input::ExportTickets(secret) = input else {
            return Err(Failure::new("test_input"));
        };
        assert!(secret.iter().all(|byte| *byte == 42));
        Ok(())
    }

    #[test]
    fn typed_state_layout_matches_supported_64_bit_go_abi() {
        assert_eq!(std::mem::size_of::<Cookie>(), 120);
        assert_eq!(std::mem::size_of::<Alternative>(), 56);
        assert_eq!(std::mem::size_of::<Transfer>(), 96);
        assert_eq!(std::mem::size_of::<ResultData>(), 240);
    }
}
