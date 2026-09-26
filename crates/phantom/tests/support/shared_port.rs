//! Loopback port numbers for an origin that serves TCP and UDP on one port.
//!
//! Such an origin binds one protocol and then the other at the same port
//! number, so neither bind can use port 0 on its own. Binding UDP to port 0
//! and TCP to whatever port it got does not work on Windows: UDP ephemeral
//! ports there are handed out in sequence, so while the host's counter walks
//! through a block that Windows reserves for TCP
//! (`netsh int ipv4 show excludedportrange protocol=tcp`), every retry gets
//! the next port of the same block and the TCP bind fails with `WSAEACCES`
//! (os error 10013) each time.

use std::{
    io,
    sync::atomic::{AtomicU32, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// The first candidate port.
const FIRST: u32 = 20_000;
/// How many ports the candidates span. The span ends below 49152, where the
/// dynamic range starts on Windows and Linux: under a full workspace test
/// run, TCP clients leave many `TIME_WAIT` sockets on dynamic ports, and
/// binding a listener there fails with `AddrInUse`.
const SPAN: u32 = 29_000;
/// The distance between consecutive candidates. It is prime and does not
/// divide `SPAN`, so the candidates visit every port of the span before one
/// repeats.
const STRIDE: u32 = 7_919;
/// How many candidates one call offers.
const ATTEMPTS: usize = 256;

/// Returns candidate port numbers for a TCP and UDP origin, in an order that
/// differs between processes and between calls.
///
/// A candidate may be in use or reserved by the host. Try the next one when
/// a bind fails with an error for which [`is_unavailable`] returns `true`.
pub(crate) fn candidates() -> impl Iterator<Item = u16> {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos())
        ^ std::process::id();
    (0..ATTEMPTS).filter_map(move |_| {
        let step = NEXT.fetch_add(1, Ordering::Relaxed) % SPAN;
        let offset = (seed % SPAN + step * STRIDE % SPAN) % SPAN;
        // Always a port number: the span ends below 49152.
        u16::try_from(FIRST + offset).ok()
    })
}

/// Returns whether a bind failed because another socket holds the port or
/// the host reserves it (`WSAEACCES` on Windows).
pub(crate) fn is_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
    )
}
