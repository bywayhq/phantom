//! Opt-in TLS key logging for debugging a caller's own connections.

use std::{
    fmt,
    io::{self, Write},
    sync::{Mutex, PoisonError},
};

use phantom_net::NssKeyLogReceiver;

/// Queued TLS secrets of a client's connections, in NSS key log format.
///
/// This is the format `SSLKEYLOGFILE` uses and Wireshark reads. Enable it with
/// [`ClientBuilder::key_log`](crate::ClientBuilder::key_log) and read it with
/// [`Client::key_log`](crate::Client::key_log).
///
/// The lines are the TLS 1.3 traffic secrets of the client's TCP and QUIC
/// handshakes. Anyone who holds them can decrypt a capture of those
/// connections. Use a key log only to debug your own connections, and store
/// it as carefully as a private key.
pub struct KeyLog {
    receiver: Mutex<NssKeyLogReceiver>,
}

impl KeyLog {
    pub(crate) fn new(receiver: NssKeyLogReceiver) -> Self {
        Self {
            receiver: Mutex::new(receiver),
        }
    }

    /// Writes every queued line to `writer` and returns how many were written.
    ///
    /// Handshakes never wait for this call. Append the result to a file
    /// named by Wireshark's "(Pre)-Master-Secret log filename" setting.
    ///
    /// # Errors
    ///
    /// Returns the first error from `writer`. The line that failed is lost;
    /// later lines stay queued.
    pub fn write_pending(&self, writer: &mut impl Write) -> io::Result<usize> {
        self.receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_pending_nss(writer)
    }

    /// Returns how many lines were dropped: lines that found the queue full,
    /// and TLS 1.2 secrets, which are not logged.
    #[must_use]
    pub fn dropped_line_count(&self) -> usize {
        self.receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dropped_line_count()
    }
}

impl fmt::Debug for KeyLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyLog")
            .field("dropped_line_count", &self.dropped_line_count())
            .finish_non_exhaustive()
    }
}
