//! Bounded opt-in capture of BoringSSL's NSS-compatible TLS key log.

use std::fmt;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};

use btls::ssl::SslContextBuilder;
use zeroize::Zeroize;

// The longest accepted line is a 31-byte handshake-secret label, two
// separators, a 32-byte client random in hex, and a SHA-384 secret in hex.
const MAX_NSS_KEY_LOG_LINE_LEN: usize = 31 + 1 + 64 + 1 + 96;

/// One validated NSS key-log line containing TLS traffic secrets.
///
/// The line deliberately has no `Display`, `AsRef<str>`, or `Clone`
/// implementation. Writing its secret contents requires an explicit call to
/// [`Self::write_nss`]. Its fixed storage is cleared when dropped.
pub struct NssKeyLogLine {
    bytes: [u8; MAX_NSS_KEY_LOG_LINE_LEN],
    len: usize,
}

impl NssKeyLogLine {
    fn parse(line: &str) -> Option<Self> {
        if line.len() > MAX_NSS_KEY_LOG_LINE_LEN {
            return None;
        }

        let mut fields = line.split(' ');
        let label = fields.next()?;
        let client_random = fields.next()?;
        let secret = fields.next()?;
        if fields.next().is_some()
            || !is_quic_tls13_label(label)
            || client_random.len() != 64
            || !matches!(secret.len(), 64 | 96)
            || !is_hex(client_random)
            || !is_hex(secret)
        {
            return None;
        }

        let mut bytes = [0; MAX_NSS_KEY_LOG_LINE_LEN];
        bytes[..line.len()].copy_from_slice(line.as_bytes());
        Some(Self {
            bytes,
            len: line.len(),
        })
    }

    /// Writes this secret line followed by the newline required by NSS key-log files.
    ///
    /// This is the only operation that exposes the line contents. Call it only
    /// with a destination whose confidentiality matches that of live TLS keys.
    pub fn write_nss(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&self.bytes[..self.len])?;
        writer.write_all(b"\n")
    }
}

impl fmt::Debug for NssKeyLogLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NssKeyLogLine([REDACTED])")
    }
}

impl Zeroize for NssKeyLogLine {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}

impl Drop for NssKeyLogLine {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The receiving side of a bounded NSS key-log queue.
///
/// BoringSSL's callback never waits for this receiver. A line that cannot be
/// queued immediately is discarded and included in [`Self::dropped_line_count`].
pub struct NssKeyLogReceiver {
    receiver: Receiver<NssKeyLogLine>,
    dropped_lines: Arc<AtomicUsize>,
}

impl NssKeyLogReceiver {
    /// Attempts to receive one key-log line without waiting.
    pub fn try_recv(&self) -> Result<NssKeyLogLine, TryRecvError> {
        self.receiver.try_recv()
    }

    /// Returns the number of malformed or capacity-limited lines discarded so far.
    #[must_use]
    pub fn dropped_line_count(&self) -> usize {
        self.dropped_lines.load(Ordering::Relaxed)
    }

    /// Writes all currently queued lines in NSS key-log format without waiting for more.
    ///
    /// The supplied writer may itself block. It is used only by this explicit
    /// consumer-side operation and is never called from BoringSSL's callback.
    pub fn write_pending_nss(&self, writer: &mut impl Write) -> io::Result<usize> {
        let mut written = 0usize;
        loop {
            match self.try_recv() {
                Ok(line) => {
                    line.write_nss(writer)?;
                    written = written.saturating_add(1);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return Ok(written),
            }
        }
    }
}

impl fmt::Debug for NssKeyLogReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NssKeyLogReceiver")
            .field("dropped_line_count", &self.dropped_line_count())
            .finish_non_exhaustive()
    }
}

/// Installs bounded, nonblocking NSS key logging on a uniquely owned TLS context builder.
///
/// Key logging is disabled unless the crate's `keylog` feature is enabled and
/// this function is called before [`SslContextBuilder::build`]. The installed
/// callback owns the sending side of a queue with exactly `capacity` slots.
/// Full, disconnected, or malformed records are discarded rather than delaying
/// or failing a TLS handshake.
#[must_use]
pub fn configure_nss_key_log(
    builder: &mut SslContextBuilder,
    capacity: NonZeroUsize,
) -> NssKeyLogReceiver {
    let (sender, receiver) = mpsc::sync_channel(capacity.get());
    let dropped_lines = Arc::new(AtomicUsize::new(0));
    let callback_dropped_lines = Arc::clone(&dropped_lines);

    builder.set_keylog_callback(move |_ssl, line| {
        enqueue_key_log_line(&sender, &callback_dropped_lines, line);
    });

    NssKeyLogReceiver {
        receiver,
        dropped_lines,
    }
}

fn enqueue_key_log_line(
    sender: &SyncSender<NssKeyLogLine>,
    dropped_lines: &AtomicUsize,
    line: &str,
) {
    let Some(line) = NssKeyLogLine::parse(line) else {
        record_dropped_line(dropped_lines);
        return;
    };
    if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = sender.try_send(line) {
        record_dropped_line(dropped_lines);
    }
}

fn record_dropped_line(dropped_lines: &AtomicUsize) {
    let _ = dropped_lines.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(1))
    });
}

fn is_quic_tls13_label(label: &str) -> bool {
    matches!(
        label,
        "CLIENT_EARLY_TRAFFIC_SECRET"
            | "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
            | "SERVER_HANDSHAKE_TRAFFIC_SECRET"
            | "CLIENT_TRAFFIC_SECRET_0"
            | "SERVER_TRAFFIC_SECRET_0"
            | "EXPORTER_SECRET"
    )
}

fn is_hex(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use btls::ssl::{SslContext, SslMethod};

    const CLIENT_RANDOM: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const SHA256_SECRET: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    fn fixture(label: &str) -> String {
        format!("{label} {CLIENT_RANDOM} {SHA256_SECRET}")
    }

    #[test]
    fn line_writes_explicit_nss_record_and_redacts_debug() {
        let raw = fixture("CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        let line =
            NssKeyLogLine::parse(&raw).unwrap_or_else(|| panic!("valid NSS fixture was rejected"));
        assert_eq!(format!("{line:?}"), "NssKeyLogLine([REDACTED])");
        assert!(!format!("{line:?}").contains(SHA256_SECRET));

        let mut output = Vec::new();
        line.write_nss(&mut output)
            .unwrap_or_else(|error| panic!("NSS write failed: {error}"));
        assert_eq!(output, format!("{raw}\n").as_bytes());
    }

    #[test]
    fn line_rejects_non_quic_labels_invalid_hex_and_extra_fields() {
        for invalid in [
            String::new(),
            format!("CLIENT_RANDOM {CLIENT_RANDOM} {SHA256_SECRET}"),
            format!("CLIENT_TRAFFIC_SECRET_0 {CLIENT_RANDOM} not-hex"),
            format!("CLIENT_TRAFFIC_SECRET_0 {CLIENT_RANDOM} {SHA256_SECRET} extra"),
            format!("CLIENT_TRAFFIC_SECRET_0 {CLIENT_RANDOM} {SHA256_SECRET}\n"),
            format!(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET {CLIENT_RANDOM} {}",
                "aa".repeat(49)
            ),
        ] {
            assert!(NssKeyLogLine::parse(&invalid).is_none(), "{invalid:?}");
        }
    }

    #[test]
    fn line_accepts_sha384_at_the_fixed_storage_limit() {
        let raw = format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {CLIENT_RANDOM} {}",
            "ab".repeat(48)
        );
        assert_eq!(raw.len(), MAX_NSS_KEY_LOG_LINE_LEN);
        assert!(NssKeyLogLine::parse(&raw).is_some());
    }

    #[test]
    fn line_is_explicitly_zeroizable() {
        let mut line = NssKeyLogLine::parse(&fixture("EXPORTER_SECRET"))
            .unwrap_or_else(|| panic!("valid NSS fixture was rejected"));
        line.zeroize();
        assert_eq!(line.len, 0);
        assert!(line.bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn malformed_full_and_disconnected_records_drop_without_waiting() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let dropped = AtomicUsize::new(0);
        let first = fixture("CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        let second = fixture("SERVER_HANDSHAKE_TRAFFIC_SECRET");

        enqueue_key_log_line(&sender, &dropped, "not an NSS key-log line");
        enqueue_key_log_line(&sender, &dropped, &first);
        enqueue_key_log_line(&sender, &dropped, &second);
        assert_eq!(dropped.load(Ordering::Relaxed), 2);

        let queued = receiver
            .try_recv()
            .unwrap_or_else(|error| panic!("first record was not queued: {error}"));
        let mut output = Vec::new();
        queued
            .write_nss(&mut output)
            .unwrap_or_else(|error| panic!("queued record write failed: {error}"));
        assert_eq!(output, format!("{first}\n").as_bytes());

        drop(receiver);
        enqueue_key_log_line(&sender, &dropped, &second);
        assert_eq!(dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn receiver_drains_only_pending_records_and_redacts_debug() {
        let (sender, receiver) = mpsc::sync_channel(2);
        let dropped_lines = Arc::new(AtomicUsize::new(0));
        let receiver = NssKeyLogReceiver {
            receiver,
            dropped_lines: Arc::clone(&dropped_lines),
        };
        let client = fixture("CLIENT_TRAFFIC_SECRET_0");
        let server = fixture("SERVER_TRAFFIC_SECRET_0");
        enqueue_key_log_line(&sender, &dropped_lines, &client);
        enqueue_key_log_line(&sender, &dropped_lines, &server);

        let debug = format!("{receiver:?}");
        assert_eq!(debug, "NssKeyLogReceiver { dropped_line_count: 0, .. }");
        assert!(!debug.contains(SHA256_SECRET));

        let mut output = Vec::new();
        let written = receiver
            .write_pending_nss(&mut output)
            .unwrap_or_else(|error| panic!("pending NSS write failed: {error}"));
        assert_eq!(written, 2);
        assert_eq!(output, format!("{client}\n{server}\n").as_bytes());
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn builder_owns_sender_until_its_context_is_dropped() {
        let mut builder = SslContext::builder(SslMethod::tls())
            .unwrap_or_else(|error| panic!("TLS context allocation failed: {error}"));
        let receiver = configure_nss_key_log(
            &mut builder,
            NonZeroUsize::new(1).unwrap_or_else(|| panic!("one is nonzero")),
        );
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

        drop(builder);
        assert!(matches!(
            receiver.try_recv(),
            Err(TryRecvError::Disconnected)
        ));
    }
}
