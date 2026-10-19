//! Fresh ClientHello generation without network I/O.

use std::io::{self, Read, Write};

use btls::ssl::{ErrorCode, SslStream};
use phantom_profile::TlsSettings;

use super::{TlsConnector, TlsError};

const LIMIT: usize = 128 * 1024;

/// Generates a fresh TCP ClientHello using the production TLS configuration.
///
/// Returns one handshake message, without TLS record headers. No DNS, sockets,
/// session restoration or peer authentication occurs. Random values and key
/// shares are generated normally; this is not a deterministic byte export.
/// `server_name` selects SNI and name-dependent ECH padding as in a connection.
///
/// # Errors
///
/// Rejects unsupported settings, invalid server names, backend failures and
/// output exceeding 128 KiB. This does not validate a server handshake.
pub fn preview_client_hello(
    settings: &TlsSettings,
    server_name: &str,
) -> Result<Vec<u8>, TlsError> {
    let connector = TlsConnector::new(settings)?;
    let ssl = connector
        .handshake_configuration(server_name, None)?
        .into_ssl(server_name)
        .map_err(|error| TlsError::backend("server_name", error))?;
    let mut stream = SslStream::new(ssl, Capture::default())
        .map_err(|error| TlsError::backend("ClientHello preview", error))?;
    match stream.connect() {
        Err(error) if error.code() == ErrorCode::WANT_READ => {}
        Err(error) => return Err(TlsError::handshake(error)),
        Ok(()) => {
            return Err(invalid("handshake completed without a peer"));
        }
    }
    let mut records = stream.get_ref().bytes.as_slice();
    let mut handshake = Vec::new();
    while !records.is_empty() {
        let header = records
            .get(..5)
            .ok_or_else(|| invalid("truncated TLS record header"))?;
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let payload = records
            .get(5..5 + size)
            .filter(|_| header[0] == 22)
            .ok_or_else(|| invalid("invalid ClientHello TLS record"))?;
        handshake.extend_from_slice(payload);
        records = &records[5 + size..];
    }
    phantom_profile::client_hello::ClientHelloSummary::from_handshake_bytes(&handshake)
        .map_err(|_| invalid("invalid generated ClientHello"))?;
    Ok(handshake)
}

fn invalid(message: &'static str) -> TlsError {
    TlsError::configuration("ClientHello preview", message)
}

#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
}

impl Read for Capture {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > LIMIT.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("ClientHello preview exceeds 128 KiB"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
