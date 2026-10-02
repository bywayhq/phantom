//! A model of the GREASE ECH payload length the NSS of Firefox 157 sends,
//! written from NSS rather than from the BoringSSL patch that reproduces it.
//!
//! `tls13_MaybeGreaseEch` runs once every other extension, including
//! `pre_shared_key`, is built and before padding. It sizes the payload as the
//! EncodedClientHelloInner a real ECH offer would encrypt
//! (`tls13_ConstructInnerExtensionsFromOuter` with compression), padded by
//! `tls13_PadChInner`, plus a 16-byte AEAD tag.

use super::TestResult;

const SERVER_NAME: u16 = 0x0000;
const EC_POINT_FORMATS: u16 = 0x000b;
const PADDING: u16 = 0x0015;
const EXTENDED_MASTER_SECRET: u16 = 0x0017;
const SESSION_TICKET: u16 = 0x0023;
const PRE_SHARED_KEY: u16 = 0x0029;
const SUPPORTED_VERSIONS: u16 = 0x002b;
const RENEGOTIATION_INFO: u16 = 0xff01;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// The tag of AES-128-GCM and ChaCha20-Poly1305, the two Firefox AEADs.
const AEAD_TAG: usize = 16;

/// Returns the GREASE ECH payload length NSS gives `handshake`, a ClientHello
/// handshake message with its four-byte header, for an ECHConfig whose
/// `maximum_name_length` is `maximum_name_length`.
///
/// NSS pads by the length of the URL host, `host_len`. Without it, the
/// model takes the length of the `server_name` host name, which is the URL
/// host unless the host is an IP literal.
pub(crate) fn payload_length(
    handshake: &[u8],
    maximum_name_length: usize,
    host_len: Option<usize>,
) -> TestResult<usize> {
    model(handshake, maximum_name_length, host_len, None)
}

/// Returns [`payload_length`] for the same resumed ClientHello had its
/// `pre_shared_key` body been `pre_shared_key_len` bytes long.
///
/// The ticket and the binder's hash, which set that length, are the
/// server's choice. This compares a ClientHello that resumes a loopback
/// server's session against a capture that resumed another server's.
pub(crate) fn payload_length_with_pre_shared_key(
    handshake: &[u8],
    maximum_name_length: usize,
    host_len: Option<usize>,
    pre_shared_key_len: usize,
) -> TestResult<usize> {
    model(
        handshake,
        maximum_name_length,
        host_len,
        Some(pre_shared_key_len),
    )
}

/// Returns the length of the `pre_shared_key` body of `handshake`.
pub(crate) fn pre_shared_key_length(handshake: &[u8]) -> TestResult<usize> {
    Ok(pre_shared_key(handshake)?.len())
}

/// Returns the length of the one PSK identity, the session ticket, that
/// `handshake` presents.
pub(crate) fn ticket_length(handshake: &[u8]) -> TestResult<usize> {
    let mut identities = Reader(Reader(pre_shared_key(handshake)?).vector16()?);
    let identity = identities.vector16()?;
    // The obfuscated ticket age.
    identities.take(4)?;
    if !identities.0.is_empty() {
        return Err("the ClientHello presents more than one PSK identity".into());
    }
    Ok(identity.len())
}

fn pre_shared_key(handshake: &[u8]) -> TestResult<&[u8]> {
    parse(handshake)?
        .extensions
        .into_iter()
        .find_map(|(extension_type, body)| (extension_type == PRE_SHARED_KEY).then_some(body))
        .ok_or_else(|| "the ClientHello has no pre_shared_key extension".into())
}

/// Returns the payload length of the GREASE `encrypted_client_hello`
/// extension in `handshake`, a ClientHello with its four-byte header.
pub(crate) fn sent_payload_length(handshake: &[u8]) -> TestResult<usize> {
    let (_, body) = parse(handshake)?
        .extensions
        .into_iter()
        .find(|&(extension_type, _)| extension_type == ENCRYPTED_CLIENT_HELLO)
        .ok_or("the ClientHello has no encrypted_client_hello extension")?;
    // Outer type, cipher suite, configuration ID, then the encapsulated key
    // and the payload.
    let mut ech = Reader(body);
    ech.take(1 + 4 + 1)?;
    ech.vector16()?;
    Ok(ech.vector16()?.len())
}

fn model(
    handshake: &[u8],
    maximum_name_length: usize,
    host_len: Option<usize>,
    pre_shared_key_len: Option<usize>,
) -> TestResult<usize> {
    let ClientHello {
        outer_fields,
        extensions,
    } = parse(handshake)?;
    // legacy_version, random, an empty legacy_session_id, the outer cipher
    // suites and compression methods, the extensions length, and the inner
    // `encrypted_client_hello` extension with its one-byte type.
    let mut length = 2 + 32 + 1 + outer_fields + 2 + 4 + 1;
    let mut compressed = 0;
    let mut name_len = 0;
    for (extension_type, body) in extensions {
        match extension_type {
            // Sized before either is added.
            ENCRYPTED_CLIENT_HELLO | PADDING => {}
            // Supported by NSS but unknown to it in TLS 1.3, so left out of
            // ClientHelloInner.
            EC_POINT_FORMATS | EXTENDED_MASTER_SECRET | SESSION_TICKET | RENEGOTIATION_INFO => {}
            // Copied whole; the host name follows a list length, a name type,
            // and a name length.
            SERVER_NAME => {
                length += 4 + body.len();
                name_len = body.len().checked_sub(5).ok_or("short server_name")?;
            }
            // TLS 1.3, and a GREASE version when the outer list has one.
            SUPPORTED_VERSIONS => {
                let versions = Reader(body).vector8()?;
                let grease = versions
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|version| version[0] & 0x0f == 0x0a && version[1] & 0x0f == 0x0a);
                length += 4 + 1 + 2 + if grease { 2 } else { 0 };
            }
            // Copied whole.
            PRE_SHARED_KEY => length += 4 + pre_shared_key_len.unwrap_or(body.len()),
            // Named in `ech_outer_extensions`.
            _ => compressed += 1,
        }
    }
    if compressed > 0 {
        length += 4 + 1 + 2 * compressed;
    }
    length += maximum_name_length.saturating_sub(host_len.unwrap_or(name_len));
    Ok(length.div_ceil(32) * 32 + AEAD_TAG)
}

/// The parts of a ClientHello the model reads.
struct ClientHello<'a> {
    /// The length of the length-prefixed cipher suites and compression
    /// methods.
    outer_fields: usize,
    /// The extensions in wire order, by type and body.
    extensions: Vec<(u16, &'a [u8])>,
}

fn parse(handshake: &[u8]) -> TestResult<ClientHello<'_>> {
    let mut body = Reader(handshake.get(4..).ok_or("truncated ClientHello")?);
    body.take(2 + 32)?;
    body.vector8()?;
    let outer_fields = 2 + body.vector16()?.len() + 1 + body.vector8()?.len();
    let mut extensions = Reader(body.vector16()?);
    let mut parsed = Vec::new();
    while !extensions.0.is_empty() {
        let extension_type = extensions.take(2)?;
        parsed.push((
            u16::from_be_bytes([extension_type[0], extension_type[1]]),
            extensions.vector16()?,
        ));
    }
    Ok(ClientHello {
        outer_fields,
        extensions: parsed,
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> TestResult<&'a [u8]> {
        let (taken, rest) = self
            .0
            .split_at_checked(count)
            .ok_or("truncated ClientHello field")?;
        self.0 = rest;
        Ok(taken)
    }

    fn vector8(&mut self) -> TestResult<&'a [u8]> {
        let length = usize::from(self.take(1)?[0]);
        self.take(length)
    }

    fn vector16(&mut self) -> TestResult<&'a [u8]> {
        let length = self.take(2)?;
        self.take(usize::from(u16::from_be_bytes([length[0], length[1]])))
    }
}
