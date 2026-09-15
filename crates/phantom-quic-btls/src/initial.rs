use std::fmt;

use crate::backend::{hkdf_expand_sha256, hkdf_extract_sha256};
use crate::secret::{AES_128_KEY_LEN, QUIC_NONCE_LEN, SHA256_LEN, Secret};
use crate::{CryptoError, HeaderProtectionKey, PacketProtectionKey, QuicVersion, Result};

const MAX_CONNECTION_ID_LEN: usize = 20;

/// Which endpoint owns the local half of a derived initial key pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointSide {
    /// The local endpoint initiated the connection.
    Client,
    /// The local endpoint accepted the connection.
    Server,
}

/// Packet and header keys for one direction of an Initial packet space.
pub struct DirectionKeys {
    header: HeaderProtectionKey,
    packet: PacketProtectionKey,
}

impl DirectionKeys {
    /// Returns the header-protection key.
    #[must_use]
    pub const fn header(&self) -> &HeaderProtectionKey {
        &self.header
    }

    /// Returns the packet-protection key.
    #[must_use]
    pub const fn packet(&self) -> &PacketProtectionKey {
        &self.packet
    }
}

impl fmt::Debug for DirectionKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectionKeys([REDACTED])")
    }
}

/// Local and remote keys for a QUIC Initial packet space.
pub struct InitialKeys {
    local: DirectionKeys,
    remote: DirectionKeys,
}

impl InitialKeys {
    /// Returns keys used to protect packets sent by the local endpoint.
    #[must_use]
    pub const fn local(&self) -> &DirectionKeys {
        &self.local
    }

    /// Returns keys used to process packets sent by the peer.
    #[must_use]
    pub const fn remote(&self) -> &DirectionKeys {
        &self.remote
    }
}

impl fmt::Debug for InitialKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitialKeys([REDACTED])")
    }
}

/// Derives the version-specific Initial packet keys for one endpoint.
pub fn derive_initial_keys(
    version: QuicVersion,
    destination_connection_id: &[u8],
    side: EndpointSide,
) -> Result<InitialKeys> {
    if destination_connection_id.len() > MAX_CONNECTION_ID_LEN {
        return Err(CryptoError::InvalidConnectionIdLength {
            actual: destination_connection_id.len(),
            maximum: MAX_CONNECTION_ID_LEN,
        });
    }

    let (client_secret, server_secret) =
        derive_initial_secrets(version, destination_connection_id)?;
    let client = derive_direction_keys(&client_secret)?;
    let server = derive_direction_keys(&server_secret)?;
    let (local, remote) = match side {
        EndpointSide::Client => (client, server),
        EndpointSide::Server => (server, client),
    };
    Ok(InitialKeys { local, remote })
}

fn derive_initial_secrets(
    version: QuicVersion,
    destination_connection_id: &[u8],
) -> Result<(Secret<SHA256_LEN>, Secret<SHA256_LEN>)> {
    let mut initial = Secret::<SHA256_LEN>::zeroed();
    hkdf_extract_sha256(
        version.initial_salt(),
        destination_connection_id,
        initial.as_mut_slice(),
    )?;

    let mut client = Secret::<SHA256_LEN>::zeroed();
    hkdf_expand_label(initial.as_slice(), b"client in", client.as_mut_slice())?;
    let mut server = Secret::<SHA256_LEN>::zeroed();
    hkdf_expand_label(initial.as_slice(), b"server in", server.as_mut_slice())?;
    Ok((client, server))
}

fn derive_direction_keys(secret: &Secret<SHA256_LEN>) -> Result<DirectionKeys> {
    let mut packet_key = Secret::<AES_128_KEY_LEN>::zeroed();
    hkdf_expand_label(secret.as_slice(), b"quic key", packet_key.as_mut_slice())?;
    let mut iv = Secret::<QUIC_NONCE_LEN>::zeroed();
    hkdf_expand_label(secret.as_slice(), b"quic iv", iv.as_mut_slice())?;
    let mut header_key = Secret::<AES_128_KEY_LEN>::zeroed();
    hkdf_expand_label(secret.as_slice(), b"quic hp", header_key.as_mut_slice())?;

    Ok(DirectionKeys {
        header: HeaderProtectionKey::aes_128(header_key.as_slice())?,
        packet: PacketProtectionKey::aes_128_gcm(packet_key.as_slice(), iv.as_slice())?,
    })
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], output: &mut [u8]) -> Result<()> {
    const TLS_LABEL: &[u8] = b"tls13 ";
    const MAX_LABEL_LEN: usize = u8::MAX as usize;
    let full_label_len = TLS_LABEL
        .len()
        .checked_add(label.len())
        .filter(|length| *length <= MAX_LABEL_LEN)
        .ok_or(CryptoError::BackendFailure("HKDF label encoding"))?;
    let output_len = u16::try_from(output.len())
        .map_err(|_| CryptoError::BackendFailure("HKDF output length encoding"))?;

    let mut info = [0; 2 + 1 + TLS_LABEL.len() + 16 + 1];
    let required = 2 + 1 + full_label_len + 1;
    if label.len() > 16 || required > info.len() {
        return Err(CryptoError::BackendFailure("HKDF label encoding"));
    }
    info[..2].copy_from_slice(&output_len.to_be_bytes());
    info[2] = full_label_len as u8;
    let tls_end = 3 + TLS_LABEL.len();
    info[3..tls_end].copy_from_slice(TLS_LABEL);
    let label_end = tls_end + label.len();
    info[tls_end..label_end].copy_from_slice(label);
    info[label_end] = 0;
    hkdf_expand_sha256(secret, &info[..required], output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_9001_initial_secrets_are_exact() {
        let destination_connection_id = hex::<8>("8394c8f03e515708");
        let (client, server) = derive_initial_secrets(QuicVersion::V1, &destination_connection_id)
            .unwrap_or_else(|error| panic!("RFC fixture derivation failed: {error}"));

        assert_eq!(
            client.as_slice(),
            &hex::<32>("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            server.as_slice(),
            &hex::<32>("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );
    }

    pub(super) fn hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2, "fixture has wrong encoded length");
        let mut output = [0; N];
        for (index, byte) in output.iter_mut().enumerate() {
            let start = index * 2;
            *byte = match u8::from_str_radix(&input[start..start + 2], 16) {
                Ok(value) => value,
                Err(error) => panic!("fixture is not hexadecimal: {error}"),
            };
        }
        output
    }
}
