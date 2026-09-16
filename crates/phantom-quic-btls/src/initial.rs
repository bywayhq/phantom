use std::fmt;

use crate::backend::{HkdfDigest, hkdf_extract_sha256};
use crate::hkdf::expand_label;
use crate::key_schedule::{CipherSuite, derive_direction_keys};
use crate::secret::{SHA256_LEN, Secret};
use crate::{CryptoError, DirectionKeys, EndpointSide, QuicVersion, Result};

const MAX_CONNECTION_ID_LEN: usize = 20;

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
    let client = derive_direction_keys(CipherSuite::Aes128GcmSha256, client_secret.as_slice())?;
    let server = derive_direction_keys(CipherSuite::Aes128GcmSha256, server_secret.as_slice())?;
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
    expand_label(
        HkdfDigest::Sha256,
        initial.as_slice(),
        b"client in",
        &[],
        client.as_mut_slice(),
    )?;
    let mut server = Secret::<SHA256_LEN>::zeroed();
    expand_label(
        HkdfDigest::Sha256,
        initial.as_slice(),
        b"server in",
        &[],
        server.as_mut_slice(),
    )?;
    Ok((client, server))
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
