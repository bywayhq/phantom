//! Stock Quinn packet-crypto trait adapters.
//!
//! Quinn 0.11.18 validates header sample bounds before invoking
//! [`quinn_proto::crypto::HeaderKey`] and reserves
//! [`quinn_proto::crypto::PacketKey::tag_len`] bytes before encryption. The
//! traits have no encryption error channel, so an out-of-contract call is
//! failed closed by zeroing its buffer. Checked callers should continue to use
//! the concrete methods, which return this crate's typed errors.

use bytes::BytesMut;
use quinn_proto::crypto;

use crate::{HeaderProtectionKey, PacketProtectionKey};

impl crypto::HeaderKey for HeaderProtectionKey {
    fn decrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
        if self.unprotect(packet_number_offset, packet).is_err() {
            packet.fill(0);
        }
    }

    fn encrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
        if self.protect(packet_number_offset, packet).is_err() {
            packet.fill(0);
        }
    }

    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

impl crypto::PacketKey for PacketProtectionKey {
    fn encrypt(&self, packet_number: u64, packet: &mut [u8], header_len: usize) {
        if self.seal(packet_number, packet, header_len).is_err() {
            packet.fill(0);
        }
    }

    fn decrypt(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> std::result::Result<(), crypto::CryptoError> {
        match self.open(packet_number, header, payload.as_mut()) {
            Ok(plaintext_len) => {
                payload.truncate(plaintext_len);
                Ok(())
            }
            Err(_) => {
                payload.clear();
                Err(crypto::CryptoError)
            }
        }
    }

    fn tag_len(&self) -> usize {
        PacketProtectionKey::tag_len(self)
    }

    fn confidentiality_limit(&self) -> u64 {
        PacketProtectionKey::confidentiality_limit(self)
    }

    fn integrity_limit(&self) -> u64 {
        PacketProtectionKey::integrity_limit(self)
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use quinn_proto::crypto::{HeaderKey as _, PacketKey as _};

    use crate::{EndpointSide, HeaderProtectionKey, QuicVersion, derive_initial_keys};

    #[test]
    fn quinn_traits_reproduce_rfc_9001_server_initial() {
        let destination_connection_id = hex::<8>("8394c8f03e515708");
        let server = derive_initial_keys(
            QuicVersion::V1,
            &destination_connection_id,
            EndpointSide::Server,
        )
        .unwrap_or_else(|error| panic!("RFC server derivation failed: {error}"));
        let client = derive_initial_keys(
            QuicVersion::V1,
            &destination_connection_id,
            EndpointSide::Client,
        )
        .unwrap_or_else(|error| panic!("RFC client derivation failed: {error}"));
        let header = hex::<20>("c1000000010008f067a5502a4262b50040750001");
        let payload = hex::<99>(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739\
             88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94\
             0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00\
             020304",
        );
        let packet_key: &dyn quinn_proto::crypto::PacketKey = server.local().packet();
        let header_key: &dyn quinn_proto::crypto::HeaderKey = server.local().header();
        let mut packet = vec![0; header.len() + payload.len() + packet_key.tag_len()];
        packet[..header.len()].copy_from_slice(&header);
        packet[header.len()..header.len() + payload.len()].copy_from_slice(&payload);

        packet_key.encrypt(1, &mut packet, header.len());
        header_key.encrypt(18, &mut packet);
        assert_eq!(
            packet,
            hex_vec(include_str!("../testdata/rfc9001-server-initial.hex"))
        );

        let remote_header: &dyn quinn_proto::crypto::HeaderKey = client.remote().header();
        remote_header.decrypt(18, &mut packet);
        assert_eq!(&packet[..header.len()], &header);
        let (_, encrypted_payload) = packet.split_at(header.len());
        let mut encrypted_payload = BytesMut::from(encrypted_payload);
        let remote_packet: &dyn quinn_proto::crypto::PacketKey = client.remote().packet();
        remote_packet
            .decrypt(1, &header, &mut encrypted_payload)
            .unwrap_or_else(|_| panic!("RFC packet decryption failed"));
        assert_eq!(encrypted_payload.as_ref(), payload);
    }

    #[test]
    fn quinn_header_trait_reproduces_rfc_9001_chacha_short_header() {
        let header_key = HeaderProtectionKey::chacha20(&hex::<32>(
            "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
        ))
        .unwrap_or_else(|error| panic!("RFC ChaCha header key failed: {error}"));
        let expected = hex::<21>("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
        let mut packet = hex::<21>("4200bff4655e5cd55c41f69080575d7999c25a5bfb");

        header_key.encrypt(1, &mut packet);
        assert_eq!(packet, expected);
        header_key.decrypt(1, &mut packet);
        assert_eq!(&packet[..4], &hex::<4>("4200bff4"));
    }

    #[test]
    fn quinn_infallible_encrypt_traits_fail_closed_on_invalid_bounds() {
        let keys = derive_initial_keys(QuicVersion::V1, &[1; 8], EndpointSide::Client)
            .unwrap_or_else(|error| panic!("test key derivation failed: {error}"));
        let mut short_header = [0xabu8; 12];
        keys.local().header().encrypt(8, &mut short_header);
        assert_eq!(short_header, [0; 12]);

        let mut missing_tag = [0xabu8; 15];
        keys.local().packet().encrypt(0, &mut missing_tag, 0);
        assert_eq!(missing_tag, [0; 15]);
    }

    #[test]
    fn quinn_decrypt_trait_maps_errors_and_clears_payload() {
        let keys = derive_initial_keys(QuicVersion::V1, &[1; 8], EndpointSide::Client)
            .unwrap_or_else(|error| panic!("test key derivation failed: {error}"));
        let mut payload = BytesMut::from(&[0xabu8; 15][..]);

        assert!(
            keys.remote()
                .packet()
                .decrypt(0, &[], &mut payload)
                .is_err()
        );
        assert!(payload.is_empty());
    }

    #[test]
    fn quinn_packet_trait_reports_aes_usage_limits() {
        let keys = derive_initial_keys(QuicVersion::V1, &[1; 8], EndpointSide::Client)
            .unwrap_or_else(|error| panic!("test key derivation failed: {error}"));
        assert_eq!(keys.local().packet().tag_len(), 16);
        assert_eq!(keys.local().packet().confidentiality_limit(), 1 << 23);
        assert_eq!(keys.local().packet().integrity_limit(), 1 << 52);
    }

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        let compact: String = input
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert_eq!(compact.len(), N * 2, "fixture has wrong encoded length");
        let mut output = [0; N];
        for (index, byte) in output.iter_mut().enumerate() {
            let start = index * 2;
            *byte = match u8::from_str_radix(&compact[start..start + 2], 16) {
                Ok(value) => value,
                Err(error) => panic!("fixture is not hexadecimal: {error}"),
            };
        }
        output
    }

    fn hex_vec(input: &str) -> Vec<u8> {
        let compact: String = input
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert_eq!(compact.len() % 2, 0, "fixture has odd encoded length");
        compact
            .as_bytes()
            .chunks_exact(2)
            .map(|encoded| {
                let encoded = match std::str::from_utf8(encoded) {
                    Ok(encoded) => encoded,
                    Err(error) => panic!("fixture is not UTF-8: {error}"),
                };
                match u8::from_str_radix(encoded, 16) {
                    Ok(value) => value,
                    Err(error) => panic!("fixture is not hexadecimal: {error}"),
                }
            })
            .collect()
    }
}
