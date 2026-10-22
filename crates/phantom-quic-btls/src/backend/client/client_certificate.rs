use super::{ClientSessionError, EncryptionLevel};

/// Observes only the client's existing outgoing handshake bytes; retains no certificate bytes.
#[derive(Debug, Default)]
pub(super) struct ClientCertificateTracker {
    header: [u8; 4],
    header_len: usize,
    remaining: usize,
    prefix: [u8; 4],
    prefix_len: usize,
    nonempty: bool,
    sent: bool,
    failed: bool,
}

impl ClientCertificateTracker {
    pub(super) fn observe(
        &mut self,
        level: EncryptionLevel,
        bytes: &[u8],
    ) -> Result<(), ClientSessionError> {
        if self.failed {
            return Err(invalid_certificate());
        }
        if level != EncryptionLevel::Handshake {
            return Ok(());
        }
        let result = self.fragment(bytes);
        self.failed = result.is_err();
        result
    }

    pub(super) fn sent(&self) -> Result<bool, ClientSessionError> {
        if self.failed || self.header_len != 0 {
            return Err(invalid_certificate());
        }
        Ok(self.sent)
    }

    fn fragment(&mut self, mut bytes: &[u8]) -> Result<(), ClientSessionError> {
        while !bytes.is_empty() {
            if self.header_len < self.header.len() {
                let count = bytes.len().min(self.header.len() - self.header_len);
                self.header[self.header_len..self.header_len + count]
                    .copy_from_slice(&bytes[..count]);
                self.header_len += count;
                bytes = &bytes[count..];
                if self.header_len != self.header.len() {
                    break;
                }
                self.remaining = u24([self.header[1], self.header[2], self.header[3]]);
                self.prefix_len = 0;
                self.nonempty = false;
                // Pinned BoringSSL emits uncompressed client Certificate messages.
                // TLS1.3's handshake Certificate has an empty request context:
                // tls13_both.cc:439–466; compression negotiation is server-only.
                if self.header[0] == 25 || (self.header[0] == 11 && self.remaining < 4) {
                    return Err(invalid_certificate());
                }
            }
            let count = bytes.len().min(self.remaining);
            if self.header[0] == 11 && self.prefix_len < self.prefix.len() {
                let prefix_count = count.min(self.prefix.len() - self.prefix_len);
                self.prefix[self.prefix_len..self.prefix_len + prefix_count]
                    .copy_from_slice(&bytes[..prefix_count]);
                self.prefix_len += prefix_count;
                if self.prefix_len == self.prefix.len() {
                    let list_len = u24([self.prefix[1], self.prefix[2], self.prefix[3]]);
                    let body_len = u24([self.header[1], self.header[2], self.header[3]]);
                    // A nonempty CertificateEntry needs a u24 length, at least
                    // one certificate byte and a u16 extensions length.
                    if self.prefix[0] != 0
                        || list_len != body_len - 4
                        || (list_len != 0 && list_len < 6)
                    {
                        return Err(invalid_certificate());
                    }
                    self.nonempty = list_len != 0;
                }
            }
            self.remaining -= count;
            bytes = &bytes[count..];
            if self.remaining == 0 {
                self.sent |= self.nonempty;
                self.header_len = 0;
            }
        }
        Ok(())
    }
}

fn u24(bytes: [u8; 3]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

fn invalid_certificate() -> ClientSessionError {
    ClientSessionError::BackendFailure("outgoing client Certificate framing")
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC8446 Certificate with empty context and one opaque certificate byte.
    const NONEMPTY: &[u8] = &[11, 0, 0, 10, 0, 0, 0, 6, 0, 0, 1, 0xa5, 0, 0];
    const EMPTY: &[u8] = &[11, 0, 0, 4, 0, 0, 0, 0];
    const FINISHED: &[u8] = &[20, 0, 0, 2, 0x11, 0x22];

    #[test]
    fn no_certificate_and_empty_certificate_remain_distinct_from_nonempty()
    -> Result<(), ClientSessionError> {
        for messages in [FINISHED, EMPTY, NONEMPTY] {
            let mut tracker = ClientCertificateTracker::default();
            tracker.observe(EncryptionLevel::Handshake, messages)?;
            assert_eq!(tracker.sent()?, messages == NONEMPTY);
        }
        Ok(())
    }

    #[test]
    fn every_split_and_single_byte_fragments_preserve_complete_message_detection()
    -> Result<(), ClientSessionError> {
        for split in 0..=NONEMPTY.len() {
            let mut tracker = ClientCertificateTracker::default();
            tracker.observe(EncryptionLevel::Handshake, &NONEMPTY[..split])?;
            if split != 0 && split != NONEMPTY.len() {
                assert!(tracker.sent().is_err());
            }
            tracker.observe(EncryptionLevel::Handshake, &NONEMPTY[split..])?;
            assert!(tracker.sent()?);
        }
        let mut tracker = ClientCertificateTracker::default();
        for byte in NONEMPTY {
            tracker.observe(EncryptionLevel::Handshake, std::slice::from_ref(byte))?;
        }
        assert!(tracker.sent()?);
        Ok(())
    }

    #[test]
    fn combined_messages_and_other_packet_spaces_do_not_confuse_certificate_presence()
    -> Result<(), ClientSessionError> {
        let mut tracker = ClientCertificateTracker::default();
        for level in [EncryptionLevel::Initial, EncryptionLevel::Application] {
            tracker.observe(level, NONEMPTY)?;
        }
        assert!(!tracker.sent()?);
        let messages = [FINISHED, NONEMPTY, FINISHED, EMPTY].concat();
        tracker.observe(EncryptionLevel::Handshake, &messages)?;
        assert!(tracker.sent()?);
        Ok(())
    }

    #[test]
    fn malformed_or_truncated_messages_cannot_publish_a_negative_fact() {
        let malformed: &[&[u8]] = &[
            &[11, 0, 0, 3],
            &[11, 0, 0, 4, 1, 0, 0, 0],
            &[11, 0, 0, 4, 0, 0, 0, 1],
            &[11, 0, 0, 5, 0, 0, 0, 1, 0],
            &[25, 0, 0, 0],
        ];
        for message in malformed {
            let mut tracker = ClientCertificateTracker::default();
            assert!(
                tracker
                    .observe(EncryptionLevel::Handshake, message)
                    .is_err()
            );
            assert!(tracker.sent().is_err());
            assert!(
                tracker
                    .observe(EncryptionLevel::Handshake, FINISHED)
                    .is_err()
            );
        }
        for end in 1..NONEMPTY.len() {
            let mut tracker = ClientCertificateTracker::default();
            assert!(
                tracker
                    .observe(EncryptionLevel::Handshake, &NONEMPTY[..end])
                    .is_ok()
            );
            assert!(tracker.sent().is_err());
        }
    }

    #[test]
    fn interleaved_sessions_keep_their_own_certificate_fact() -> Result<(), ClientSessionError> {
        let mut first = ClientCertificateTracker::default();
        let mut second = ClientCertificateTracker::default();
        first.observe(EncryptionLevel::Handshake, &NONEMPTY[..7])?;
        second.observe(EncryptionLevel::Handshake, EMPTY)?;
        first.observe(EncryptionLevel::Handshake, &NONEMPTY[7..])?;
        assert!(first.sent()?);
        assert!(!second.sent()?);
        Ok(())
    }
}
