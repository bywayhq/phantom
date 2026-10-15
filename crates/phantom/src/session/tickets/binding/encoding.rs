use std::time::Duration;

use zeroize::Zeroizing;

use super::PreparationError;

/// An allocation ceiling for transfer preparation, not a protocol limit.
pub(super) const MAX_POLICY_BYTES: usize = 1024 * 1024;

pub(crate) struct Encoder {
    bytes: Zeroizing<Vec<u8>>,
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }

    fn reserve(&mut self, additional: usize) -> Result<(), PreparationError> {
        let size = self
            .bytes
            .len()
            .checked_add(additional)
            .filter(|size| *size <= MAX_POLICY_BYTES)
            .ok_or(PreparationError::TooLarge)?;
        if size > self.bytes.capacity() {
            // Reallocating a Vec could free its old secret bytes without wiping them.
            let mut replacement = Zeroizing::new(Vec::new());
            let capacity = size
                .max(self.bytes.capacity().saturating_mul(2))
                .clamp(64, MAX_POLICY_BYTES);
            replacement
                .try_reserve_exact(capacity)
                .map_err(|_| PreparationError::Allocation)?;
            replacement.extend_from_slice(&self.bytes);
            self.bytes = replacement;
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), PreparationError> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn u8(&mut self, value: u8) -> Result<(), PreparationError> {
        self.append(&[value])
    }

    pub(crate) fn bool(&mut self, value: bool) -> Result<(), PreparationError> {
        self.u8(u8::from(value))
    }

    pub(crate) fn u16(&mut self, value: u16) -> Result<(), PreparationError> {
        self.append(&value.to_be_bytes())
    }

    pub(crate) fn u32(&mut self, value: u32) -> Result<(), PreparationError> {
        self.append(&value.to_be_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> Result<(), PreparationError> {
        self.append(&value.to_be_bytes())
    }

    pub(crate) fn usize(&mut self, value: usize) -> Result<(), PreparationError> {
        self.u64(u64::try_from(value).map_err(|_| PreparationError::TooLarge)?)
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), PreparationError> {
        let length = u32::try_from(value.len()).map_err(|_| PreparationError::TooLarge)?;
        self.reserve(
            value
                .len()
                .checked_add(4)
                .ok_or(PreparationError::TooLarge)?,
        )?;
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn text(&mut self, value: &str) -> Result<(), PreparationError> {
        self.bytes(value.as_bytes())
    }

    pub(crate) fn duration(&mut self, value: Duration) -> Result<(), PreparationError> {
        self.u64(value.as_secs())?;
        self.u32(value.subsec_nanos())
    }

    pub(crate) fn option<T>(
        &mut self,
        value: Option<&T>,
        encode: impl FnOnce(&mut Self, &T) -> Result<(), PreparationError>,
    ) -> Result<(), PreparationError> {
        self.bool(value.is_some())?;
        if let Some(value) = value {
            encode(self, value)?;
        }
        Ok(())
    }

    pub(crate) fn list<T>(
        &mut self,
        values: &[T],
        mut encode: impl FnMut(&mut Self, &T) -> Result<(), PreparationError>,
    ) -> Result<(), PreparationError> {
        self.u32(u32::try_from(values.len()).map_err(|_| PreparationError::TooLarge)?)?;
        for value in values {
            encode(self, value)?;
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.bytes)
    }

    pub(crate) fn transfer_credential(
        domain: &[u8],
        fields: &[&[u8]],
    ) -> Result<btls::ssl::SessionTransferCredential, PreparationError> {
        let prefix = domain
            .len()
            .checked_add(4 + 2 + 4)
            .ok_or(PreparationError::TooLarge)?;
        fields
            .iter()
            .try_fold(prefix, |size, field| {
                size.checked_add(4)?.checked_add(field.len())
            })
            .filter(|size| *size <= 64 * 1024)
            .ok_or(PreparationError::TooLarge)?;
        let mut encoder = Self::new();
        encoder.bytes(domain)?;
        encoder.u16(2)?;
        encoder.u32(u32::try_from(fields.len()).map_err(|_| PreparationError::TooLarge)?)?;
        for field in fields {
            encoder.bytes(field)?;
        }
        btls::ssl::SessionTransferCredential::from_canonical_hmac_input(&encoder.bytes)
            .map_err(crate::route::transfer_credential_error)
    }

    pub(crate) fn request_header(
        &mut self,
        header: &phantom_net::request::RequestHeader,
    ) -> Result<(), PreparationError> {
        self.text(header.name())?;
        self.bytes(header.value())?;
        self.bool(header.is_sensitive())
    }
}
