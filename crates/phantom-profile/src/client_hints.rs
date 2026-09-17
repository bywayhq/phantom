//! Ordered client-hint fields and delivery policy.

use std::{collections::HashSet, error::Error, fmt};

/// Determines when a client-hint field is sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientHintDelivery {
    /// Send the field on every request unless the caller supplied it.
    Default,
    /// Send the field after the origin requests it through `Accept-CH`.
    AcceptCh,
}

/// One exact client-hint request field.
#[derive(Clone, Eq, PartialEq)]
pub struct ClientHint {
    name: Box<str>,
    value: Box<[u8]>,
    delivery: ClientHintDelivery,
}

impl ClientHint {
    /// Creates a field whose syntax is checked when the profile is built.
    #[must_use]
    pub fn new(
        name: impl Into<Box<str>>,
        value: impl AsRef<[u8]>,
        delivery: ClientHintDelivery,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.as_ref().into(),
            delivery,
        }
    }

    /// Returns the lowercase request-field name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact request-field value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns when this field is eligible for emission.
    #[must_use]
    pub const fn delivery(&self) -> ClientHintDelivery {
        self.delivery
    }
}

impl fmt::Debug for ClientHint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientHint")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("delivery", &self.delivery)
            .finish()
    }
}

/// Ordered client-hint fields for one client profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHintSettings {
    hints: Vec<ClientHint>,
}

impl ClientHintSettings {
    /// Creates an ordered client-hint profile.
    #[must_use]
    pub fn new(hints: Vec<ClientHint>) -> Self {
        Self { hints }
    }

    /// Returns the fields in their automatic emission order.
    #[must_use]
    pub fn hints(&self) -> &[ClientHint] {
        &self.hints
    }

    /// Validates field syntax and uniqueness.
    pub fn validate(&self) -> Result<(), InvalidClientHintSettings> {
        let mut names = HashSet::with_capacity(self.hints.len());
        for hint in &self.hints {
            if !valid_client_hint_name(hint.name()) {
                return Err(InvalidClientHintSettings::new(
                    "hints.name",
                    "names must be unique lowercase HTTP field names and structured-field tokens",
                ));
            }
            if !names.insert(hint.name()) {
                return Err(InvalidClientHintSettings::new(
                    "hints.name",
                    "field names must not repeat",
                ));
            }
            if !valid_field_value(hint.value()) {
                return Err(InvalidClientHintSettings::new(
                    "hints.value",
                    "values must contain only visible ASCII bytes, spaces, or horizontal tabs",
                ));
            }
        }
        Ok(())
    }
}

fn valid_client_hint_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let Some(first) = bytes.first().copied() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    bytes.iter().copied().all(is_tchar)
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn valid_field_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| matches!(*byte, b'\t' | b' '..=b'~'))
}

/// Error returned when client-hint profile data is inconsistent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidClientHintSettings {
    field: &'static str,
    message: &'static str,
}

impl InvalidClientHintSettings {
    const fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the reason the setting is invalid.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for InvalidClientHintSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid client-hint {}: {}",
            self.field, self.message
        )
    }
}

impl Error for InvalidClientHintSettings {}

#[cfg(test)]
#[path = "client_hints/tests.rs"]
mod tests;
