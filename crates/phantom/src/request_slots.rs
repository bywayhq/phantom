//! Fill declared caller-header positions before sending a request.

use std::{error::Error, fmt};

use http::HeaderValue;

use crate::RequestHeader;

/// A borrowed view of the caller slots available on one request.
///
/// The request builder creates this view from its template's caller slots.
/// You can fill a declared slot once, including an optional slot. Literal
/// headers, client hints, and generated authorization positions are not
/// caller slots.
///
/// Names are compared without ASCII case. Filled headers retain their value,
/// spelling, and sensitivity. The template supplies their spelling and
/// position when the request is prepared.
///
/// This view exposes no header values or mutable header list.
pub struct RequestSlots<'a> {
    headers: &'a mut Vec<RequestHeader>,
    declared_names: &'a [Box<str>],
}

impl<'a> RequestSlots<'a> {
    /// Borrows caller headers and the validated caller-slot intersection.
    ///
    /// The adapter must include only `Caller` names declared by every
    /// relevant template list. Names must already be validated and unique
    /// without ASCII case.
    pub(crate) fn new(headers: &'a mut Vec<RequestHeader>, declared_names: &'a [Box<str>]) -> Self {
        Self {
            headers,
            declared_names,
        }
    }

    /// Fills a declared slot with this header without replacing another value.
    ///
    /// The header keeps its bytes, spelling, and sensitivity. Name matching
    /// ignores ASCII case. Each successful fill appends one caller header.
    /// The template places that header when preparing the request.
    ///
    /// # Errors
    ///
    /// Returns [`RequestSlotErrorKind::Undeclared`] for a name outside the
    /// declared caller slots. Returns [`RequestSlotErrorKind::AlreadyFilled`]
    /// when a caller header already has that name, including a previous fill.
    /// Returns [`RequestSlotErrorKind::InvalidValue`] when the bytes are not
    /// a valid HTTP header value. An error leaves all caller headers unchanged.
    pub fn fill(&mut self, header: RequestHeader) -> Result<(), RequestSlotError> {
        if !self.declares(header.name()) {
            return Err(RequestSlotError::new(RequestSlotErrorKind::Undeclared));
        }
        if self.is_filled(header.name()) {
            return Err(RequestSlotError::new(RequestSlotErrorKind::AlreadyFilled));
        }
        if HeaderValue::from_bytes(header.value()).is_err() {
            return Err(RequestSlotError::new(RequestSlotErrorKind::InvalidValue));
        }
        self.headers.push(header);
        Ok(())
    }

    /// Returns whether this name is a declared caller slot, ignoring ASCII case.
    #[must_use]
    pub fn declares(&self, name: &str) -> bool {
        self.declared_names
            .iter()
            .any(|declared| declared.eq_ignore_ascii_case(name))
    }

    /// Returns whether a declared slot has a caller header, ignoring ASCII case.
    ///
    /// Returns `false` for undeclared names, including other caller headers.
    #[must_use]
    pub fn is_filled(&self, name: &str) -> bool {
        self.declares(name)
            && self
                .headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case(name))
    }
}

impl fmt::Debug for RequestSlots<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestSlots")
            .field("declared_slot_count", &self.declared_names.len())
            .field(
                "filled_slot_count",
                &self
                    .declared_names
                    .iter()
                    .filter(|name| self.is_filled(name))
                    .count(),
            )
            .finish_non_exhaustive()
    }
}

/// The reason a caller slot could not be filled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestSlotErrorKind {
    /// The name is not among the declared caller slots.
    Undeclared,
    /// A caller header already fills the slot, ignoring ASCII case.
    AlreadyFilled,
    /// The supplied bytes are not a valid HTTP header value.
    InvalidValue,
}

/// A slot-filling failure without any header name or value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RequestSlotError {
    kind: RequestSlotErrorKind,
}

impl RequestSlotError {
    pub(crate) const fn new(kind: RequestSlotErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> RequestSlotErrorKind {
        self.kind
    }
}

impl fmt::Debug for RequestSlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestSlotError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RequestSlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RequestSlotErrorKind::Undeclared => "request header is not a declared caller slot",
            RequestSlotErrorKind::AlreadyFilled => "request caller slot is already filled",
            RequestSlotErrorKind::InvalidValue => "request caller slot has an invalid header value",
        })
    }
}

impl Error for RequestSlotError {}

#[cfg(test)]
mod tests {
    use super::{RequestSlotError, RequestSlotErrorKind, RequestSlots};
    use crate::RequestHeader;

    #[test]
    fn filling_a_declared_slot_preserves_bytes_spelling_and_sensitivity()
    -> Result<(), RequestSlotError> {
        let names = [Box::<str>::from("X-Token"), Box::from("X-Context")];
        let mut headers = vec![RequestHeader::new("X-Existing", "unchanged")];
        let supplied = RequestHeader::new("x-ToKeN", b"opaque\x80\xff\t value").sensitive();
        {
            let mut slots = RequestSlots::new(&mut headers, &names);
            assert!(slots.declares("X-TOKEN"));
            assert!(!slots.is_filled("x-token"));
            slots.fill(supplied.clone())?;
            assert!(slots.is_filled("X-TOKEN"));
            assert!(!slots.is_filled("x-context"));
        }
        assert_eq!(
            headers,
            [RequestHeader::new("X-Existing", "unchanged"), supplied]
        );
        assert_eq!(headers[1].name(), "x-ToKeN");
        assert!(headers[1].is_sensitive());
        Ok(())
    }

    #[test]
    fn names_outside_the_declared_slots_cannot_add_headers() {
        let names = [Box::<str>::from("x-context")];
        let mut headers = vec![RequestHeader::new("X-Existing", "unchanged")];
        let before = headers.clone();
        for name in [
            "x-literal",
            "sec-ch-ua",
            "proxy-authorization",
            "host",
            "x-arbitrary",
        ] {
            let mut slots = RequestSlots::new(&mut headers, &names);
            assert!(!slots.declares(name));
            assert_eq!(
                slots
                    .fill(RequestHeader::new(name, "value"))
                    .map_err(|error| error.kind()),
                Err(RequestSlotErrorKind::Undeclared)
            );
        }
        assert_eq!(headers, before);
    }

    #[test]
    fn a_prior_caller_header_fills_a_slot_without_exposing_other_headers() {
        let names = [Box::<str>::from("x-token")];
        let mut headers = vec![
            RequestHeader::new("X-TOKEN", "original"),
            RequestHeader::new("X-Other", "private"),
        ];
        let before = headers.clone();
        {
            let mut slots = RequestSlots::new(&mut headers, &names);
            assert!(slots.is_filled("x-ToKeN"));
            assert!(!slots.is_filled("x-other"));
            assert_eq!(
                slots
                    .fill(RequestHeader::new("x-token", "replacement"))
                    .map_err(|error| error.kind()),
                Err(RequestSlotErrorKind::AlreadyFilled)
            );
        }
        assert_eq!(headers, before);
    }

    #[test]
    fn a_second_fill_is_rejected_without_changing_the_first() -> Result<(), RequestSlotError> {
        let names = [Box::<str>::from("x-context")];
        let mut headers = Vec::new();
        let first = RequestHeader::new("X-CONTEXT", "first");
        {
            let mut slots = RequestSlots::new(&mut headers, &names);
            slots.fill(first.clone())?;
            assert_eq!(
                slots
                    .fill(RequestHeader::new("x-context", "second"))
                    .map_err(|error| error.kind()),
                Err(RequestSlotErrorKind::AlreadyFilled)
            );
        }
        assert_eq!(headers, [first]);
        Ok(())
    }

    #[test]
    fn invalid_header_values_leave_the_slot_available() -> Result<(), RequestSlotError> {
        let names = [Box::<str>::from("x-context")];
        let mut headers = vec![RequestHeader::new("X-Existing", "unchanged")];
        for value in [
            b"value\r\ninjected: header".as_slice(),
            b"value\n",
            b"value\0",
            b"value\x7f",
        ] {
            let mut slots = RequestSlots::new(&mut headers, &names);
            assert_eq!(
                slots
                    .fill(RequestHeader::new("x-context", value))
                    .map_err(|error| error.kind()),
                Err(RequestSlotErrorKind::InvalidValue)
            );
            assert!(!slots.is_filled("x-context"));
        }
        assert_eq!(headers, [RequestHeader::new("X-Existing", "unchanged")]);
        RequestSlots::new(&mut headers, &names).fill(RequestHeader::new("x-context", ""))?;
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].value(), b"");
        Ok(())
    }

    #[test]
    fn diagnostics_omit_names_and_values_even_without_sensitivity() {
        let names = [Box::<str>::from("x-private-declaration-marker")];
        let mut headers = vec![RequestHeader::new(
            "x-private-declaration-marker",
            "private-value-marker",
        )];
        let mut slots = RequestSlots::new(&mut headers, &names);
        let errors = [
            slots
                .fill(RequestHeader::new(
                    "x-private-undeclared-marker",
                    "private-value-marker",
                ))
                .err(),
            slots
                .fill(RequestHeader::new(
                    "x-private-declaration-marker",
                    "private-value-marker",
                ))
                .err(),
        ];
        assert_eq!(
            errors.map(|error| error.map(|error| error.kind())),
            [
                Some(RequestSlotErrorKind::Undeclared),
                Some(RequestSlotErrorKind::AlreadyFilled),
            ]
        );
        let debug = format!("{slots:?}");
        assert!(debug.contains("declared_slot_count: 1"));
        assert!(debug.contains("filled_slot_count: 1"));
        for error in errors.into_iter().flatten() {
            for diagnostic in [format!("{error:?}"), error.to_string()] {
                assert!(!diagnostic.contains("marker"));
            }
        }
        assert!(!debug.contains("marker"));
        let mut empty = Vec::new();
        let error = RequestSlots::new(&mut empty, &names)
            .fill(RequestHeader::new(
                "x-private-declaration-marker",
                b"private-invalid-marker\r\n",
            ))
            .err();
        assert_eq!(
            error.map(|error| error.kind()),
            Some(RequestSlotErrorKind::InvalidValue)
        );
        if let Some(error) = error {
            assert!(!format!("{error:?} {error}").contains("marker"));
        }
    }

    #[test]
    fn public_types_keep_send_sync_and_error_traits() {
        fn slots<T: std::fmt::Debug + Send + Sync>() {}
        slots::<RequestSlots<'static>>();
        fn error<T: Clone + Copy + std::fmt::Debug + Eq + std::error::Error + Send + Sync>() {}
        error::<RequestSlotError>();
        fn kind<T: Clone + Copy + std::fmt::Debug + Eq + Send + Sync>() {}
        kind::<RequestSlotErrorKind>();
    }
}
