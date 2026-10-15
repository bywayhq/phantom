//! Borrowed immutable template values copied into the owned customization API.

use std::fmt;

use crate::{Http2Priority, ProxyAuthorizationAttempt, RequestField, RequestTemplate};

pub(super) enum RequestFieldDefinition {
    Literal {
        name: &'static str,
        value: &'static str,
    },
    Caller {
        name: &'static str,
        required: bool,
    },
    ClientHint {
        name: &'static str,
    },
    ClientHints,
    ByTrust {
        name: &'static str,
        trustworthy: Option<&'static str>,
        untrustworthy: Option<&'static str>,
    },
    ByForwarding {
        name: &'static str,
        unforwarded: Option<&'static str>,
        forwarded: Option<&'static str>,
    },
    ProxyAuthorization {
        name: &'static str,
        attempt: ProxyAuthorizationAttempt,
    },
    RestartClientHints,
    AltUsed,
}

impl RequestFieldDefinition {
    fn instantiate(&self) -> RequestField {
        match *self {
            Self::Literal { name, value } => RequestField::Literal {
                name: name.into(),
                value: value.into(),
            },
            Self::Caller { name, required } => RequestField::Caller {
                name: name.into(),
                required,
            },
            Self::ClientHint { name } => RequestField::ClientHint { name: name.into() },
            Self::ClientHints => RequestField::ClientHints,
            Self::ByTrust {
                name,
                trustworthy,
                untrustworthy,
            } => RequestField::ByTrust {
                name: name.into(),
                trustworthy: trustworthy.map(Into::into),
                untrustworthy: untrustworthy.map(Into::into),
            },
            Self::ByForwarding {
                name,
                unforwarded,
                forwarded,
            } => RequestField::ByForwarding {
                name: name.into(),
                unforwarded: unforwarded.map(Into::into),
                forwarded: forwarded.map(Into::into),
            },
            Self::ProxyAuthorization { name, attempt } => RequestField::ProxyAuthorization {
                name: name.into(),
                attempt,
            },
            Self::RestartClientHints => RequestField::RestartClientHints,
            Self::AltUsed => RequestField::AltUsed,
        }
    }
}

pub(super) struct RequestTemplateDefinition {
    pub(super) http1_fields: &'static [RequestFieldDefinition],
    pub(super) http2_fields: &'static [RequestFieldDefinition],
    pub(super) http3_fields: Option<&'static [RequestFieldDefinition]>,
    pub(super) http2_priority: Option<Http2Priority>,
    pub(super) requested_client_hint_placement: bool,
    pub(super) restarts_for_connection_accept_ch: bool,
}

impl RequestTemplateDefinition {
    pub(super) fn instantiate(&self) -> RequestTemplate {
        let fields = |definitions: &[RequestFieldDefinition]| {
            definitions
                .iter()
                .map(RequestFieldDefinition::instantiate)
                .collect()
        };
        RequestTemplate {
            http1_fields: fields(self.http1_fields),
            http2_fields: fields(self.http2_fields),
            http3_fields: self.http3_fields.map(fields),
            http2_priority: self.http2_priority,
            requested_client_hint_placement: self.requested_client_hint_placement,
            restarts_for_connection_accept_ch: self.restarts_for_connection_accept_ch,
        }
    }
}

impl fmt::Debug for RequestTemplateDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestTemplateDefinition")
            .field("http1_field_count", &self.http1_fields.len())
            .field("http2_field_count", &self.http2_fields.len())
            .field(
                "http3_field_count",
                &self.http3_fields.map(|fields| fields.len()),
            )
            .field("http2_priority", &self.http2_priority)
            .field(
                "requested_client_hint_placement",
                &self.requested_client_hint_placement,
            )
            .field(
                "restarts_for_connection_accept_ch",
                &self.restarts_for_connection_accept_ch,
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::RequestTemplateDefinition;

    #[test]
    fn an_empty_http3_list_remains_distinct_from_an_absent_list() {
        let instantiate = |http3_fields| {
            RequestTemplateDefinition {
                http1_fields: &[],
                http2_fields: &[],
                http3_fields,
                http2_priority: None,
                requested_client_hint_placement: true,
                restarts_for_connection_accept_ch: true,
            }
            .instantiate()
        };
        let absent = instantiate(None);
        let empty = instantiate(Some(&[]));
        assert!(absent.http3_fields.is_none());
        assert_eq!(empty.http3_fields, Some(Vec::new()));
        assert_ne!(absent, empty);
        assert!(absent.validate().is_ok());
        assert!(empty.validate().is_ok());
    }
}
