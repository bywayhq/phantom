//! Complete request template description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{
    Http2RequestPriority, ProxyAuthorizationAttempt, RequestField, RequestTemplate,
};

pub(super) fn parse(v: &Value) -> Result<RequestTemplate> {
    v.record(
        &[
            "http1_fields",
            "http2_fields",
            "http3_fields",
            "http2_priority",
            "requested_client_hint_placement",
            "restarts_for_connection_accept_ch",
        ],
        "request_template",
    )?;
    let settings = RequestTemplate {
        http1_fields: v
            .member("http1_fields", "request_template.http1_fields")?
            .list("request_template.http1_fields", field)?,
        http2_fields: v
            .member("http2_fields", "request_template.http2_fields")?
            .list("request_template.http2_fields", field)?,
        http3_fields: v
            .member("http3_fields", "request_template.http3_fields")?
            .optional(|v| v.list("request_template.http3_fields", field))?,
        http2_priority: v
            .member("http2_priority", "request_template.http2_priority")?
            .optional(priority)?,
        requested_client_hint_placement: v
            .member(
                "requested_client_hint_placement",
                "request_template.requested_client_hint_placement",
            )?
            .boolean("request_template.requested_client_hint_placement")?,
        restarts_for_connection_accept_ch: v
            .member(
                "restarts_for_connection_accept_ch",
                "request_template.restarts_for_connection_accept_ch",
            )?
            .boolean("request_template.restarts_for_connection_accept_ch")?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("request_template", error))?;
    Ok(settings)
}

fn priority(v: &Value) -> Result<Http2RequestPriority> {
    const FIELD: &str = "request_template.http2_priority";
    let weight = || {
        v.member("weight", "request_template.http2_priority.weight")?
            .integer("request_template.http2_priority.weight")
    };
    let exclusive = || {
        v.member("exclusive", "request_template.http2_priority.exclusive")?
            .boolean("request_template.http2_priority.exclusive")
    };
    const VARIANT: &str = "request_template.http2_priority.variant";
    match v.member("variant", VARIANT)?.text(VARIANT)? {
        "Fixed" => {
            v.record(
                &["variant", "dependency_stream_id", "weight", "exclusive"],
                FIELD,
            )?;
            Ok(Http2RequestPriority::Fixed(
                phantom_profile::Http2Priority {
                    dependency_stream_id: v
                        .member(
                            "dependency_stream_id",
                            "request_template.http2_priority.dependency_stream_id",
                        )?
                        .integer("request_template.http2_priority.dependency_stream_id")?,
                    weight: weight()?,
                    exclusive: exclusive()?,
                },
            ))
        }
        "WeightBand" => {
            v.record(&["variant", "weight", "exclusive"], FIELD)?;
            Ok(Http2RequestPriority::WeightBand {
                weight: weight()?,
                exclusive: exclusive()?,
            })
        }
        _ => Err(json::unsupported(VARIANT)),
    }
}

fn attempt(v: &Value) -> Result<ProxyAuthorizationAttempt> {
    match v.text("request_template.fields.attempt")? {
        "Every" => Ok(ProxyAuthorizationAttempt::Every),
        "Preemptive" => Ok(ProxyAuthorizationAttempt::Preemptive),
        "Replay" => Ok(ProxyAuthorizationAttempt::Replay),
        _ => Err(json::unsupported("request_template.fields.attempt")),
    }
}

fn field(v: &Value) -> Result<RequestField> {
    match v
        .member("variant", "request_template.fields.variant")?
        .text("request_template.fields.variant")?
    {
        "Literal" => {
            v.record(&["variant", "name", "value"], "request_template.fields")?;
            Ok(RequestField::Literal {
                name: v
                    .member("name", "request_template.fields.name")?
                    .text("request_template.fields.name")?
                    .into(),
                value: v
                    .member("value", "request_template.fields.value")?
                    .text("request_template.fields.value")?
                    .into(),
            })
        }
        "Caller" => {
            v.record(&["variant", "name", "required"], "request_template.fields")?;
            Ok(RequestField::Caller {
                name: v
                    .member("name", "request_template.fields.name")?
                    .text("request_template.fields.name")?
                    .into(),
                required: v
                    .member("required", "request_template.fields.required")?
                    .boolean("request_template.fields.required")?,
            })
        }
        "ClientHint" => {
            v.record(&["variant", "name"], "request_template.fields")?;
            Ok(RequestField::ClientHint {
                name: v
                    .member("name", "request_template.fields.name")?
                    .text("request_template.fields.name")?
                    .into(),
            })
        }
        "ClientHints" => {
            v.record(&["variant"], "request_template.fields")?;
            Ok(RequestField::ClientHints)
        }
        "ByTrust" => {
            v.record(
                &["variant", "name", "trustworthy", "untrustworthy"],
                "request_template.fields",
            )?;
            Ok(RequestField::ByTrust {
                name: v
                    .member("name", "request_template.fields.name")?
                    .text("request_template.fields.name")?
                    .into(),
                trustworthy: v
                    .member("trustworthy", "request_template.fields.trustworthy")?
                    .optional(|v| Ok(v.text("request_template.fields.trustworthy")?.into()))?,
                untrustworthy: v
                    .member("untrustworthy", "request_template.fields.untrustworthy")?
                    .optional(|v| Ok(v.text("request_template.fields.untrustworthy")?.into()))?,
            })
        }
        "ByForwarding" => {
            v.record(
                &["variant", "name", "unforwarded", "forwarded"],
                "request_template.fields",
            )?;
            Ok(RequestField::ByForwarding {
                name: v
                    .member("name", "request_template.fields.name")?
                    .text("request_template.fields.name")?
                    .into(),
                unforwarded: v
                    .member("unforwarded", "request_template.fields.unforwarded")?
                    .optional(|v| Ok(v.text("request_template.fields.unforwarded")?.into()))?,
                forwarded: v
                    .member("forwarded", "request_template.fields.forwarded")?
                    .optional(|v| Ok(v.text("request_template.fields.forwarded")?.into()))?,
            })
        }
        "ProxyAuthorization" => {
            v.record(&["variant", "name", "attempt"], "request_template.fields")?;
            Ok(RequestField::ProxyAuthorization {
                name: v
                    .member("name", "request_template.fields.name")?
                    .text("request_template.fields.name")?
                    .into(),
                attempt: attempt(v.member("attempt", "request_template.fields.attempt")?)?,
            })
        }
        "AltUsed" => {
            v.record(&["variant"], "request_template.fields")?;
            Ok(RequestField::AltUsed)
        }
        "RestartClientHints" => {
            v.record(&["variant"], "request_template.fields")?;
            Ok(RequestField::RestartClientHints)
        }
        _ => Err(json::unsupported("request_template.fields.variant")),
    }
}
