//! Complete proxy connect description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{
    Http2ProxyConnections, Http2RejectedConnect, ProxyConnectField, ProxyConnectTemplate,
};

pub(super) fn parse(v: &Value) -> Result<ProxyConnectTemplate> {
    v.record(
        &[
            "http1_fields",
            "http2_fields",
            "http2_rejected",
            "http2_connections",
        ],
        "proxy_connect",
    )?;
    let settings = ProxyConnectTemplate {
        http1_fields: v
            .member("http1_fields", "proxy_connect.http1_fields")?
            .list("proxy_connect.http1_fields", field)?,
        http2_fields: v
            .member("http2_fields", "proxy_connect.http2_fields")?
            .list("proxy_connect.http2_fields", field)?,
        http2_rejected: rejected(v.member("http2_rejected", "proxy_connect.http2_rejected")?)?,
        http2_connections: connections(
            v.member("http2_connections", "proxy_connect.http2_connections")?,
        )?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("proxy_connect", error))?;
    Ok(settings)
}

fn rejected(v: &Value) -> Result<Http2RejectedConnect> {
    match v.text("proxy_connect.http2_rejected")? {
        "EndStream" => Ok(Http2RejectedConnect::EndStream),
        "LeaveOpen" => Ok(Http2RejectedConnect::LeaveOpen),
        _ => Err(json::unsupported("proxy_connect.http2_rejected")),
    }
}

fn connections(v: &Value) -> Result<Http2ProxyConnections> {
    match v.text("proxy_connect.http2_connections")? {
        "Shared" => Ok(Http2ProxyConnections::Shared),
        "ByPurpose" => Ok(Http2ProxyConnections::ByPurpose),
        _ => Err(json::unsupported("proxy_connect.http2_connections")),
    }
}

fn field(v: &Value) -> Result<ProxyConnectField> {
    match v
        .member("kind", "proxy_connect.fields.kind")?
        .text("proxy_connect.fields.kind")?
    {
        "Authority" => {
            v.record(&["kind", "name"], "proxy_connect.fields")?;
            Ok(ProxyConnectField::Authority {
                name: v
                    .member("name", "proxy_connect.fields.name")?
                    .text("proxy_connect.fields.name")?
                    .into(),
            })
        }
        "Literal" => {
            v.record(&["kind", "name", "value"], "proxy_connect.fields")?;
            Ok(ProxyConnectField::Literal {
                name: v
                    .member("name", "proxy_connect.fields.name")?
                    .text("proxy_connect.fields.name")?
                    .into(),
                value: v
                    .member("value", "proxy_connect.fields.value")?
                    .text("proxy_connect.fields.value")?
                    .into(),
            })
        }
        "FromRequest" => {
            v.record(&["kind", "name"], "proxy_connect.fields")?;
            Ok(ProxyConnectField::FromRequest {
                name: v
                    .member("name", "proxy_connect.fields.name")?
                    .text("proxy_connect.fields.name")?
                    .into(),
            })
        }
        "ProxyAuthorization" => {
            v.record(&["kind", "name"], "proxy_connect.fields")?;
            Ok(ProxyConnectField::ProxyAuthorization {
                name: v
                    .member("name", "proxy_connect.fields.name")?
                    .text("proxy_connect.fields.name")?
                    .into(),
            })
        }
        _ => Err(json::unsupported("proxy_connect.fields.kind")),
    }
}
