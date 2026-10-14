//! Complete HTTP/1 description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{Http1IdleTimeout, Http1Settings};

pub(super) fn parse(v: &Value) -> Result<Http1Settings> {
    v.record(&["max_connections_per_origin", "idle_timeout"], "http1")?;
    let settings = Http1Settings {
        max_connections_per_origin: v
            .member(
                "max_connections_per_origin",
                "http1.max_connections_per_origin",
            )?
            .nonzero_usize("http1.max_connections_per_origin")?,
        idle_timeout: idle(v.member("idle_timeout", "http1.idle_timeout")?)?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("http1", error))?;
    Ok(settings)
}

fn idle(v: &Value) -> Result<Http1IdleTimeout> {
    match v
        .member("kind", "http1.idle_timeout")?
        .text("http1.idle_timeout")?
    {
        "Unlimited" => {
            v.record(&["kind"], "http1.idle_timeout")?;
            Ok(Http1IdleTimeout::Unlimited)
        }
        "CheckedOnRequest" => {
            v.record(&["kind", "duration"], "http1.idle_timeout")?;
            Ok(Http1IdleTimeout::CheckedOnRequest(
                v.member("duration", "http1.idle_timeout.duration")?
                    .duration("http1.idle_timeout.duration")?,
            ))
        }
        "ClosedOnTimer" => {
            v.record(&["kind", "duration"], "http1.idle_timeout")?;
            Ok(Http1IdleTimeout::ClosedOnTimer(
                v.member("duration", "http1.idle_timeout.duration")?
                    .duration("http1.idle_timeout.duration")?,
            ))
        }
        _ => Err(json::unsupported("http1.idle_timeout")),
    }
}
