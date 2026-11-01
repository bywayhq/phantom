//! Bounded typed snapshot conversion on the owning JavaScript environment.

use napi::{
    JsString, Result,
    bindgen_prelude::{Array, BigInt, JsObjectValue, Object},
};
use napi_derive::napi;
use phantom::{
    AltSvcSnapshot, AltSvcSnapshotEntry, CookieSameSite, CookieSnapshot, CookieSnapshotEntry,
    CookieSourceScheme,
};

use crate::state_transfer::{self as state, failure};

#[derive(Clone, Copy)]
pub(super) enum RouteTransfer {
    Checkpoint,
    Tickets,
}

impl RouteTransfer {
    fn failure(self, kind: &str) -> napi::Error {
        match self {
            Self::Checkpoint => crate::session::failure(kind),
            Self::Tickets => failure("SessionTickets", kind, None),
        }
    }
}

pub(super) fn receiving_routes(
    input: Array<'_>,
    transfer: RouteTransfer,
) -> Result<Vec<phantom::Route>> {
    if input.len() as usize > crate::session::MAXIMUM_ROUTES {
        return Err(transfer.failure("too_large"));
    }
    let mut remaining: usize = 65536;
    let mut routes = Vec::new();
    routes
        .try_reserve_exact(input.len() as usize)
        .map_err(|_| transfer.failure("allocation"))?;
    for index in 0..input.len() {
        let object: Object<'_> = input
            .get(index)?
            .ok_or_else(|| crate::error::failure("InvalidProxy", "invalid receiving route"))?;
        let kind: JsString<'_> = object.get_named_property("route")?;
        if kind.utf8_len()? > 6 {
            return Err(crate::error::failure(
                "InvalidProxy",
                "invalid receiving route",
            ));
        }
        let kind = kind.into_utf8()?;
        let kind = kind.as_str()?;
        if !matches!(kind, "direct" | "proxy") {
            return Err(crate::error::failure(
                "InvalidProxy",
                "invalid receiving route",
            ));
        }
        let mut text = |name: &str| -> Result<Option<String>> {
            let value: Option<JsString<'_>> = object.get_named_property(name)?;
            value
                .map(|value| {
                    remaining = remaining
                        .checked_sub(value.utf8_len()?)
                        .ok_or_else(|| transfer.failure("too_large"))?;
                    Ok(value.into_utf8()?.as_str()?.to_owned())
                })
                .transpose()
        };
        let proxy = text("proxy")?;
        let username = text("proxyUsername")?;
        let password = text("proxyPassword")?;
        let user_id = text("proxyUserId")?;
        routes.push(crate::client::route(
            kind,
            proxy.as_deref(),
            username.as_deref(),
            password.as_deref(),
            user_id.as_deref(),
        )?);
    }
    Ok(routes)
}

pub(super) fn ticket_bytes(
    env: &napi::Env,
    input: napi::bindgen_prelude::Buffer,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    super::buffer::copy_buffer(env, input, state::MAXIMUM_TICKETS)
        .map(zeroize::Zeroizing::new)
        .map_err(|error| {
            if error.reason.starts_with("PHANTOM:InputLimit:") {
                failure("SessionTickets", "too_large", None)
            } else {
                error
            }
        })
}

pub(super) fn ticket_key(
    env: &napi::Env,
    input: napi::bindgen_prelude::Buffer,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let bytes =
        zeroize::Zeroizing::new(super::buffer::copy_buffer(env, input, 32).map_err(|error| {
            if error.reason.starts_with("PHANTOM:InputLimit:") {
                failure("SessionTickets", "invalid_key_length", None)
            } else {
                error
            }
        })?);
    if bytes.len() != 32 {
        return Err(failure("SessionTickets", "invalid_key_length", None));
    }
    let mut key = zeroize::Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Credential-bearing fields are omitted from Debug.
#[napi(object, object_from_js = false)]
pub struct CookieEntry {
    /// Scheme of the URL that set the cookie.
    pub source_scheme: String,
    /// Cookie name; credential-bearing.
    pub name: String,
    /// Cookie value; credential-bearing.
    pub value: String,
    /// Canonical ASCII cookie domain.
    pub domain: String,
    /// Cookie path.
    pub path: String,
    /// Restricts matching to the exact domain.
    pub host_only: bool,
    /// Requires a secure origin.
    pub secure: bool,
    /// HttpOnly attribute.
    pub http_only: bool,
    /// Lowercase SameSite attribute, when set.
    pub same_site: Option<String>,
    /// Schemeful partition site, when set.
    pub partition_key: Option<String>,
    /// Signed Unix nanoseconds; absent for session cookies.
    pub expires_at_nanoseconds: Option<BigInt>,
}

impl std::fmt::Debug for CookieEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CookieEntry")
            .finish_non_exhaustive()
    }
}

/// Direct-route alternatives; no validation or trust state is transferred.
#[napi(object, object_from_js = false)]
pub struct AltSvcEntry {
    /// Canonical HTTPS origin.
    pub origin: String,
    /// Canonical unbracketed alternative host.
    pub alternative_host: String,
    /// Nonzero UDP port.
    pub alternative_port: u16,
    /// Signed Unix nanoseconds.
    pub expires_at_nanoseconds: BigInt,
}

impl std::fmt::Debug for AltSvcEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AltSvcEntry")
            .finish_non_exhaustive()
    }
}

struct TextBudget(usize);

fn expiry(object: &Object<'_>) -> Result<Option<std::time::SystemTime>> {
    let value: Option<BigInt> = object.get_named_property("expiresAtNanoseconds")?;
    value.map(state::time).transpose()
}

impl TextBudget {
    fn take(&mut self, length: usize) -> Result<()> {
        self.0 = self
            .0
            .checked_sub(length)
            .ok_or_else(|| failure("StateSnapshot", "too_large", None))?;
        Ok(())
    }

    fn string(&mut self, object: &Object<'_>, name: &str) -> Result<String> {
        let value: JsString<'_> = object.get_named_property(name)?;
        // Inspect the UTF-8 length before allocating the native string copy.
        self.take(value.utf8_len()?)?;
        Ok(value.into_utf8()?.as_str()?.to_owned())
    }

    fn optional_string(&mut self, object: &Object<'_>, name: &str) -> Result<Option<String>> {
        let value: Option<JsString<'_>> = object.get_named_property(name)?;
        value
            .map(|value| {
                self.take(value.utf8_len()?)?;
                Ok(value.into_utf8()?.as_str()?.to_owned())
            })
            .transpose()
    }
}

pub(super) fn cookies(input: Array<'_>) -> Result<CookieSnapshot> {
    if input.len() > state::MAXIMUM_COOKIES {
        return Err(failure("CookieSnapshot", "too_large", None));
    }
    let mut budget = TextBudget(state::MAXIMUM_TEXT);
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(input.len() as usize)
        .map_err(|_| failure("CookieSnapshot", "allocation", None))?;
    for index in 0..input.len() {
        let object: Object<'_> = input
            .get(index)?
            .ok_or_else(|| failure("CookieSnapshot", "invalid_entry", Some(index as usize)))?;
        let scheme = match budget.string(&object, "sourceScheme")?.as_str() {
            "http" => CookieSourceScheme::Http,
            "https" => CookieSourceScheme::Https,
            _ => {
                return Err(failure(
                    "CookieSnapshot",
                    "invalid_cookie",
                    Some(index as usize),
                ));
            }
        };
        let mut entry = CookieSnapshotEntry::new(
            scheme,
            budget.string(&object, "name")?,
            budget.string(&object, "value")?,
            budget.string(&object, "domain")?,
            budget.string(&object, "path")?,
        )
        .with_host_only(object.get_named_property("hostOnly")?)
        .with_secure(object.get_named_property("secure")?)
        .with_http_only(object.get_named_property("httpOnly")?);
        if let Some(same_site) = budget.optional_string(&object, "sameSite")? {
            entry = entry.with_same_site(match same_site.as_str() {
                "strict" => CookieSameSite::Strict,
                "lax" => CookieSameSite::Lax,
                "none" => CookieSameSite::None,
                _ => {
                    return Err(failure(
                        "CookieSnapshot",
                        "invalid_cookie",
                        Some(index as usize),
                    ));
                }
            });
        }
        if let Some(partition) = budget.optional_string(&object, "partitionKey")? {
            entry = entry.with_partition_key(partition);
        }
        if let Some(expiry) = expiry(&object)? {
            entry = entry.with_expires_at(expiry);
        }
        entries.push(entry);
    }
    Ok(CookieSnapshot::new(entries))
}

pub(super) fn alternatives(input: Array<'_>) -> Result<AltSvcSnapshot> {
    if input.len() > state::MAXIMUM_ALTERNATIVES {
        return Err(failure("AltSvcSnapshot", "too_large", None));
    }
    let mut budget = TextBudget(state::MAXIMUM_TEXT);
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(input.len() as usize)
        .map_err(|_| failure("AltSvcSnapshot", "allocation", None))?;
    for index in 0..input.len() {
        let object: Object<'_> = input
            .get(index)?
            .ok_or_else(|| failure("AltSvcSnapshot", "invalid_entry", Some(index as usize)))?;
        let port: f64 = object.get_named_property("alternativePort")?;
        if !port.is_finite() || port.fract() != 0.0 || !(1.0..=65535.0).contains(&port) {
            return Err(failure(
                "AltSvcSnapshot",
                "invalid_alternative",
                Some(index as usize),
            ));
        }
        entries.push(AltSvcSnapshotEntry::new(
            budget.string(&object, "origin")?,
            budget.string(&object, "alternativeHost")?,
            port as u16,
            expiry(&object)?
                .ok_or_else(|| failure("AltSvcSnapshot", "invalid_expiry", Some(index as usize)))?,
        ));
    }
    Ok(AltSvcSnapshot::new(entries))
}

pub(super) fn export_cookies(snapshot: CookieSnapshot) -> Result<Vec<CookieEntry>> {
    if snapshot.entries().len() > state::MAXIMUM_COOKIES as usize {
        return Err(failure("CookieSnapshot", "too_large", None));
    }
    let mut budget = TextBudget(state::MAXIMUM_TEXT);
    snapshot
        .entries()
        .iter()
        .map(|entry| {
            for value in [
                entry.name(),
                entry.value(),
                entry.domain(),
                entry.path(),
                entry.partition_key().unwrap_or(""),
            ] {
                budget.take(value.len())?;
            }
            budget.take(match entry.source_scheme() {
                CookieSourceScheme::Http => 4,
                CookieSourceScheme::Https => 5,
            })?;
            budget.take(entry.same_site().map_or(0, |value| match value {
                CookieSameSite::Strict => 6,
                CookieSameSite::Lax => 3,
                CookieSameSite::None => 4,
            }))?;
            Ok(CookieEntry {
                source_scheme: match entry.source_scheme() {
                    CookieSourceScheme::Http => "http",
                    CookieSourceScheme::Https => "https",
                }
                .into(),
                name: entry.name().into(),
                value: entry.value().into(),
                domain: entry.domain().into(),
                path: entry.path().into(),
                host_only: entry.host_only(),
                secure: entry.secure(),
                http_only: entry.http_only(),
                same_site: entry.same_site().map(|value| {
                    match value {
                        CookieSameSite::Strict => "strict",
                        CookieSameSite::Lax => "lax",
                        CookieSameSite::None => "none",
                    }
                    .into()
                }),
                partition_key: entry.partition_key().map(Into::into),
                expires_at_nanoseconds: entry.expires_at().map(state::timestamp),
            })
        })
        .collect()
}

pub(super) fn export_alternatives(snapshot: AltSvcSnapshot) -> Result<Vec<AltSvcEntry>> {
    if snapshot.entries().len() > state::MAXIMUM_ALTERNATIVES as usize {
        return Err(failure("AltSvcSnapshot", "too_large", None));
    }
    let mut budget = TextBudget(state::MAXIMUM_TEXT);
    snapshot
        .entries()
        .iter()
        .map(|entry| {
            budget.take(entry.origin().len())?;
            budget.take(entry.alternative_host().len())?;
            Ok(AltSvcEntry {
                origin: entry.origin().into(),
                alternative_host: entry.alternative_host().into(),
                alternative_port: entry.alternative_port(),
                expires_at_nanoseconds: state::timestamp(entry.expires_at()),
            })
        })
        .collect()
}
