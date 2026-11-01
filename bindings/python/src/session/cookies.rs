//! Editable cookie metadata; the core validates the complete snapshot before mutation.

use phantom::{
    Client, CookieSameSite, CookieSnapshot, CookieSnapshotEntry, CookieSnapshotError,
    CookieSnapshotErrorKind, CookieSourceScheme,
};
use pyo3::{prelude::*, types::PyList};

use super::{
    MAXIMUM_TEXT, owned_text_size, timestamp, transfer_failure, unix_nanos, validate_entries,
};
use crate::error;

const MAXIMUM_ENTRIES: usize = 16384;

pub(crate) type Fields = (
    String,
    String,
    String,
    String,
    bool,
    String,
    bool,
    bool,
    Option<String>,
    Option<String>,
    Option<i128>,
);

fn failure(error: CookieSnapshotError) -> PyErr {
    let kind = match error.kind() {
        CookieSnapshotErrorKind::Disabled => "disabled",
        CookieSnapshotErrorKind::InvalidCookie => "invalid_cookie",
        CookieSnapshotErrorKind::CookieTooLarge => "cookie_too_large",
        CookieSnapshotErrorKind::PublicSuffix => "public_suffix",
        CookieSnapshotErrorKind::InvalidPrefix => "invalid_prefix",
        CookieSnapshotErrorKind::UnsupportedPolicy => "unsupported_policy",
        CookieSnapshotErrorKind::InvalidPartitionKey => "invalid_partition_key",
        _ => "unknown",
    };
    transfer_failure("cookie_snapshot", kind, error.entry_index())
}

pub(crate) fn export(py: Python<'_>, client: &Client) -> PyResult<Option<Vec<Fields>>> {
    py.detach(|| {
        let Some(snapshot) = client.export_cookies() else {
            return Ok(None);
        };
        if snapshot.entries().len() > MAXIMUM_ENTRIES {
            return Err(error::input("state_transfer_limit"));
        }
        let mut remaining = MAXIMUM_TEXT;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(snapshot.entries().len())
            .map_err(|_| transfer_failure("cookie_snapshot", "allocation", None))?;
        for entry in snapshot.entries() {
            let scheme = match entry.source_scheme() {
                CookieSourceScheme::Http => "http",
                CookieSourceScheme::Https => "https",
            };
            let same_site = entry.same_site().map(|value| match value {
                CookieSameSite::Strict => "strict",
                CookieSameSite::Lax => "lax",
                CookieSameSite::None => "none",
            });
            owned_text_size(
                [
                    scheme,
                    entry.name(),
                    entry.value(),
                    entry.domain(),
                    entry.path(),
                    same_site.unwrap_or(""),
                    entry.partition_key().unwrap_or(""),
                ],
                &mut remaining,
            )?;
            entries.push((
                scheme.to_owned(),
                entry.name().to_owned(),
                entry.value().to_owned(),
                entry.domain().to_owned(),
                entry.host_only(),
                entry.path().to_owned(),
                entry.secure(),
                entry.http_only(),
                same_site.map(str::to_owned),
                entry.partition_key().map(str::to_owned),
                entry.expires_at().map(unix_nanos).transpose()?,
            ));
        }
        Ok(Some(entries))
    })
}

pub(crate) fn import(py: Python<'_>, client: &Client, entries: &Bound<'_, PyList>) -> PyResult<()> {
    validate_entries(
        entries,
        MAXIMUM_ENTRIES,
        11,
        &[0, 1, 2, 3, 5],
        &[8, 9],
        &[4, 6, 7],
    )?;
    let mut snapshot = Vec::new();
    snapshot
        .try_reserve_exact(entries.len())
        .map_err(|_| transfer_failure("cookie_snapshot", "allocation", None))?;
    for value in entries.iter() {
        let value = value.cast_exact::<pyo3::types::PyTuple>()?;
        let expiry = value.get_item(10)?;
        let expiry = if expiry.is_none() {
            None
        } else {
            Some(timestamp(&expiry)?)
        };
        let (
            scheme,
            name,
            contents,
            domain,
            host_only,
            path,
            secure,
            http_only,
            same_site,
            partition,
            _,
        ): Fields = value.extract()?;
        let scheme = match scheme.as_str() {
            "http" => CookieSourceScheme::Http,
            "https" => CookieSourceScheme::Https,
            _ => return Err(error::input("invalid_cookie_source_scheme")),
        };
        let same_site = same_site
            .as_deref()
            .map(|value| match value {
                "strict" => Ok(CookieSameSite::Strict),
                "lax" => Ok(CookieSameSite::Lax),
                "none" => Ok(CookieSameSite::None),
                _ => Err(error::input("invalid_cookie_same_site")),
            })
            .transpose()?;
        let mut entry = CookieSnapshotEntry::new(scheme, name, contents, domain, path)
            .with_host_only(host_only)
            .with_secure(secure)
            .with_http_only(http_only);
        if let Some(value) = same_site {
            entry = entry.with_same_site(value);
        }
        if let Some(value) = partition {
            entry = entry.with_partition_key(value);
        }
        if let Some(value) = expiry {
            entry = entry.with_expires_at(value);
        }
        snapshot.push(entry);
    }
    py.detach(|| {
        client
            .import_cookies(&CookieSnapshot::new(snapshot))
            .map_err(failure)
    })
}
