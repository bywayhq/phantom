//! Typed, caller-owned cookie, Alt-Svc and encrypted ticket transfers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use phantom::{
    AltSvcSnapshot, AltSvcSnapshotEntry, AltSvcSnapshotErrorKind, Client, CookieSameSite,
    CookieSnapshot, CookieSnapshotEntry, CookieSnapshotErrorKind, CookieSourceScheme, Route,
    SessionTicketErrorKind, SessionTicketSnapshot,
};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Failure;

pub(crate) const MAX_COOKIES: usize = 16_384;
pub(crate) const MAX_ALTERNATIVES: usize = 32_768;
pub(crate) const MAX_TEXT: usize = 32 * 1024 * 1024;
pub(crate) const MAX_TICKETS: usize = 16 * 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Text {
    pub(crate) offset: u64,
    pub(crate) length: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Timestamp {
    pub(crate) seconds: i64,
    pub(crate) nanoseconds: u64,
}

impl Timestamp {
    pub(crate) fn decode(self) -> Result<SystemTime, Failure> {
        if self.nanoseconds >= 1_000_000_000 {
            return Err(Failure::new("invalid_state_expiry"));
        }
        let seconds = Duration::from_secs(self.seconds.unsigned_abs());
        let base = if self.seconds < 0 {
            UNIX_EPOCH.checked_sub(seconds)
        } else {
            UNIX_EPOCH.checked_add(seconds)
        };
        let time = base
            .and_then(|time| time.checked_add(Duration::from_nanos(self.nanoseconds)))
            .ok_or_else(|| Failure::new("invalid_state_expiry"))?;
        if Self::encode(time)? != self {
            return Err(Failure::new("invalid_state_expiry"));
        }
        Ok(time)
    }

    fn encode(time: SystemTime) -> Result<Self, Failure> {
        match time.duration_since(UNIX_EPOCH) {
            Ok(value) => Ok(Self {
                seconds: i64::try_from(value.as_secs())
                    .map_err(|_| Failure::new("invalid_state_expiry"))?,
                nanoseconds: u64::from(value.subsec_nanos()),
            }),
            Err(error) => {
                let value = error.duration();
                let seconds = i64::try_from(value.as_secs())
                    .map_err(|_| Failure::new("invalid_state_expiry"))?;
                let (seconds, nanoseconds) = if value.subsec_nanos() == 0 {
                    (-seconds, 0)
                } else {
                    (
                        seconds
                            .checked_neg()
                            .and_then(|value| value.checked_sub(1))
                            .ok_or_else(|| Failure::new("invalid_state_expiry"))?,
                        1_000_000_000 - u64::from(value.subsec_nanos()),
                    )
                };
                Ok(Self {
                    seconds,
                    nanoseconds,
                })
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Cookie {
    pub(crate) name: Text,
    pub(crate) value: Text,
    pub(crate) domain: Text,
    pub(crate) path: Text,
    pub(crate) partition_key: Text,
    // host-only, secure, HttpOnly, partition present, expiry present.
    pub(crate) flags: u64,
    pub(crate) source_scheme: u64,
    pub(crate) same_site: u64,
    pub(crate) expiry: Timestamp,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Alternative {
    pub(crate) origin: Text,
    pub(crate) host: Text,
    pub(crate) port: u64,
    pub(crate) expiry: Timestamp,
}

fn text(arena: &[u8], value: Text) -> Result<&str, Failure> {
    let offset =
        usize::try_from(value.offset).map_err(|_| Failure::new("invalid_state_snapshot"))?;
    let length =
        usize::try_from(value.length).map_err(|_| Failure::new("invalid_state_snapshot"))?;
    let bytes = offset
        .checked_add(length)
        .and_then(|end| arena.get(offset..end))
        .ok_or_else(|| Failure::new("invalid_state_snapshot"))?;
    std::str::from_utf8(bytes).map_err(|_| Failure::new("invalid_state_snapshot"))
}

pub(crate) fn cookies(rows: &[Cookie], arena: &[u8]) -> Result<CookieSnapshot, Failure> {
    let mut entries = Vec::with_capacity(rows.len());
    let mut remaining = MAX_TEXT;
    for row in rows {
        if row.flags & !31 != 0
            || (row.flags & 8 == 0 && row.partition_key.length != 0)
            || (row.flags & 16 == 0 && row.expiry != Timestamp::default())
        {
            return Err(Failure::new("invalid_state_snapshot"));
        }
        let scheme = match row.source_scheme {
            1 => CookieSourceScheme::Http,
            2 => CookieSourceScheme::Https,
            _ => return Err(Failure::new("invalid_cookie_source_scheme")),
        };
        let mut take = |value| {
            let value = text(arena, value)?;
            remaining = remaining
                .checked_sub(value.len())
                .ok_or_else(|| Failure::new("input_limit"))?;
            Ok::<_, Failure>(value)
        };
        let mut entry = CookieSnapshotEntry::new(
            scheme,
            take(row.name)?,
            take(row.value)?,
            take(row.domain)?,
            take(row.path)?,
        )
        .with_host_only(row.flags & 1 != 0)
        .with_secure(row.flags & 2 != 0)
        .with_http_only(row.flags & 4 != 0);
        entry = match row.same_site {
            0 => entry,
            1 => entry.with_same_site(CookieSameSite::Strict),
            2 => entry.with_same_site(CookieSameSite::Lax),
            3 => entry.with_same_site(CookieSameSite::None),
            _ => return Err(Failure::new("invalid_cookie_same_site")),
        };
        if row.flags & 8 != 0 {
            entry = entry.with_partition_key(take(row.partition_key)?);
        }
        if row.flags & 16 != 0 {
            entry = entry.with_expires_at(row.expiry.decode()?);
        }
        entries.push(entry);
    }
    Ok(CookieSnapshot::new(entries))
}

pub(crate) fn alternatives(rows: &[Alternative], arena: &[u8]) -> Result<AltSvcSnapshot, Failure> {
    let mut entries = Vec::with_capacity(rows.len());
    let mut remaining = MAX_TEXT;
    for row in rows {
        let origin = text(arena, row.origin)?;
        let host = text(arena, row.host)?;
        remaining = remaining
            .checked_sub(origin.len())
            .and_then(|value| value.checked_sub(host.len()))
            .ok_or_else(|| Failure::new("input_limit"))?;
        let port = u16::try_from(row.port).map_err(|_| Failure::new("invalid_state_snapshot"))?;
        entries.push(AltSvcSnapshotEntry::new(
            origin,
            host,
            port,
            row.expiry.decode()?,
        ));
    }
    Ok(AltSvcSnapshot::new(entries))
}

pub(crate) enum Input {
    ExportCookies,
    ImportCookies(CookieSnapshot),
    ExportAltSvc,
    ImportAltSvc(AltSvcSnapshot),
    ExportTickets(Zeroizing<[u8; 32]>),
    ImportTickets(SessionTicketSnapshot, Zeroizing<[u8; 32]>, Vec<Route>),
}

pub(crate) struct ResultData {
    pub(crate) kind: u64,
    pub(crate) enabled: bool,
    pub(crate) cookies: Vec<Cookie>,
    pub(crate) alternatives: Vec<Alternative>,
    pub(crate) arena: Zeroizing<Vec<u8>>,
    pub(crate) error: Option<Failure>,
    pub(crate) entry: Option<usize>,
}

impl ResultData {
    fn new(kind: u64) -> Self {
        Self {
            kind,
            enabled: true,
            cookies: Vec::new(),
            alternatives: Vec::new(),
            arena: Zeroizing::new(Vec::new()),
            error: None,
            entry: None,
        }
    }

    fn put(&mut self, value: &str) -> Result<Text, Failure> {
        if value.len() > MAX_TEXT - self.arena.len() {
            return Err(Failure::new("state_transfer_limit"));
        }
        let span = Text {
            offset: self.arena.len() as u64,
            length: value.len() as u64,
        };
        self.arena.extend_from_slice(value.as_bytes());
        Ok(span)
    }

    fn export_cookies(&mut self, client: &Client) -> Result<(), Failure> {
        let Some(snapshot) = client.export_cookies() else {
            self.enabled = false;
            return Ok(());
        };
        if snapshot.len() > MAX_COOKIES {
            return Err(Failure::new("state_transfer_limit"));
        }
        for entry in snapshot.entries() {
            let row = Cookie {
                name: self.put(entry.name())?,
                value: self.put(entry.value())?,
                domain: self.put(entry.domain())?,
                path: self.put(entry.path())?,
                partition_key: self.put(entry.partition_key().unwrap_or_default())?,
                flags: u64::from(entry.host_only())
                    | (u64::from(entry.secure()) << 1)
                    | (u64::from(entry.http_only()) << 2)
                    | (u64::from(entry.partition_key().is_some()) << 3)
                    | (u64::from(entry.expires_at().is_some()) << 4),
                source_scheme: match entry.source_scheme() {
                    CookieSourceScheme::Http => 1,
                    CookieSourceScheme::Https => 2,
                },
                same_site: match entry.same_site() {
                    None => 0,
                    Some(CookieSameSite::Strict) => 1,
                    Some(CookieSameSite::Lax) => 2,
                    Some(CookieSameSite::None) => 3,
                },
                expiry: entry
                    .expires_at()
                    .map(Timestamp::encode)
                    .transpose()?
                    .unwrap_or_default(),
            };
            self.cookies.push(row);
        }
        Ok(())
    }

    fn export_alt_svc(&mut self, client: &Client) -> Result<(), Failure> {
        let Some(snapshot) = client.export_alt_svc() else {
            self.enabled = false;
            return Ok(());
        };
        if snapshot.len() > MAX_ALTERNATIVES {
            return Err(Failure::new("state_transfer_limit"));
        }
        for entry in snapshot.entries() {
            let row = Alternative {
                origin: self.put(entry.origin())?,
                host: self.put(entry.alternative_host())?,
                port: u64::from(entry.alternative_port()),
                expiry: Timestamp::encode(entry.expires_at())?,
            };
            self.alternatives.push(row);
        }
        Ok(())
    }
}

pub(crate) fn ticket_error(kind: SessionTicketErrorKind) -> Failure {
    Failure::new(match kind {
        SessionTicketErrorKind::TooLarge => "session_ticket_too_large",
        SessionTicketErrorKind::Allocation => "session_ticket_allocation",
        SessionTicketErrorKind::InvalidSnapshot => "session_ticket_invalid_snapshot",
        SessionTicketErrorKind::Authentication => "session_ticket_authentication",
        SessionTicketErrorKind::IncompatibleBackend => "session_ticket_incompatible_backend",
        SessionTicketErrorKind::Expired => "session_ticket_expired",
        SessionTicketErrorKind::Policy => "session_ticket_policy",
        SessionTicketErrorKind::Unsupported => "session_ticket_unsupported",
        SessionTicketErrorKind::Busy => "session_ticket_busy",
        SessionTicketErrorKind::Backend => "session_ticket_backend",
        _ => "session_ticket_unknown",
    })
}

pub(crate) fn execute(client: &Client, input: Input) -> ResultData {
    let kind = match &input {
        Input::ExportCookies => 1,
        Input::ImportCookies(_) => 2,
        Input::ExportAltSvc => 3,
        Input::ImportAltSvc(_) => 4,
        Input::ExportTickets(_) => 5,
        Input::ImportTickets(..) => 6,
    };
    let mut result = ResultData::new(kind);
    let outcome = match input {
        Input::ExportCookies => result.export_cookies(client),
        Input::ImportCookies(snapshot) => client.import_cookies(&snapshot).map_err(|error| {
            result.entry = error.entry_index();
            Failure::new(match error.kind() {
                CookieSnapshotErrorKind::Disabled => "cookie_snapshot_disabled",
                CookieSnapshotErrorKind::InvalidCookie => "cookie_snapshot_invalid_cookie",
                CookieSnapshotErrorKind::CookieTooLarge => "cookie_snapshot_cookie_too_large",
                CookieSnapshotErrorKind::PublicSuffix => "cookie_snapshot_public_suffix",
                CookieSnapshotErrorKind::InvalidPrefix => "cookie_snapshot_invalid_prefix",
                CookieSnapshotErrorKind::UnsupportedPolicy => "cookie_snapshot_unsupported_policy",
                CookieSnapshotErrorKind::InvalidPartitionKey => {
                    "cookie_snapshot_invalid_partition_key"
                }
                _ => "cookie_snapshot_unknown",
            })
        }),
        Input::ExportAltSvc => result.export_alt_svc(client),
        Input::ImportAltSvc(snapshot) => client.import_alt_svc(&snapshot).map_err(|error| {
            result.entry = error.entry_index();
            Failure::new(match error.kind() {
                AltSvcSnapshotErrorKind::Disabled => "alt_svc_snapshot_disabled",
                AltSvcSnapshotErrorKind::NoncanonicalOrigin => {
                    "alt_svc_snapshot_noncanonical_origin"
                }
                AltSvcSnapshotErrorKind::InvalidAlternative => {
                    "alt_svc_snapshot_invalid_alternative"
                }
                _ => "alt_svc_snapshot_unknown",
            })
        }),
        Input::ExportTickets(key) => client
            .export_session_tickets(&key)
            .map(|snapshot| {
                result.arena.extend_from_slice(snapshot.as_bytes());
            })
            .map_err(|error| ticket_error(error.kind())),
        Input::ImportTickets(snapshot, key, routes) => client
            .import_session_tickets(&snapshot, &key, &routes)
            .map_err(|error| ticket_error(error.kind())),
    };
    result.error = outcome.err();
    if result.error.is_some() {
        result.cookies.clear();
        result.alternatives.clear();
        result.arena.zeroize();
    }
    result
}

#[cfg(test)]
mod tests;
