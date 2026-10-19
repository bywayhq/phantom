use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

#[cfg(feature = "cookies")]
use super::MAX_COOKIES;
use super::{
    MAX_ALTERNATIVES, MAX_BYTES, SessionSnapshotError, SessionSnapshotErrorKind as Kind, State,
};

const MAX_FIELD: usize = 64 * 1024;

pub(super) fn copy(
    bytes: &[u8],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, SessionSnapshotError> {
    if bytes.len() > maximum {
        return Err(SessionSnapshotError::new(Kind::TooLarge));
    }
    let mut owned = Zeroizing::new(Vec::new());
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| SessionSnapshotError::new(Kind::Allocation))?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

pub(super) struct Writer(pub(super) Zeroizing<Vec<u8>>);

impl Writer {
    pub(super) fn new() -> Self {
        Self(Zeroizing::new(Vec::new()))
    }

    pub(super) fn raw(&mut self, bytes: &[u8]) -> Result<(), SessionSnapshotError> {
        let length = self
            .0
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_BYTES)
            .ok_or_else(|| SessionSnapshotError::new(Kind::TooLarge))?;
        if length > self.0.capacity() {
            // Wipe the previous allocation instead of letting Vec reallocation free secrets.
            let mut replacement = Zeroizing::new(Vec::new());
            replacement
                .try_reserve_exact(
                    length
                        .max(self.0.capacity().saturating_mul(2))
                        .min(MAX_BYTES),
                )
                .map_err(|_| SessionSnapshotError::new(Kind::Allocation))?;
            replacement.extend_from_slice(&self.0);
            self.0 = replacement;
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), SessionSnapshotError> {
        self.raw(&[value])
    }

    fn count(&mut self, value: usize, maximum: usize) -> Result<(), SessionSnapshotError> {
        if value > maximum {
            return Err(SessionSnapshotError::new(Kind::TooLarge));
        }
        self.raw(
            &u32::try_from(value)
                .map_err(|_| SessionSnapshotError::new(Kind::TooLarge))?
                .to_be_bytes(),
        )
    }

    fn field(&mut self, value: &[u8], maximum: usize) -> Result<(), SessionSnapshotError> {
        self.count(value.len(), maximum)?;
        self.raw(value)
    }

    fn text(&mut self, value: &str) -> Result<(), SessionSnapshotError> {
        self.field(value.as_bytes(), MAX_FIELD)
    }

    fn time(&mut self, value: SystemTime) -> Result<(), SessionSnapshotError> {
        let duration = value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?;
        self.raw(&duration.as_secs().to_be_bytes())?;
        self.raw(&duration.subsec_nanos().to_be_bytes())
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn raw(&mut self, length: usize) -> Result<&'a [u8], SessionSnapshotError> {
        let value = self
            .0
            .get(..length)
            .ok_or_else(|| SessionSnapshotError::new(Kind::InvalidSnapshot))?;
        self.0 = &self.0[length..];
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, SessionSnapshotError> {
        Ok(self.raw(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, SessionSnapshotError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SessionSnapshotError::new(Kind::InvalidSnapshot)),
        }
    }

    fn count(&mut self, maximum: usize) -> Result<usize, SessionSnapshotError> {
        let value = u32::from_be_bytes(
            self.raw(4)?
                .try_into()
                .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?,
        ) as usize;
        if value > maximum {
            return Err(SessionSnapshotError::new(Kind::TooLarge));
        }
        Ok(value)
    }

    fn field(&mut self, maximum: usize) -> Result<&'a [u8], SessionSnapshotError> {
        let length = self.count(maximum)?;
        self.raw(length)
    }

    fn text(&mut self) -> Result<Box<str>, SessionSnapshotError> {
        let bytes = self.field(MAX_FIELD)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?;
        Ok(value.into())
    }

    fn time(&mut self) -> Result<SystemTime, SessionSnapshotError> {
        let seconds = u64::from_be_bytes(
            self.raw(8)?
                .try_into()
                .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?,
        );
        let nanos = u32::from_be_bytes(
            self.raw(4)?
                .try_into()
                .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?,
        );
        if nanos >= 1_000_000_000 {
            return Err(SessionSnapshotError::new(Kind::InvalidSnapshot));
        }
        UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanos))
            .ok_or_else(|| SessionSnapshotError::new(Kind::InvalidSnapshot))
    }
}

pub(super) fn encode(state: &State) -> Result<Zeroizing<Vec<u8>>, SessionSnapshotError> {
    let mut writer = Writer::new();
    writer.field(&state.context, 1024 * 1024)?;
    #[cfg(feature = "cookies")]
    write_cookies(&mut writer, state.cookies.as_ref())?;
    #[cfg(not(feature = "cookies"))]
    writer.byte(0)?;
    writer.byte(u8::from(state.alt_svc.is_some()))?;
    if let Some(snapshot) = &state.alt_svc {
        writer.count(snapshot.len(), MAX_ALTERNATIVES)?;
        for entry in snapshot.entries() {
            writer.text(entry.origin())?;
            writer.text(entry.alternative_host())?;
            writer.raw(&entry.alternative_port().to_be_bytes())?;
            writer.time(entry.expires_at())?;
        }
    }
    writer.field(state.tickets.as_bytes(), 16 * 1024 * 1024)?;
    Ok(writer.0)
}

pub(super) fn decode(bytes: &[u8]) -> Result<State, SessionSnapshotError> {
    let mut reader = Reader(bytes);
    let context = copy(reader.field(1024 * 1024)?, 1024 * 1024)?;
    let has_cookies = reader.boolean()?;
    #[cfg(feature = "cookies")]
    let cookies = has_cookies.then(|| read_cookies(&mut reader)).transpose()?;
    #[cfg(not(feature = "cookies"))]
    if has_cookies {
        return Err(SessionSnapshotError::new(Kind::Disabled));
    }
    let alt_svc = if reader.boolean()? {
        let count = reader.count(MAX_ALTERNATIVES)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| SessionSnapshotError::new(Kind::Allocation))?;
        for _ in 0..count {
            let origin = reader.text()?;
            let host = reader.text()?;
            let port = u16::from_be_bytes(
                reader
                    .raw(2)?
                    .try_into()
                    .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?,
            );
            entries.push(crate::AltSvcSnapshotEntry::new(
                origin,
                host,
                port,
                reader.time()?,
            ));
        }
        Some(crate::AltSvcSnapshot::new(entries))
    } else {
        None
    };
    let tickets = crate::SessionTicketSnapshot::from_bytes(reader.field(16 * 1024 * 1024)?)
        .map_err(|error| SessionSnapshotError::source(Kind::Tickets, error))?;
    if !reader.0.is_empty() {
        return Err(SessionSnapshotError::new(Kind::InvalidSnapshot));
    }
    Ok(State {
        context,
        #[cfg(feature = "cookies")]
        cookies,
        alt_svc,
        tickets,
    })
}

#[cfg(feature = "cookies")]
fn write_cookies(
    writer: &mut Writer,
    snapshot: Option<&crate::CookieSnapshot>,
) -> Result<(), SessionSnapshotError> {
    writer.byte(u8::from(snapshot.is_some()))?;
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    writer.count(snapshot.len(), MAX_COOKIES)?;
    for entry in snapshot.entries() {
        writer.byte(match entry.source_scheme() {
            crate::CookieSourceScheme::Http => 0,
            crate::CookieSourceScheme::Https => 1,
        })?;
        for field in [entry.name(), entry.value(), entry.domain(), entry.path()] {
            writer.text(field)?;
        }
        writer.byte(u8::from(entry.host_only()))?;
        writer.byte(u8::from(entry.secure()))?;
        writer.byte(u8::from(entry.http_only()))?;
        writer.byte(match entry.same_site() {
            None => 0,
            Some(crate::CookieSameSite::Strict) => 1,
            Some(crate::CookieSameSite::Lax) => 2,
            Some(crate::CookieSameSite::None) => 3,
        })?;
        writer.byte(u8::from(entry.partition_key().is_some()))?;
        if let Some(partition) = entry.partition_key() {
            writer.text(partition)?;
        }
        writer.byte(u8::from(entry.expires_at().is_some()))?;
        if let Some(time) = entry.expires_at() {
            writer.time(time)?;
        }
    }
    Ok(())
}

#[cfg(feature = "cookies")]
fn read_cookies(reader: &mut Reader<'_>) -> Result<crate::CookieSnapshot, SessionSnapshotError> {
    let count = reader.count(MAX_COOKIES)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| SessionSnapshotError::new(Kind::Allocation))?;
    for _ in 0..count {
        let scheme = match reader.byte()? {
            0 => crate::CookieSourceScheme::Http,
            1 => crate::CookieSourceScheme::Https,
            _ => return Err(SessionSnapshotError::new(Kind::InvalidSnapshot)),
        };
        let mut entry = crate::CookieSnapshotEntry::new(
            scheme,
            reader.text()?,
            reader.text()?,
            reader.text()?,
            reader.text()?,
        );
        entry = entry
            .with_host_only(reader.boolean()?)
            .with_secure(reader.boolean()?)
            .with_http_only(reader.boolean()?);
        entry = match reader.byte()? {
            0 => entry,
            1 => entry.with_same_site(crate::CookieSameSite::Strict),
            2 => entry.with_same_site(crate::CookieSameSite::Lax),
            3 => entry.with_same_site(crate::CookieSameSite::None),
            _ => return Err(SessionSnapshotError::new(Kind::InvalidSnapshot)),
        };
        if reader.boolean()? {
            entry = entry.with_partition_key(reader.text()?);
        }
        if reader.boolean()? {
            entry = entry.with_expires_at(reader.time()?);
        }
        entries.push(entry);
    }
    Ok(crate::CookieSnapshot::new(entries))
}
