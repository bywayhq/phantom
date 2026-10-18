use std::{fmt, num::NonZeroUsize};

use http::{Method, StatusCode, Uri};

/// A bounded record of the redirects selected before a final response.
///
/// Enable it with [`crate::RequestBuilder::redirect_history`], then retrieve it
/// from [`http::Response::extensions`]. The first requested number of hops is
/// retained, with later hops counted by [`Self::omitted_hops`]. Disabled requests
/// retain no history. A request that returns an error has no response history.
///
/// Entries describe selected redirects, rather than separate HTTP attempts.
/// Retries and browser replays do not add entries. Bodies and headers are not
/// retained. Debug output omits URLs, which may contain sensitive paths or queries.
#[derive(Clone, Eq, PartialEq)]
pub struct RedirectHistory {
    maximum: NonZeroUsize,
    entries: Vec<RedirectHop>,
    omitted: usize,
}

impl RedirectHistory {
    /// Returns the retained hops in the order they were selected.
    #[must_use]
    pub fn entries(&self) -> &[RedirectHop] {
        &self.entries
    }

    /// Returns how many later hops exceeded the requested history capacity.
    #[must_use]
    pub const fn omitted_hops(&self) -> usize {
        self.omitted
    }

    pub(crate) fn new(maximum: NonZeroUsize) -> Self {
        Self {
            maximum,
            entries: Vec::new(),
            omitted: 0,
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.entries.len() == self.maximum.get()
    }

    pub(crate) fn push(&mut self, hop: RedirectHop) {
        self.entries.push(hop);
    }

    pub(crate) fn finish(&mut self, followed: usize) {
        self.omitted = followed.saturating_sub(self.entries.len());
    }
}

impl fmt::Debug for RedirectHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectHistory")
            .field("retained_hops", &self.entries.len())
            .field("omitted_hops", &self.omitted)
            .finish_non_exhaustive()
    }
}

/// The response and destination selected for one followed redirect.
///
/// URLs use the client's absolute HTTP URI representation, without fragments.
/// Access them explicitly: debug output omits both URLs.
#[derive(Clone, Eq, PartialEq)]
pub struct RedirectHop {
    from: Uri,
    to: Uri,
    method: Method,
    next_method: Method,
    status: StatusCode,
}

impl RedirectHop {
    /// Returns the URL that produced the redirect response.
    #[must_use]
    pub fn from_uri(&self) -> &Uri {
        &self.from
    }

    /// Returns the resolved destination selected by the redirect policy.
    #[must_use]
    pub fn to_uri(&self) -> &Uri {
        &self.to
    }

    /// Returns the method that produced the redirect response.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the method selected for the destination.
    #[must_use]
    pub fn next_method(&self) -> &Method {
        &self.next_method
    }

    /// Returns the redirect response status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn new(
        from: Uri,
        to: Uri,
        method: Method,
        next_method: Method,
        status: StatusCode,
    ) -> Self {
        Self {
            from,
            to,
            method,
            next_method,
            status,
        }
    }
}

impl fmt::Debug for RedirectHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectHop")
            .field("method", &self.method)
            .field("next_method", &self.next_method)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}
