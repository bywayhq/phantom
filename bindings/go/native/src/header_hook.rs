//! Owned header-call metadata and edits. No foreign pointer enters async work.

use std::{error::Error, fmt};

use phantom::{HeaderHookContext, HeaderHookError};

use crate::client::Header;

pub(crate) struct Invocation {
    pub(crate) index: usize,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) headers: Vec<Header>,
}

pub(crate) enum Edit {
    Append(Header),
    Set(Header),
    Remove(String),
}

impl Edit {
    pub(crate) fn apply(self, context: &mut HeaderHookContext<'_>) -> Result<(), HeaderHookError> {
        match self {
            Self::Append(header) => context.append(header.into_request()),
            Self::Set(header) => context.set(header.into_request()),
            Self::Remove(name) => context.remove(&name),
        }
    }
}

#[derive(Debug)]
pub(crate) struct HostFailure;

impl fmt::Display for HostFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("host header hook failed")
    }
}

impl Error for HostFailure {}
