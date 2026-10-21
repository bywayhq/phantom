//! Native profile ownership, catalog selection and explicit imports.

use std::sync::Arc;

use napi::{Env, Result, bindgen_prelude::Buffer};
use napi_derive::napi;

use super::buffer::copy_buffer;
use crate::profile::{MAXIMUM_PROFILE_BYTES, ProfileState};

/// Immutable settings owned by Rust, without references to JavaScript inputs.
#[derive(Debug)]
#[napi]
pub struct NativeProfile {
    pub(super) state: Arc<ProfileState>,
}

/// An imported owner and the core's explicit observation/supplement report.
#[derive(Debug)]
#[napi(object, object_from_js = false)]
pub struct NativeImportedProfile {
    /// Immutable imported settings, without catalog identity.
    pub profile: NativeProfile,
    /// Canonical paths established by the supplied input.
    pub observed_fields: Vec<String>,
    /// Canonical paths retained from the explicitly selected base.
    pub supplemented_fields: Vec<String>,
}

impl From<crate::profile::ProfileImport> for NativeImportedProfile {
    fn from(imported: crate::profile::ProfileImport) -> Self {
        Self {
            profile: NativeProfile {
                state: imported.state,
            },
            observed_fields: imported.observed_fields,
            supplemented_fields: imported.supplemented_fields,
        }
    }
}

#[napi]
impl NativeProfile {
    /// Imports raw JA3 settings using this owner's explicit supplements.
    #[napi]
    pub fn import_ja3(&self, text: String) -> Result<NativeImportedProfile> {
        self.state.import_ja3(&text).map(Into::into)
    }

    /// Copies a complete TLS handshake message, excluding its record header.
    #[napi]
    pub fn import_client_hello(&self, env: Env, input: Buffer) -> Result<NativeImportedProfile> {
        let input = copy_buffer(&env, input, MAXIMUM_PROFILE_BYTES)?;
        self.state.import_client_hello(&input).map(Into::into)
    }

    /// Imports HTTP/2 settings without inventing the remaining protocol layers.
    #[napi]
    pub fn import_akamai(&self, text: String) -> Result<NativeImportedProfile> {
        self.state.import_akamai(&text).map(Into::into)
    }

    /// Imports unhashed JA4 with an explicit original or sorted interpretation.
    #[napi]
    pub fn import_ja4(&self, text: String, format: String) -> Result<NativeImportedProfile> {
        self.state.import_ja4(&text, &format).map(Into::into)
    }

    /// Copies the TLS extension 57 payload, without packet or handshake framing.
    #[napi]
    pub fn import_quic_transport(&self, env: Env, input: Buffer) -> Result<NativeImportedProfile> {
        let input = copy_buffer(&env, input, MAXIMUM_PROFILE_BYTES)?;
        self.state.import_quic_transport(&input).map(Into::into)
    }

    /// Returns the exact catalog identity, or null for every imported profile.
    #[napi(getter)]
    #[must_use]
    pub fn catalog_id(&self) -> Option<String> {
        self.state.catalog_id()
    }

    /// Lists supported explicit contexts without substituting another template.
    #[napi(getter)]
    #[must_use]
    pub fn contexts(&self) -> Vec<String> {
        self.state.contexts()
    }

    /// Exports the core's editable JSON document into a fresh owned Buffer.
    #[napi]
    pub fn export_json(&self) -> Result<Buffer> {
        self.state.export().map(Buffer::from)
    }
}

/// Selects an exact catalog profile and optionally attaches its named template.
#[napi]
pub fn profile_catalog(identifier: String, context: Option<String>) -> Result<NativeProfile> {
    ProfileState::catalog(&identifier, context.as_deref()).map(|state| NativeProfile { state })
}

/// Copies bounded ordinary bytes on this Env before strict native JSON import.
#[napi]
pub fn profile_import_json(env: Env, input: Buffer) -> Result<NativeProfile> {
    let input = copy_buffer(&env, input, MAXIMUM_PROFILE_BYTES)?;
    ProfileState::import(&input).map(|state| NativeProfile { state })
}

/// Lists exact compiled identifiers without maintaining a second registry.
#[napi]
#[must_use]
pub fn profile_ids() -> Vec<String> {
    phantom_profile::catalog::profiles()
        .iter()
        .map(|profile| profile.id().as_str().to_owned())
        .collect()
}
