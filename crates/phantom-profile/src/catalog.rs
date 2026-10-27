//! Select compiled browser recipes and inspect their sources.
//!
//! Definitions describe a recipe revision. Instantiation returns fresh owned
//! settings; changing those settings does not change the catalog definition.
//!
//! ```
//! use phantom_profile::catalog::{profile, ProfileLayer};
//!
//! let definition = profile("chrome-154-windows")?;
//! let settings = definition.instantiate(&[ProfileLayer::Http2, ProfileLayer::Http3])?;
//! assert!(settings.http3().is_some());
//! # Ok::<(), phantom_profile::catalog::CatalogError>(())
//! ```

use std::fmt;

use crate::{ClientProfile, RequestTemplate};

pub(crate) mod browser_profiles;
pub(crate) mod client_hints_components;
mod connection_profile_definitions;
mod connection_profile_values;
pub(crate) mod cookie_components;
pub(crate) mod dns_components;
mod generated;
pub(crate) mod http1_components;
pub(crate) mod http2_components;
pub(crate) mod http3_components;
pub(crate) mod proxy_connect_components;
pub(crate) mod quic_components;
mod request_template_definitions;
mod request_template_values;
pub(crate) mod tcp_components;
pub(crate) mod udp_components;
pub(crate) mod websocket_components;

/// An immutable identifier assigned to one compiled recipe revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileId(&'static str);

impl ProfileId {
    /// Returns the exact identifier accepted by [`profile`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

/// A browser brand, independent of its underlying transport implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Browser {
    /// Google Chrome.
    Chrome,
    /// Microsoft Edge.
    Edge,
    /// Brave.
    Brave,
    /// Mozilla Firefox.
    Firefox,
    /// Opera.
    Opera,
    /// Apple Safari.
    Safari,
}

/// The operating system described by a recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfilePlatform {
    /// Windows.
    Windows,
    /// macOS.
    Macos,
    /// Linux.
    Linux,
    /// Android.
    Android,
    /// iOS.
    Ios,
}

/// The environment where the browser was recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CaptureEnvironment {
    /// A desktop browser on its host operating system.
    Desktop,
    /// An emulated device.
    Emulator,
    /// A browser on a physical mobile device.
    PhysicalDevice,
}

/// Whether a recipe comes from browser observations or an external client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileIdentity {
    /// A recipe based on browser observations.
    Observed {
        /// Advertised browser build. Each layer lists its own sources.
        build: &'static str,
        /// Recorded operating-system release or capture target.
        platform_release: &'static str,
        /// Recorded host or emulator architecture, if available.
        architecture: Option<&'static str>,
        /// Environment used for the browser observations.
        environment: CaptureEnvironment,
    },
    /// A preset ported from a pinned external client.
    Peer {
        /// Upstream project name.
        project: &'static str,
        /// Exact upstream source commit.
        source_revision: &'static str,
        /// Upstream preset name.
        recipe: &'static str,
        /// Browser version advertised by that preset.
        release: &'static str,
    },
}

/// Browser target and provenance for one recipe revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileMetadata {
    browser: Browser,
    platform: ProfilePlatform,
    identity: ProfileIdentity,
    revision: u32,
}

impl ProfileMetadata {
    /// Returns the browser brand.
    #[must_use]
    pub const fn browser(&self) -> Browser {
        self.browser
    }

    /// Returns the advertised browser version or peer preset release.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        match self.identity {
            ProfileIdentity::Observed { build, .. } => build,
            ProfileIdentity::Peer { release, .. } => release,
        }
    }

    /// Returns the recipe's observed-browser or external-client identity.
    #[must_use]
    pub const fn identity(&self) -> ProfileIdentity {
        self.identity
    }

    /// Returns the browser build for an observed recipe, or `None` for a peer.
    ///
    /// Individual layers list their source builds in [`ProfileDefinition::layers`].
    #[must_use]
    pub const fn build(&self) -> Option<&'static str> {
        match self.identity {
            ProfileIdentity::Observed { build, .. } => Some(build),
            ProfileIdentity::Peer { .. } => None,
        }
    }

    /// Returns the recipe's platform, independent of the compilation host.
    #[must_use]
    pub const fn platform(&self) -> ProfilePlatform {
        self.platform
    }

    /// Returns the recorded OS release or capture target, absent for peers.
    #[must_use]
    pub const fn platform_release(&self) -> Option<&'static str> {
        match self.identity {
            ProfileIdentity::Observed {
                platform_release, ..
            } => Some(platform_release),
            ProfileIdentity::Peer { .. } => None,
        }
    }

    /// Returns the recorded host or emulator architecture, if available.
    #[must_use]
    pub const fn architecture(&self) -> Option<&'static str> {
        match self.identity {
            ProfileIdentity::Observed { architecture, .. } => architecture,
            ProfileIdentity::Peer { .. } => None,
        }
    }

    /// Returns the browser capture environment, absent for peers.
    #[must_use]
    pub const fn environment(&self) -> Option<CaptureEnvironment> {
        match self.identity {
            ProfileIdentity::Observed { environment, .. } => Some(environment),
            ProfileIdentity::Peer { .. } => None,
        }
    }

    /// Returns the settings revision included in the catalog identifier.
    #[must_use]
    pub const fn revision(&self) -> u32 {
        self.revision
    }
}

/// A layer that can be required when constructing a profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileLayer {
    /// TLS over TCP.
    TcpTls,
    /// TCP socket and address-selection policies.
    Tcp,
    /// UDP socket policies.
    Udp,
    /// The client's address cache.
    Dns,
    /// HTTP/1.1 connection policies.
    Http1,
    /// HTTP/2 connection and request settings.
    Http2,
    /// TLS over QUIC.
    QuicTls,
    /// QUIC transport settings.
    QuicTransport,
    /// HTTP/3 connection settings.
    Http3,
    /// HTTP/3 request settings.
    Http3Request,
    /// Client hints.
    ClientHints,
    /// WebSocket openings and connection policies.
    WebSocket,
    /// Proxy CONNECT request settings.
    ProxyConnect,
    /// Automatic cookie placement.
    CookiePlacement,
}

/// Whether a recipe configures a layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LayerSupport {
    /// The recipe provides settings for this layer.
    Configured,
    /// The browser deliberately omits this behavior, such as Firefox hints.
    IntentionallyAbsent,
    /// No recipe is provided for this layer.
    Unavailable,
}

/// How one source supports a layer's settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EvidenceKind {
    /// A retained browser capture or hook observation.
    Capture,
    /// Browser source defines the behavior.
    Source,
    /// Another recipe supplies settings compared against this browser.
    Reused,
    /// The implementation and its citations.
    Recipe,
    /// A pinned external client's source.
    ExternalSource,
    /// A recording of an external client.
    PeerCapture,
}

/// One source reference and the browser or upstream build it describes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceReference {
    kind: EvidenceKind,
    location: &'static str,
    build: &'static str,
}

impl EvidenceReference {
    /// Returns the kind of evidence.
    #[must_use]
    pub const fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// Returns a repository-relative path or primary-source URL.
    #[must_use]
    pub const fn location(&self) -> &'static str {
        self.location
    }

    /// Returns the build described by this reference.
    #[must_use]
    pub const fn build(&self) -> &'static str {
        self.build
    }
}

/// Availability, sources and limits for one layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerEvidence {
    layer: ProfileLayer,
    support: LayerSupport,
    references: &'static [EvidenceReference],
    limitations: &'static [&'static str],
}

impl LayerEvidence {
    /// Returns the described layer.
    #[must_use]
    pub const fn layer(&self) -> ProfileLayer {
        self.layer
    }

    /// Returns whether the recipe provides this layer.
    #[must_use]
    pub const fn support(&self) -> LayerSupport {
        self.support
    }

    /// Returns source locations and their builds.
    #[must_use]
    pub const fn references(&self) -> &'static [EvidenceReference] {
        self.references
    }

    /// Returns known recipe limitations.
    #[must_use]
    pub const fn limitations(&self) -> &'static [&'static str] {
        self.limitations
    }
}

/// A request kind with an independently selected header template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestTemplateKind {
    /// A page navigation.
    Navigation,
    /// A same-origin fetch with `cache: "no-store"`.
    FetchNoStore,
    /// A same-origin fetch with the browser's ordinary cache policy.
    Fetch,
    /// A same-origin POST upload.
    FetchUpload,
    /// A same-origin classic script.
    Script,
    /// A same-origin stylesheet.
    Stylesheet,
    /// A same-origin image.
    Image,
    /// A same-origin CSS font.
    Font,
}

/// An immutable compiled definition, with owned settings created on demand.
///
/// Instantiation leaves per-client and per-connection random values for
/// client and connection setup. Pool and session keys use the settings.
#[derive(Clone, Debug)]
pub struct ProfileDefinition {
    id: ProfileId,
    selector: &'static str,
    metadata: ProfileMetadata,
    layers: &'static [LayerEvidence],
    composition: &'static connection_profile_values::ConnectionProfileDefinition,
    templates: &'static [RequestTemplateBinding],
}

impl ProfileDefinition {
    /// Returns this recipe revision's stable identifier.
    #[must_use]
    pub const fn id(&self) -> ProfileId {
        self.id
    }

    /// Returns the short name fixed to this recipe revision.
    #[must_use]
    pub const fn selector(&self) -> &'static str {
        self.selector
    }

    /// Returns browser and platform metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ProfileMetadata {
        &self.metadata
    }

    /// Returns per-layer availability, sources and limits.
    #[must_use]
    pub const fn layers(&self) -> &'static [LayerEvidence] {
        self.layers
    }

    /// Returns the selected recipe's sources for a layer.
    #[must_use]
    pub fn evidence(&self, layer: ProfileLayer) -> Option<&'static LayerEvidence> {
        self.layers.iter().find(|entry| entry.layer == layer)
    }

    /// Creates fresh settings, requiring each named layer to be configured.
    ///
    /// An empty requirement slice accepts this recipe's partial composition.
    /// Missing layers retain the ordinary custom-profile behavior documented
    /// by [`ClientProfile`]. No request template is selected implicitly.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::UnavailableLayer`] if a requirement is missing
    /// or intentionally absent.
    pub fn instantiate(&self, required: &[ProfileLayer]) -> Result<ClientProfile, CatalogError> {
        for &layer in required {
            if !self
                .evidence(layer)
                .is_some_and(|entry| entry.support == LayerSupport::Configured)
            {
                return Err(CatalogError::UnavailableLayer {
                    profile: self.id,
                    layer,
                });
            }
        }

        Ok(self
            .composition
            .instantiate()
            .with_request_context_profile(self.id))
    }

    /// Returns a fresh request template for the explicitly selected kind.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::UnavailableTemplate`] when this exact recipe
    /// has no template for that request kind.
    pub fn request_template(
        &self,
        kind: RequestTemplateKind,
    ) -> Result<RequestTemplate, CatalogError> {
        self.templates
            .iter()
            .find(|entry| entry.kind == kind)
            .map(|entry| entry.definition.instantiate())
            .ok_or(CatalogError::UnavailableTemplate {
                profile: self.id,
                kind,
            })
    }
}

/// A failed exact lookup or unsupported requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CatalogError {
    /// No definition has the supplied selector or exact identifier.
    UnknownProfile,
    /// The selected definition does not configure the required layer.
    UnavailableLayer {
        /// The selected recipe.
        profile: ProfileId,
        /// The first unmet requirement.
        layer: ProfileLayer,
    },
    /// The selected definition has no template for the request kind.
    UnavailableTemplate {
        /// The selected recipe.
        profile: ProfileId,
        /// The unavailable request kind.
        kind: RequestTemplateKind,
    },
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProfile => formatter.write_str("unknown profile identifier"),
            Self::UnavailableLayer { profile, layer } => {
                write!(formatter, "profile {profile} does not configure {layer:?}")
            }
            Self::UnavailableTemplate { profile, kind } => {
                write!(
                    formatter,
                    "profile {profile} has no {kind:?} request template"
                )
            }
        }
    }
}

impl std::error::Error for CatalogError {}

/// Creates a browser profile with default headers for the selected request kind.
///
/// Uses the fixed short selector or exact identifier accepted by [`profile`].
/// The connection settings and request template come from the same definition.
/// Other configured layers are retained; unavailable layers are not added.
///
/// ```
/// use phantom_profile::catalog::{RequestTemplateKind, profile_for};
///
/// let settings = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
/// assert!(settings.request_template().is_some());
/// # Ok::<(), phantom_profile::catalog::CatalogError>(())
/// ```
///
/// # Errors
///
/// Returns [`CatalogError::UnknownProfile`] for an unknown name, or
/// [`CatalogError::UnavailableTemplate`] when that request kind is unavailable.
pub fn profile_for(name: &str, kind: RequestTemplateKind) -> Result<ClientProfile, CatalogError> {
    let definition = profile(name)?;
    let template = definition.request_template(kind)?;
    Ok(definition.instantiate(&[])?.with_request_template(template))
}

/// Returns all compiled definitions in identifier order, without allocation.
#[must_use]
pub fn profiles() -> &'static [ProfileDefinition] {
    generated::PROFILES
}

/// Looks up a recipe by its fixed short selector or exact identifier.
///
/// Both names return the same immutable definition. Selection is case-sensitive
/// and never chooses another version, revision or host platform.
///
/// # Errors
///
/// Returns [`CatalogError::UnknownProfile`] for any unknown identifier.
pub fn profile(name: &str) -> Result<&'static ProfileDefinition, CatalogError> {
    if let Ok(index) = profiles().binary_search_by_key(&name, |entry| entry.id.as_str()) {
        return profiles().get(index).ok_or(CatalogError::UnknownProfile);
    }

    profiles()
        .iter()
        .find(|entry| entry.selector == name)
        .ok_or(CatalogError::UnknownProfile)
}

#[derive(Debug)]
struct RequestTemplateBinding {
    kind: RequestTemplateKind,
    definition: &'static request_template_values::RequestTemplateDefinition,
}
