//! Exact selection and evidence for compiled browser recipes.
//!
//! Definitions describe a recipe revision. Instantiation returns fresh owned
//! settings; changing those settings does not change the catalog definition.
//! Catalog identity does not establish transport compatibility or cache identity.
//!
//! ```
//! use phantom_profile::catalog::{profile, ProfileLayer};
//!
//! let definition = profile("chrome/154.0.8037.97/windows-11-26200/r1")?;
//! let settings = definition.instantiate(&[ProfileLayer::Http2, ProfileLayer::Http3])?;
//! assert!(settings.http3().is_some());
//! # Ok::<(), phantom_profile::catalog::CatalogError>(())
//! ```

use std::fmt;

use crate::{ClientProfile, RequestTemplate, browser};

pub(crate) mod dns_components;
mod generated;
pub(crate) mod http1_components;
pub(crate) mod http2_components;
pub(crate) mod http3_components;
pub(crate) mod quic_components;
pub(crate) mod tcp_components;
pub(crate) mod udp_components;

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
}

/// The environment used for retained observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CaptureEnvironment {
    /// A desktop browser on its host operating system.
    Desktop,
    /// An emulator; its reported model does not establish physical hardware.
    Emulator,
    /// A browser on a physical mobile device.
    PhysicalDevice,
}

/// Browser and platform information for one recipe revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileMetadata {
    browser: Browser,
    build: &'static str,
    platform: ProfilePlatform,
    platform_release: &'static str,
    architecture: Option<&'static str>,
    environment: CaptureEnvironment,
    revision: u32,
}

impl ProfileMetadata {
    /// Returns the browser brand.
    #[must_use]
    pub const fn browser(&self) -> Browser {
        self.browser
    }

    /// Returns the advertised browser build selected by this recipe.
    ///
    /// Individual layers can be backed by different builds. Inspect their
    /// evidence instead of attributing this build to every setting.
    #[must_use]
    pub const fn build(&self) -> &'static str {
        self.build
    }

    /// Returns the recipe's platform, independent of the compilation host.
    #[must_use]
    pub const fn platform(&self) -> ProfilePlatform {
        self.platform
    }

    /// Returns the recorded operating-system release or capture target.
    #[must_use]
    pub const fn platform_release(&self) -> &'static str {
        self.platform_release
    }

    /// Returns the observed host or emulator architecture, when established.
    ///
    /// This is not inferred from the `User-Agent` or client hints.
    #[must_use]
    pub const fn architecture(&self) -> Option<&'static str> {
        self.architecture
    }

    /// Returns the capture environment.
    #[must_use]
    pub const fn environment(&self) -> CaptureEnvironment {
        self.environment
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
    /// Configured; evidence can still cover only some fields.
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
    /// The implementation and its citations; not independent browser evidence.
    Recipe,
}

/// One retained reference, with its own browser or upstream build.
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

    /// Returns the build described by this reference, not the whole profile.
    #[must_use]
    pub const fn build(&self) -> &'static str {
        self.build
    }
}

/// Evidence and limits for one configured or missing layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerEvidence {
    layer: ProfileLayer,
    support: LayerSupport,
    references: &'static [EvidenceReference],
    verified_fields: &'static [&'static str],
    limitations: &'static [&'static str],
}

impl LayerEvidence {
    /// Returns the described layer.
    #[must_use]
    pub const fn layer(&self) -> ProfileLayer {
        self.layer
    }

    /// Returns configuration availability, independent of evidence coverage.
    #[must_use]
    pub const fn support(&self) -> LayerSupport {
        self.support
    }

    /// Returns each source with its own build and provenance.
    #[must_use]
    pub const fn references(&self) -> &'static [EvidenceReference] {
        self.references
    }

    /// Returns the fields checked against retained browser observations.
    ///
    /// Source-derived policies are references, not captured fields. An empty
    /// slice therefore need not mean the configuration lacks source support.
    #[must_use]
    pub const fn verified_fields(&self) -> &'static [&'static str] {
        self.verified_fields
    }

    /// Returns unverified behavior and known limits of the evidence.
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
}

/// An immutable compiled definition, with owned settings created on demand.
///
/// It is metadata, not a connection-pool or session-cache key. Instantiation
/// does not draw per-client or per-connection random values.
#[derive(Clone, Debug)]
pub struct ProfileDefinition {
    id: ProfileId,
    metadata: ProfileMetadata,
    layers: &'static [LayerEvidence],
    binding: RecipeBinding,
}

impl ProfileDefinition {
    /// Returns this recipe revision's stable identifier.
    #[must_use]
    pub const fn id(&self) -> ProfileId {
        self.id
    }

    /// Returns browser and platform metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ProfileMetadata {
        &self.metadata
    }

    /// Returns per-layer availability and evidence.
    #[must_use]
    pub const fn layers(&self) -> &'static [LayerEvidence] {
        self.layers
    }

    /// Finds a layer's evidence without selecting another recipe.
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
    /// or intentionally absent. Never substitutes another browser or version.
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

        Ok(self.binding.instantiate())
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
        self.binding
            .template(kind)
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
    /// No definition has the supplied exact identifier.
    UnknownProfile,
    /// The selected definition does not configure the required layer.
    UnavailableLayer {
        /// The selected recipe, without an implicit replacement.
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

/// Returns all compiled definitions in identifier order, without allocation.
#[must_use]
pub fn profiles() -> &'static [ProfileDefinition] {
    generated::PROFILES
}

/// Looks up one exact recipe revision, without aliases or version fallback.
///
/// # Errors
///
/// Returns [`CatalogError::UnknownProfile`] for any unknown identifier.
pub fn profile(id: &str) -> Result<&'static ProfileDefinition, CatalogError> {
    let index = profiles()
        .binary_search_by_key(&id, |entry| entry.id.as_str())
        .map_err(|_| CatalogError::UnknownProfile)?;
    profiles().get(index).ok_or(CatalogError::UnknownProfile)
}

#[derive(Clone, Copy, Debug)]
enum RecipeBinding {
    ChromeWindows154,
    ChromeAndroid154,
    EdgeWindows154,
    EdgeAndroid153,
    BraveWindows154,
    BraveAndroid153,
    FirefoxWindows157,
    FirefoxAndroid156,
    OperaWindows136,
    OperaAndroid102,
}

impl RecipeBinding {
    fn instantiate(self) -> ClientProfile {
        match self {
            Self::ChromeWindows154 => browser::chrome::v154_windows(),
            Self::ChromeAndroid154 => browser::chrome::v154_android(),
            Self::EdgeWindows154 => browser::edge::v154_windows(),
            Self::EdgeAndroid153 => browser::edge::v153_android(),
            Self::BraveWindows154 => browser::brave::v154_windows(),
            Self::BraveAndroid153 => browser::brave::v153_android(),
            Self::FirefoxWindows157 => browser::firefox::v157_windows(),
            Self::FirefoxAndroid156 => browser::firefox::v156_android(),
            Self::OperaWindows136 => browser::opera::v136_windows(),
            Self::OperaAndroid102 => browser::opera::v102_android(),
        }
    }

    fn template(self, kind: RequestTemplateKind) -> Option<RequestTemplate> {
        use RequestTemplateKind::{Fetch, FetchNoStore, FetchUpload, Navigation};

        let factory: fn() -> RequestTemplate = match (self, kind) {
            (Self::ChromeWindows154, Navigation) => {
                browser::chrome::v154_windows_navigation_template
            }
            (Self::ChromeWindows154, FetchNoStore) => {
                browser::chrome::v154_windows_fetch_no_store_template
            }
            (Self::ChromeWindows154, Fetch) => browser::chrome::v154_windows_fetch_template,
            (Self::ChromeWindows154, FetchUpload) => {
                browser::chrome::v154_windows_fetch_upload_template
            }
            (Self::ChromeAndroid154, Navigation) => {
                browser::chrome::v154_android_navigation_template
            }
            (Self::ChromeAndroid154, FetchNoStore) => {
                browser::chrome::v154_android_fetch_no_store_template
            }
            (Self::EdgeWindows154, Navigation) => browser::edge::v154_windows_navigation_template,
            (Self::EdgeWindows154, FetchNoStore) => {
                browser::edge::v154_windows_fetch_no_store_template
            }
            (Self::EdgeAndroid153, Navigation) => browser::edge::v153_android_navigation_template,
            (Self::EdgeAndroid153, FetchNoStore) => {
                browser::edge::v153_android_fetch_no_store_template
            }
            (Self::BraveWindows154, Navigation) => browser::brave::v154_windows_navigation_template,
            (Self::BraveWindows154, FetchNoStore) => {
                browser::brave::v154_windows_fetch_no_store_template
            }
            (Self::BraveAndroid153, Navigation) => browser::brave::v153_android_navigation_template,
            (Self::BraveAndroid153, FetchNoStore) => {
                browser::brave::v153_android_fetch_no_store_template
            }
            (Self::FirefoxWindows157, Navigation) => {
                browser::firefox::v157_windows_navigation_template
            }
            (Self::FirefoxWindows157, FetchNoStore) => {
                browser::firefox::v157_windows_fetch_no_store_template
            }
            (Self::FirefoxWindows157, Fetch) => browser::firefox::v157_windows_fetch_template,
            (Self::FirefoxWindows157, FetchUpload) => {
                browser::firefox::v157_windows_fetch_upload_template
            }
            (Self::OperaWindows136, Navigation) => browser::opera::v136_windows_navigation_template,
            (Self::OperaWindows136, FetchNoStore) => {
                browser::opera::v136_windows_fetch_no_store_template
            }
            _ => return None,
        };

        Some(factory())
    }
}
