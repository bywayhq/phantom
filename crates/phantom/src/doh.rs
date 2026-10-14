//! Explicit DNS-over-HTTPS address lookups through an independent HTTP/2 client.

use std::{
    error::Error, fmt, io, net::IpAddr, num::NonZeroU16, num::NonZeroUsize, sync::Arc,
    time::Duration,
};

use phantom_profile::ClientProfile;
use tokio::sync::Semaphore;
use url::{Host, Url};

use crate::{
    AddressResolver, BuildError, Client, ClientBuilder, RedirectPolicy, RequestTimeouts,
    RetryPolicy, Route,
};

mod address;
mod exchange;
#[cfg(test)]
mod tests;

/// The HTTP method used for every DNS exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DohMethod {
    /// Put unpadded base64url DNS bytes in the URL's `dns` parameter.
    Get,
    /// Send raw DNS bytes with the DNS message media type.
    Post,
}

/// Address queries and the order of their combined result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DohAddressFamilies {
    /// Query A records only.
    Ipv4Only,
    /// Query AAAA and A concurrently, returning IPv6 addresses first.
    DualIpv6First,
}

/// Required endpoint, bootstrap and work bounds for a DoH address resolver.
///
/// This selects an exact HTTP/2 direct connection. It does not discover a
/// resolver, use OS DNS, follow redirects or fall back to another protocol.
#[derive(Clone)]
pub struct DohConfiguration {
    endpoint: String,
    bootstrap: Vec<IpAddr>,
    method: DohMethod,
    families: DohAddressFamilies,
    lookup_timeout: Duration,
    maximum_lookups: NonZeroUsize,
    query_id: u16,
    padding_block: Option<NonZeroU16>,
    chromium_headers: bool,
}

impl DohConfiguration {
    /// Configures a concrete HTTPS URL, its addresses and finite work bounds.
    ///
    /// The endpoint has no credentials, fragment, template variables or existing
    /// `dns` query parameter. DNS-host bootstrap addresses retain their order.
    /// An IP-literal endpoint requires all bootstrap addresses to equal that IP.
    /// The query ID starts at zero, with no EDNS padding.
    /// [`DnsOverHttps::builder`] validates these settings before creating state.
    #[must_use]
    pub fn new(
        endpoint: impl Into<String>,
        bootstrap: impl IntoIterator<Item = IpAddr>,
        method: DohMethod,
        families: DohAddressFamilies,
        lookup_timeout: Duration,
        maximum_lookups: NonZeroUsize,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            bootstrap: bootstrap.into_iter().collect(),
            method,
            families,
            lookup_timeout,
            maximum_lookups,
            query_id: 0,
            padding_block: None,
            chromium_headers: false,
        }
    }

    /// Sets the DNS ID required of each response. HTTP correlates the exchange.
    #[must_use]
    pub const fn query_id(mut self, id: u16) -> Self {
        self.query_id = id;
        self
    }

    /// Pads each DNS message to this block size with zero EDNS bytes.
    ///
    /// `None` sends no EDNS padding. This changes DNS bytes, not HTTP/2 padding.
    #[must_use]
    pub const fn padding_block(mut self, block: Option<NonZeroU16>) -> Self {
        self.padding_block = block;
        self
    }

    /// Selects Chromium 154's zero ID, 128-byte DNS padding and minimal headers.
    ///
    /// This also requires HTTP status 200. The selected method remains unchanged.
    /// Later wire setters replace their respective settings. HTTP/2-only direct
    /// transport and refusing redirects are explicit limits of this subset.
    #[must_use]
    pub const fn chromium154_wire(mut self) -> Self {
        // Chromium 154.0.8037.58: net/dns/dns_transaction.cc
        // ConstructDnsHTTPAttempt and net/dns/dns_http_attempt.cc.
        self.query_id = 0;
        self.padding_block = NonZeroU16::new(128);
        self.chromium_headers = true;
        self
    }
}

impl fmt::Debug for DohConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DohConfiguration")
            .field("bootstrap_addresses", &self.bootstrap.len())
            .field("method", &self.method)
            .field("families", &self.families)
            .field("lookup_timeout", &self.lookup_timeout)
            .field("maximum_lookups", &self.maximum_lookups)
            .field("query_id", &self.query_id)
            .field("padding_block", &self.padding_block)
            .field("chromium_headers", &self.chromium_headers)
            .finish_non_exhaustive()
    }
}

/// An independent, verified DoH endpoint and its bounded address resolver.
///
/// Clones share this endpoint's HTTP pool and admission bound. Application
/// clients keep their own pools, cookies, routes and resolver caches.
#[derive(Clone)]
pub struct DnsOverHttps {
    endpoint: Arc<Endpoint>,
}

struct Endpoint {
    client: Client,
    url: Url,
    configuration: DohConfiguration,
    admission: Semaphore,
}

impl DnsOverHttps {
    /// Validates the configuration and prepares a dedicated HTTP/2 client.
    ///
    /// The endpoint's URL host remains its TLS and HTTP identity. Explicit IPs
    /// supply only connection addresses. Certificate verification stays enabled.
    /// Only its TLS, TCP and HTTP/2 settings enter the private client. Ordinary
    /// request templates, client hints and application protocols are excluded.
    ///
    /// # Errors
    ///
    /// Returns [`DohBuildError`] for invalid endpoint/bootstrap/bounds or a
    /// profile without HTTP/2. No network I/O occurs.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::{net::{IpAddr, Ipv4Addr}, num::NonZeroUsize, time::Duration};
    /// use phantom::{Client, dns::{DnsOverHttps, DohAddressFamilies,
    ///     DohConfiguration, DohMethod}, profile::browser::chrome};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let configuration = DohConfiguration::new(
    ///     "https://dns.example/dns-query",
    ///     [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
    ///     DohMethod::Post,
    ///     DohAddressFamilies::DualIpv6First,
    ///     Duration::from_secs(5),
    ///     NonZeroUsize::MIN,
    /// );
    /// let doh = DnsOverHttps::builder(chrome::v154_windows(), configuration)?.build()?;
    /// let client = Client::builder(chrome::v154_windows())
    ///     .dns_resolver(doh.address_resolver())
    ///     .build()?;
    /// # drop(client);
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder(
        profile: ClientProfile,
        configuration: DohConfiguration,
    ) -> Result<DnsOverHttpsBuilder, DohBuildError> {
        let url = validate_configuration(&configuration)?;
        let mut client = Client::builder(transport_profile(profile)?)
            .dns_resolver(AddressResolver::from_fn(|_| async {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "unconfigured DoH bootstrap hostname",
                ))
            }))
            .no_dns_cache()
            .route(Route::direct())
            .redirect_policy(RedirectPolicy::none())
            .retry_policy(RetryPolicy::none());
        if let Some(Host::Domain(host)) = url.host() {
            client = client.resolve(host, configuration.bootstrap.iter().copied());
        }
        Ok(DnsOverHttpsBuilder {
            client,
            url,
            configuration,
        })
    }

    /// Returns a resolver for the configured address families.
    ///
    /// It preserves address order and duplicates. NXDOMAIN conflicting with
    /// another family's positive or NODATA answer fails. A positive answer plus
    /// a family transport failure remains usable with zero cache lifetime.
    ///
    /// Dropping an uncached lookup cancels its HTTP work. The client's optional
    /// DNS cache owns shared lookups even after one waiter drops. Both remain
    /// bounded by this endpoint's deadline and admission limit.
    #[must_use]
    pub fn address_resolver(&self) -> AddressResolver {
        let endpoint = Arc::clone(&self.endpoint);
        AddressResolver::from_answer_fn(move |host| {
            let endpoint = Arc::clone(&endpoint);
            async move { address::lookup(&endpoint, &host).await }
        })
    }
}

impl fmt::Debug for DnsOverHttps {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsOverHttps")
            .field("configuration", &self.endpoint.configuration)
            .finish_non_exhaustive()
    }
}

/// Builds the private verifying HTTP client used for DoH exchanges.
pub struct DnsOverHttpsBuilder {
    client: ClientBuilder,
    url: Url,
    configuration: DohConfiguration,
}

impl DnsOverHttpsBuilder {
    /// Adds a DER certificate to the endpoint's normal public trust roots.
    #[must_use]
    pub fn add_root_certificate_der(mut self, certificate: impl Into<Box<[u8]>>) -> Self {
        self.client = self.client.add_root_certificate_der(certificate);
        self
    }

    /// Builds the endpoint without opening a connection.
    ///
    /// # Errors
    ///
    /// Returns [`DohBuildErrorKind::Client`] when the profile or trust roots
    /// cannot build the verifying HTTP client.
    pub fn build(self) -> Result<DnsOverHttps, DohBuildError> {
        let client = self.client.build().map_err(|source| DohBuildError {
            kind: DohBuildErrorKind::Client,
            source: Some(source),
        })?;
        let admission = Semaphore::new(self.configuration.maximum_lookups.get());
        Ok(DnsOverHttps {
            endpoint: Arc::new(Endpoint {
                client,
                url: self.url,
                configuration: self.configuration,
                admission,
            }),
        })
    }
}

impl fmt::Debug for DnsOverHttpsBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsOverHttpsBuilder")
            .field("configuration", &self.configuration)
            .finish_non_exhaustive()
    }
}

/// A recoverable DoH configuration or client construction failure.
#[derive(Debug)]
pub struct DohBuildError {
    kind: DohBuildErrorKind,
    source: Option<BuildError>,
}

/// The configuration that prevents a DoH endpoint from being built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DohBuildErrorKind {
    /// The URL is not a concrete, credential-free HTTPS DNS endpoint.
    InvalidEndpoint,
    /// No usable explicit bootstrap address was provided.
    InvalidBootstrap,
    /// A timeout or admission bound is zero, out of range or unrepresentable.
    InvalidLimits,
    /// The transport profile has no HTTP/2 settings.
    MissingHttp2,
    /// The underlying profile or verifying trust roots failed to build.
    Client,
}

impl DohBuildError {
    fn new(kind: DohBuildErrorKind) -> Self {
        Self { kind, source: None }
    }

    /// Returns the failed configuration category.
    #[must_use]
    pub const fn kind(&self) -> DohBuildErrorKind {
        self.kind
    }
}

impl fmt::Display for DohBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            DohBuildErrorKind::InvalidEndpoint => "invalid DNS-over-HTTPS endpoint",
            DohBuildErrorKind::InvalidBootstrap => "invalid DNS-over-HTTPS bootstrap addresses",
            DohBuildErrorKind::InvalidLimits => "invalid DNS-over-HTTPS work limits",
            DohBuildErrorKind::MissingHttp2 => "DNS-over-HTTPS requires HTTP/2 settings",
            DohBuildErrorKind::Client => "cannot build DNS-over-HTTPS client",
        })
    }
}

impl Error for DohBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|source| source as &dyn Error)
    }
}

fn transport_profile(profile: ClientProfile) -> Result<ClientProfile, DohBuildError> {
    let http2 = profile
        .http2()
        .cloned()
        .ok_or_else(|| DohBuildError::new(DohBuildErrorKind::MissingHttp2))?;
    // Exact direct H2 uses these transport settings. Carrying client hints
    // would append page fields and enable Accept-CH request restarts.
    let mut transport = ClientProfile::new(profile.tls().clone()).with_http2(http2);
    if let Some(tcp) = profile.tcp() {
        transport = transport.with_tcp(*tcp);
    }
    Ok(transport)
}

fn validate_configuration(configuration: &DohConfiguration) -> Result<Url, DohBuildError> {
    let invalid_endpoint = || DohBuildError::new(DohBuildErrorKind::InvalidEndpoint);
    if configuration.endpoint.contains(['{', '}']) {
        return Err(invalid_endpoint());
    }
    let url = Url::parse(&configuration.endpoint).map_err(|_| invalid_endpoint())?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
        || url.query_pairs().any(|(key, _)| key == "dns")
    {
        return Err(invalid_endpoint());
    }
    if configuration.bootstrap.is_empty()
        || configuration.bootstrap.iter().any(|address| {
            address.is_unspecified()
                || address.is_multicast()
                || match address {
                    IpAddr::V4(address) => address.is_broadcast(),
                    IpAddr::V6(address) => address.is_unicast_link_local(),
                }
        })
    {
        return Err(DohBuildError::new(DohBuildErrorKind::InvalidBootstrap));
    }
    let literal = match url.host() {
        Some(Host::Ipv4(address)) => Some(IpAddr::V4(address)),
        Some(Host::Ipv6(address)) => Some(IpAddr::V6(address)),
        Some(Host::Domain(_)) | None => None,
    };
    if literal.is_some_and(|literal| {
        configuration
            .bootstrap
            .iter()
            .any(|address| *address != literal)
    }) {
        return Err(DohBuildError::new(DohBuildErrorKind::InvalidBootstrap));
    }
    if configuration.lookup_timeout.is_zero()
        || !RequestTimeouts::new()
            .total(configuration.lookup_timeout)
            .validate()
        || configuration.maximum_lookups.get() > Semaphore::MAX_PERMITS
    {
        return Err(DohBuildError::new(DohBuildErrorKind::InvalidLimits));
    }
    Ok(url)
}
