use std::{
    fmt, io,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use phantom_net::dns::{DnsOverTlsTransport, HttpsRecordResolver};
use phantom_profile::TlsSettings;
use tokio::sync::Semaphore;

use super::{DohAddressFamilies, Endpoint, LookupSettings, Transport};
use crate::AddressResolver;

/// Address queries and the order of their combined DNS-over-TLS result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DotAddressFamilies {
    /// Query A records only.
    Ipv4Only,
    /// Query AAAA and A concurrently, returning IPv6 addresses first.
    DualIpv6First,
}

/// Explicit identity, bootstrap addresses and work bounds for DNS-over-TLS.
///
/// Connections go directly to these addresses. There is no resolver discovery,
/// OS DNS, cleartext fallback or automatic use of an application's proxy.
#[derive(Clone)]
pub struct DotConfiguration {
    name: String,
    bootstrap: Vec<SocketAddr>,
    families: DotAddressFamilies,
    lookup_timeout: Duration,
    maximum_lookups: NonZeroUsize,
    padding_block: Option<NonZeroU16>,
}

impl DotConfiguration {
    /// Selects the verified server name, explicit addresses and finite limits.
    ///
    /// Use port 853 normally. `name` remains the TLS authentication identity,
    /// independent of the bootstrap addresses. Names must be ASCII. The
    /// deadline covers setup, both address families and all CNAME follow-ups.
    /// At most 32767 lookups may be admitted concurrently. No DNS padding is
    /// sent by default. [`DnsOverTlsBuilder::build`] validates all settings.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        bootstrap: impl IntoIterator<Item = SocketAddr>,
        families: DotAddressFamilies,
        lookup_timeout: Duration,
        maximum_lookups: NonZeroUsize,
    ) -> Self {
        Self {
            name: name.into(),
            bootstrap: bootstrap.into_iter().collect(),
            families,
            lookup_timeout,
            maximum_lookups,
            padding_block: None,
        }
    }

    /// Pads each DNS message with zero EDNS bytes to a multiple of this size.
    #[must_use]
    pub const fn padding_block(mut self, block: Option<NonZeroU16>) -> Self {
        self.padding_block = block;
        self
    }
}

impl fmt::Debug for DotConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DotConfiguration")
            .field("bootstrap_addresses", &self.bootstrap.len())
            .field("families", &self.families)
            .field("lookup_timeout", &self.lookup_timeout)
            .field("maximum_lookups", &self.maximum_lookups)
            .field("padding_block", &self.padding_block)
            .finish_non_exhaustive()
    }
}

/// Verified address and HTTPS-record lookups on a shared TLS connection.
///
/// Clones and both resolver factories share connection and admission state.
/// Replies may arrive out of order. Dropping a lookup cancels its interest
/// without closing another lookup's connection. The application client owns
/// its separate DNS cache. This does not enable HTTP/3 discovery or DNSSEC
/// validation, or claim to reproduce a browser's encrypted DNS behavior.
#[derive(Clone)]
pub struct DnsOverTls {
    endpoint: Arc<Endpoint>,
}

impl DnsOverTls {
    /// Prepares an endpoint builder without opening a connection.
    ///
    /// TLS uses normal public trust roots and hostname verification. Its ALPN
    /// is `dot`, with ALPS and early data disabled. Other supplied TLS settings
    /// remain in effect.
    ///
    /// ```no_run
    /// use std::{num::NonZeroUsize, time::Duration};
    /// use phantom::{Client, dns::{DnsOverTls, DotConfiguration, DotAddressFamilies},
    ///     profile::browser::chrome};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let profile = chrome::v154_windows();
    /// let configuration = DotConfiguration::new(
    ///     "dns.example", ["192.0.2.1:853".parse()?],
    ///     DotAddressFamilies::DualIpv6First, Duration::from_secs(5),
    ///     NonZeroUsize::MIN,
    /// );
    /// let dot = DnsOverTls::builder(profile.tls().clone(), configuration).build()?;
    /// let client = Client::builder(profile).dns_resolver(dot.address_resolver()).build()?;
    /// # drop(client);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn builder(settings: TlsSettings, configuration: DotConfiguration) -> DnsOverTlsBuilder {
        DnsOverTlsBuilder {
            settings,
            configuration,
            roots: Vec::new(),
        }
    }

    /// Returns bounded address lookups, with IPv6 first for dual-family queries.
    ///
    /// Names, ordering, CNAME budgets, negative answers and partial-family
    /// results follow [`super::DnsOverHttps::address_resolver`]. A failed family
    /// leaves a positive sibling usable with zero cache lifetime.
    #[must_use]
    pub fn address_resolver(&self) -> AddressResolver {
        super::address_resolver(&self.endpoint)
    }

    /// Returns bounded HTTPS-record lookups over this same TLS connection.
    ///
    /// Non-default ports use `_<port>._https.<host>`. CNAMEs retain their budget
    /// and expiry. HTTPS AliasMode targets are returned without following them.
    #[must_use]
    pub fn https_record_resolver(&self) -> HttpsRecordResolver {
        super::https_record_resolver(&self.endpoint)
    }
}

impl fmt::Debug for DnsOverTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsOverTls")
            .field("settings", &self.endpoint.settings)
            .finish_non_exhaustive()
    }
}

/// Builds a verified DNS-over-TLS endpoint with optional additional trust roots.
pub struct DnsOverTlsBuilder {
    settings: TlsSettings,
    configuration: DotConfiguration,
    roots: Vec<Box<[u8]>>,
}

impl DnsOverTlsBuilder {
    /// Adds a DER certificate to the endpoint's normal public trust roots.
    #[must_use]
    pub fn add_root_certificate_der(mut self, certificate: impl Into<Box<[u8]>>) -> Self {
        self.roots.push(certificate.into());
        self
    }

    /// Validates all settings and builds an endpoint without network I/O.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for an invalid name, bootstrap address, timeout,
    /// admission bound, TLS setting or trust root. Errors retain their sources.
    pub fn build(self) -> io::Result<DnsOverTls> {
        let configuration = self.configuration;
        let maximum_queries = configuration
            .maximum_lookups
            .get()
            .checked_mul(2)
            .filter(|queries| *queries <= usize::from(u16::MAX))
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid DNS-over-TLS lookup limit",
                )
            })?;
        let transport = DnsOverTlsTransport::new_with_additional_roots(
            &self.settings,
            &configuration.name,
            configuration.bootstrap,
            configuration.lookup_timeout,
            maximum_queries,
            self.roots.iter().map(AsRef::as_ref),
        )?;
        Ok(DnsOverTls {
            endpoint: Arc::new(Endpoint {
                transport: Transport::Tls(transport),
                settings: LookupSettings {
                    families: match configuration.families {
                        DotAddressFamilies::Ipv4Only => DohAddressFamilies::Ipv4Only,
                        DotAddressFamilies::DualIpv6First => DohAddressFamilies::DualIpv6First,
                    },
                    lookup_timeout: configuration.lookup_timeout,
                    query_id: 0,
                    padding_block: configuration.padding_block,
                },
                admission: Semaphore::new(configuration.maximum_lookups.get()),
            }),
        })
    }
}

impl fmt::Debug for DnsOverTlsBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsOverTlsBuilder")
            .field("configuration", &self.configuration)
            .field("additional_roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}
