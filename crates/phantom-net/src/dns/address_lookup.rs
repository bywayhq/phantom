//! Address lookups with Phantom's own A and AAAA queries, made as Chromium's
//! built-in DNS client makes them.
//!
//! The rules follow Chromium at tag `154.0.8037.58`: `localhost` names are
//! answered locally (`net/dns/host_resolver_manager.cc:334-344`,
//! `:1260-1282`); names under `local` go to the system resolver
//! (`:1459-1504`); the hosts file answers before DNS (`:1169-1258`); AAAA is
//! queried only when the IPv6 probe finds a global route (`:820-841`,
//! `:1569-1694`), AAAA before A
//! (`net/dns/host_resolver_dns_task.cc:393-433`); a failed or empty DNS task
//! falls back to the system resolver (`net/dns/host_resolver_manager.cc:1415-1421`,
//! `net/dns/host_resolver_manager_job.cc:932-946`), and 16 such fallbacks in
//! a row turn the built-in client off (`net/dns/dns_client.h:67`,
//! `net/dns/dns_client.cc:245-256`, `net/dns/host_resolver_manager.cc:1869-1880`).

use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use hickory_resolver::{
    Hosts,
    lookup::Lookup,
    net::{DnsError, NetError},
    proto::{
        op::Query,
        rr::{Name, RData, RecordType},
    },
};
use phantom_profile::UdpSettings;
use tokio::sync::Notify;

use super::{Nameservers, query_sockets::notify_sent_queries};
use crate::host_resolver::{DnsLookup, ResolveFuture, Resolved};

/// Consecutive lookups that needed the system resolver after which the DNS
/// queries stop, Chromium's `kMaxInsecureFallbackFailures`.
const MAX_FALLBACKS: u32 = 16;

/// How long one IPv6 probe result is reused, Chromium's `kIPv6ProbePeriodMs`.
const PROBE_PERIOD: Duration = Duration::from_secs(1);

/// The destination of the IPv6 probe, Chromium's `kIPv6ProbeAddress`
/// (Google Public DNS), and its port.
const PROBE_DESTINATION: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    443,
);

/// Resolves host names with Phantom's own A and AAAA queries.
pub(crate) struct AddressLookup {
    nameservers: Nameservers,
    hosts: Arc<Hosts>,
    /// Shared with every lookup made from this one with other UDP settings,
    /// as one Chromium resolver keeps one probe result.
    ipv6: Arc<Ipv6Route>,
    system: SystemResolver,
    /// Lookups in a row that the system resolver answered after the DNS
    /// queries failed, shared as `ipv6` is, as Chromium's `DnsClient` keeps
    /// one count.
    fallbacks: Arc<AtomicU32>,
}

impl AddressLookup {
    pub(crate) fn system() -> io::Result<Self> {
        Ok(Self::new(
            Nameservers::system().map_err(configuration_error)?,
        ))
    }

    pub(crate) fn with_nameservers(
        nameservers: impl IntoIterator<Item = SocketAddr>,
    ) -> io::Result<Self> {
        Ok(Self::new(
            Nameservers::with_addresses(nameservers).map_err(configuration_error)?,
        ))
    }

    fn new(nameservers: Nameservers) -> Self {
        Self {
            nameservers,
            // A missing or unreadable hosts file answers nothing, as
            // Chromium's empty `DnsHosts` does.
            hosts: Arc::new(Hosts::from_system().unwrap_or_default()),
            ipv6: Arc::new(Ipv6Route::Probe(Mutex::default())),
            system: SystemResolver::Os,
            fallbacks: Arc::default(),
        }
    }

    /// A lookup that queries `nameservers`, reads `hosts` as a hosts file,
    /// takes `ipv6` as the probe's answer, and answers every system lookup
    /// with `system`, so a test opens no probe socket and needs no network.
    #[cfg(test)]
    pub(crate) fn for_test(
        nameservers: impl IntoIterator<Item = SocketAddr>,
        hosts: &str,
        ipv6: bool,
        system: Vec<IpAddr>,
    ) -> io::Result<Self> {
        let mut parsed = Hosts::default();
        parsed.read_hosts_conf(hosts.as_bytes())?;
        Ok(Self {
            hosts: Arc::new(parsed),
            ipv6: Arc::new(Ipv6Route::Fixed(ipv6)),
            system: SystemResolver::Fixed(system),
            ..Self::with_nameservers(nameservers)?
        })
    }

    /// Returns a lookup with the same nameservers, hosts file, probe result,
    /// and fallback count whose query sockets open with `settings`.
    pub(crate) fn with_udp_settings(&self, settings: UdpSettings) -> Self {
        Self {
            nameservers: self.nameservers.with_udp_settings(settings),
            hosts: Arc::clone(&self.hosts),
            ipv6: Arc::clone(&self.ipv6),
            system: self.system.clone(),
            fallbacks: Arc::clone(&self.fallbacks),
        }
    }

    pub(crate) fn udp_settings(&self) -> Option<UdpSettings> {
        self.nameservers.udp
    }

    /// Resolves `host`, a lowercased name that is not an IP literal.
    pub(crate) async fn resolve(&self, host: &str) -> io::Result<Resolved> {
        if is_localhost(host) {
            return Ok(Resolved::without_ttl([
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ]));
        }
        let ipv6 = self.ipv6.reachable(self.nameservers.udp);
        let name = match fully_qualified(host) {
            Some(name) if self.fallbacks.load(Ordering::Relaxed) < MAX_FALLBACKS => name,
            _ => return self.resolve_by_system(host, ipv6).await,
        };
        if let Some(addresses) = self.hosts_answer(&name, ipv6) {
            return Ok(Resolved::without_ttl(addresses));
        }
        if let Some(resolved) = self.query(name, ipv6).await {
            self.fallbacks.store(0, Ordering::Relaxed);
            return Ok(resolved);
        }
        // Chromium counts a fallback only once the system resolver has
        // answered (`net/dns/host_resolver_manager_job.cc:787-792`,
        // `net/dns/host_resolver_manager.cc:1869-1880`), and clears the count
        // only on a DNS answer or a new DNS configuration
        // (`net/dns/dns_client.cc:385-391`), which this lookup never reads
        // again.
        let resolved = self.resolve_by_system(host, ipv6).await?;
        self.fallbacks.fetch_add(1, Ordering::Relaxed);
        Ok(resolved)
    }

    /// Resolves `host` through the system resolver for the families the
    /// probe allows.
    ///
    /// Without a global IPv6 route Chromium asks `getaddrinfo` for IPv4
    /// only, and asks again for both families when every IPv4 address is a
    /// loopback address (`net/dns/host_resolver_system_task.cc:539-549`,
    /// `:628-645`). Phantom asks for both and keeps the same addresses.
    async fn resolve_by_system(&self, host: &str, ipv6: bool) -> io::Result<Resolved> {
        let mut resolved = self.system.resolve(host).await?;
        if ipv6 {
            return Ok(resolved);
        }
        let ipv4: Vec<_> = resolved
            .addresses
            .iter()
            .copied()
            .filter(SocketAddr::is_ipv4)
            .collect();
        if ipv4.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{host} has no IPv4 address, and this host has no global IPv6 route"),
            ));
        }
        if !ipv4.iter().all(|address| address.ip().is_loopback()) {
            resolved.addresses = ipv4;
        }
        Ok(resolved)
    }

    /// Returns the hosts file's addresses for `name`, IPv6 first.
    fn hosts_answer(&self, name: &Name, ipv6: bool) -> Option<Vec<IpAddr>> {
        let addresses = families(ipv6)
            .iter()
            .filter_map(|family| {
                self.hosts
                    .lookup_static_host(&Query::query(name.clone(), *family))
            })
            .flat_map(|lookup| addresses(&lookup).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        (!addresses.is_empty()).then_some(addresses)
    }

    /// Sends the AAAA query, when `ipv6`, and the A query, and returns their
    /// addresses, IPv6 first, with the smallest TTL; or `None` when a query
    /// failed or no address came back.
    async fn query(&self, name: Name, ipv6: bool) -> Option<Resolved> {
        let resolver = self.nameservers.resolver().ok()?;
        // The A query waits until the AAAA datagram has been sent, or the
        // AAAA lookup has ended without one, so AAAA always goes first.
        let aaaa_sent = Arc::new(Notify::new());
        let (aaaa, a) = tokio::join!(
            async {
                if !ipv6 {
                    aaaa_sent.notify_one();
                    return None;
                }
                let lookup = resolver.lookup(name.clone(), RecordType::AAAA);
                let result = notify_sent_queries(Arc::clone(&aaaa_sent), lookup).await;
                aaaa_sent.notify_one();
                Some(result)
            },
            async {
                aaaa_sent.notified().await;
                resolver.lookup(name.clone(), RecordType::A).await
            },
        );
        let mut found = Vec::new();
        let mut ttl: Option<u32> = None;
        for answer in [aaaa, Some(a)].into_iter().flatten() {
            let (addresses, answer_ttl) = family_answer(answer)?;
            found.extend(addresses);
            ttl = match (ttl, answer_ttl) {
                (Some(ttl), Some(answer_ttl)) => Some(ttl.min(answer_ttl)),
                (ttl, answer_ttl) => ttl.or(answer_ttl),
            };
        }
        if found.is_empty() {
            return None;
        }
        let mut resolved = Resolved::without_ttl(found);
        resolved.ttl = ttl.map(|seconds| Duration::from_secs(u64::from(seconds)));
        Some(resolved)
    }
}

impl DnsLookup for AddressLookup {
    fn start(self: Arc<Self>, host: String) -> ResolveFuture {
        Box::pin(async move { self.resolve(&host).await })
    }

    fn opened_with(&self, settings: UdpSettings) -> Arc<dyn DnsLookup> {
        Arc::new(self.with_udp_settings(settings))
    }

    fn socket_settings(&self) -> Option<UdpSettings> {
        self.udp_settings()
    }
}

impl fmt::Debug for AddressLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddressLookup")
            .field("nameservers", &self.nameservers)
            .finish_non_exhaustive()
    }
}

/// Whether this host has a global IPv6 route, as Chromium's probe decides.
enum Ipv6Route {
    /// The last probe's time and result.
    Probe(Mutex<Option<(Instant, bool)>>),
    /// A fixed answer, so tests open no probe socket.
    #[cfg(test)]
    Fixed(bool),
}

impl Ipv6Route {
    fn reachable(&self, udp: Option<UdpSettings>) -> bool {
        let last = match self {
            Self::Probe(last) => last,
            #[cfg(test)]
            Self::Fixed(reachable) => return *reachable,
        };
        let mut last = last.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((at, reachable)) = *last
            && at.elapsed() <= PROBE_PERIOD
        {
            return reachable;
        }
        let reachable = probe(udp);
        *last = Some((Instant::now(), reachable));
        reachable
    }
}

/// Binds a UDP socket to `[::]:0` with the profile's UDP settings, as
/// Chromium sets `SO_RANDOMIZE_PORT` on its probe socket, connects it to
/// [`PROBE_DESTINATION`], which sends nothing, and reports whether the
/// source address the route gives it is neither link-local nor Teredo, as
/// Chromium's `FinishGloballyReachableCheck` does
/// (`net/dns/host_resolver_manager.cc:1644-1694`).
fn probe(udp: Option<UdpSettings>) -> bool {
    let local = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    let bind = |udp| crate::udp::bind_socket(PROBE_DESTINATION, local, None, udp);
    let Some(socket) = probe_socket(udp, bind) else {
        return false;
    };
    if socket.connect(PROBE_DESTINATION).is_err() {
        return false;
    }
    socket
        .local_addr()
        .is_ok_and(|address| globally_reachable(address.ip()))
}

/// Binds the probe socket with `udp`, or without it when that bind fails.
///
/// Chromium ignores a failure to set `SO_RANDOMIZE_PORT`
/// (`net/socket/udp_socket_win.cc:563-568`), so a rejected option must not
/// turn into a missing IPv6 route and stop the AAAA queries.
fn probe_socket(
    udp: Option<UdpSettings>,
    bind: impl Fn(Option<UdpSettings>) -> io::Result<std::net::UdpSocket>,
) -> Option<std::net::UdpSocket> {
    match bind(udp) {
        Ok(socket) => Some(socket),
        Err(_) if udp.is_some() => bind(None).ok(),
        Err(_) => None,
    }
}

fn globally_reachable(source: IpAddr) -> bool {
    match source {
        IpAddr::V6(address) => {
            let [first, second, ..] = address.segments();
            let link_local = first & 0xffc0 == 0xfe80;
            let teredo = first == 0x2001 && second == 0;
            !link_local && !teredo
        }
        IpAddr::V4(address) => !address.is_link_local(),
    }
}

/// The query types for an address lookup, in the order they start.
const fn families(ipv6: bool) -> &'static [RecordType] {
    if ipv6 {
        &[RecordType::AAAA, RecordType::A]
    } else {
        &[RecordType::A]
    }
}

/// One family's addresses and smallest TTL, or `None` when its query failed.
///
/// An empty answer (NXDOMAIN, or NOERROR without records) is no addresses,
/// with the TTL of its SOA record, which Chromium counts toward the entry's
/// TTL (`net/dns/dns_response_result_extractor.cc:265-296`).
fn family_answer(answer: Result<Lookup, NetError>) -> Option<(Vec<IpAddr>, Option<u32>)> {
    match answer {
        Ok(lookup) => Some((
            addresses(&lookup).collect(),
            lookup.answers().iter().map(|record| record.ttl).min(),
        )),
        Err(NetError::Dns(DnsError::NoRecordsFound(empty))) => {
            Some((Vec::new(), empty.soa.map(|soa| soa.ttl)))
        }
        Err(_) => None,
    }
}

fn addresses(lookup: &Lookup) -> impl Iterator<Item = IpAddr> + '_ {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address) => Some(IpAddr::V4(address.0)),
            RData::AAAA(address) => Some(IpAddr::V6(address.0)),
            _ => None,
        })
}

/// `localhost`, `localhost.`, and names under it, Chromium's
/// `IsLocalHostname`.
fn is_localhost(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    host == "localhost" || host.ends_with(".localhost")
}

/// Returns the name to query, or `None` for a name the system resolver
/// answers: one without a dot, which Chromium would extend with the search
/// suffixes, or one under `local`, Chromium's `ResemblesMulticastDNSName`.
fn fully_qualified(host: &str) -> Option<Name> {
    let bare = host.strip_suffix('.').unwrap_or(host);
    if !host.contains('.') || bare == "local" || bare.ends_with(".local") {
        return None;
    }
    Name::from_ascii(format!("{bare}.")).ok()
}

/// How names the DNS queries do not answer are resolved.
#[derive(Clone)]
enum SystemResolver {
    /// Through the operating system, as Chromium's `HostResolverSystemTask`
    /// does.
    Os,
    /// With fixed addresses, so tests need no network.
    #[cfg(test)]
    Fixed(Vec<IpAddr>),
}

impl SystemResolver {
    async fn resolve(&self, host: &str) -> io::Result<Resolved> {
        match self {
            Self::Os => Ok(Resolved {
                addresses: tokio::net::lookup_host((host, 0)).await?.collect(),
                ttl: None,
            }),
            #[cfg(test)]
            Self::Fixed(addresses) => Ok(Resolved::without_ttl(addresses.iter().copied())),
        }
    }
}

fn configuration_error(detail: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid DNS resolver configuration: {detail}"),
    )
}

#[cfg(test)]
mod tests;
