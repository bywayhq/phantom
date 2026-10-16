//! Paired system DNS snapshots. Native refresh and shutdown have one owner.

#[cfg(target_os = "linux")]
use super::linux_system_configuration::{
    ConfigurationEligibility, ConfigurationError, ConfigurationGeneration,
    ConfigurationIneligibility, ConfigurationObserver, ConfigurationWatch, WatchError,
};
#[cfg(windows)]
use super::system_configuration::{
    ConfigurationError, WindowsDnsEligibility as ConfigurationEligibility,
    WindowsDnsIneligibility as ConfigurationIneligibility, chromium_windows,
};
use super::{AddressLookup, HttpsLookupError, HttpsRecordLookup, HttpsRecordResolver, Nameservers};
use crate::host_resolver::{
    AddressResolver, DnsConfigurationToken, DnsLookup, ResolveFuture, configuration_changed,
};
#[cfg(windows)]
use crate::system_dns_ffi::{
    configuration::read_windows_settings,
    configuration_watch::{
        ConfigurationGeneration, ConfigurationObserver, ConfigurationWatch, WatchError,
    },
};
use phantom_profile::UdpSettings;
use std::{
    fmt, io,
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
};
use tokio::sync::watch;

#[derive(Debug)]
enum ConfigurationFailure {
    Read(ConfigurationError),
    Watch(WatchError),
    ThreadStart(io::Error),
    WorkerStopped,
    RefreshCapacity,
    StatePoisoned,
    SystemOnly(ConfigurationIneligibility),
}
impl fmt::Display for ConfigurationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => fmt::Display::fmt(error, f),
            Self::Watch(error) => fmt::Display::fmt(error, f),
            Self::ThreadStart(_) => f.write_str("cannot start system DNS owner"),
            Self::WorkerStopped => f.write_str("system DNS owner stopped"),
            Self::RefreshCapacity => f.write_str("system DNS refresh queue is full"),
            Self::StatePoisoned => f.write_str("system DNS generation state poisoned"),
            Self::SystemOnly(reasons) => write!(
                f,
                "system DNS configuration requires the system resolver; raw HTTPS queries are unavailable ({reasons:?})"
            ),
        }
    }
}
impl std::error::Error for ConfigurationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Watch(error) => Some(error),
            Self::ThreadStart(error) => Some(error),
            _ => None,
        }
    }
}
fn failure(error: ConfigurationFailure) -> io::Error {
    io::Error::other(error)
}

type RefreshOutcome = Result<Arc<Snapshot>, Arc<io::Error>>;
type RefreshReceiver = watch::Receiver<Option<RefreshOutcome>>;

struct Refresh {
    generation: ConfigurationGeneration,
    token: DnsConfigurationToken,
    reply: watch::Sender<Option<RefreshOutcome>>,
}

#[derive(Default)]
struct SnapshotState {
    cached: Option<(DnsConfigurationToken, Arc<Snapshot>)>,
    pending: Option<(DnsConfigurationToken, RefreshReceiver)>,
}

enum SnapshotSelection {
    Cached(Arc<Snapshot>),
    Waiting {
        receiver: RefreshReceiver,
        same_generation: bool,
    },
    Start {
        receiver: RefreshReceiver,
        reply: watch::Sender<Option<RefreshOutcome>>,
    },
}

impl SnapshotState {
    fn select(&mut self, token: &DnsConfigurationToken) -> io::Result<SnapshotSelection> {
        token.require_current()?;
        if let Some((known, snapshot)) = &self.cached
            && known == token
        {
            return Ok(SnapshotSelection::Cached(Arc::clone(snapshot)));
        }
        if let Some((known, receiver)) = &self.pending {
            return Ok(SnapshotSelection::Waiting {
                receiver: receiver.clone(),
                same_generation: known == token,
            });
        }
        let (reply, receiver) = watch::channel(None);
        // The owner retains a receiver until the actual worker completes,
        // even when every requesting future is cancelled.
        self.pending = Some((token.clone(), receiver.clone()));
        Ok(SnapshotSelection::Start { receiver, reply })
    }

    fn finish(
        &mut self,
        token: &DnsConfigurationToken,
        mut result: io::Result<Arc<Snapshot>>,
    ) -> RefreshOutcome {
        if let Err(error) = token.require_current() {
            result = Err(error);
        }
        let is_pending = self
            .pending
            .as_ref()
            .is_some_and(|(known, _)| known == token);
        if is_pending && let Ok(snapshot) = &result {
            self.cached = Some((token.clone(), Arc::clone(snapshot)));
        }
        // The actual read and projection have completed. Release admission
        // here, then notify outside this lock before the worker reads again.
        if is_pending {
            self.pending = None;
        }
        result.map_err(Arc::new)
    }
}

#[derive(Debug)]
struct SharedRefreshError(Arc<io::Error>);
impl fmt::Display for SharedRefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}
impl std::error::Error for SharedRefreshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

async fn completed(receiver: &mut RefreshReceiver) -> io::Result<RefreshOutcome> {
    receiver
        .wait_for(Option::is_some)
        .await
        .map_err(|_| failure(ConfigurationFailure::WorkerStopped))?
        .as_ref()
        .cloned()
        .ok_or_else(|| failure(ConfigurationFailure::WorkerStopped))
}

struct SystemDnsOwner {
    observer: ConfigurationObserver,
    generation: Mutex<Option<(ConfigurationGeneration, DnsConfigurationToken)>>,
    snapshots: Arc<Mutex<SnapshotState>>,
    requests: Option<mpsc::SyncSender<Refresh>>,
    worker: Option<JoinHandle<io::Result<()>>>,
}
impl fmt::Debug for SystemDnsOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SystemDnsOwner(..)")
    }
}

impl SystemDnsOwner {
    fn start() -> io::Result<Arc<Self>> {
        let (requests, receive) = mpsc::sync_channel::<Refresh>(1);
        let (ready, started) = mpsc::sync_channel(1);
        let snapshots = Arc::new(Mutex::new(SnapshotState::default()));
        let worker_snapshots = Arc::clone(&snapshots);
        let worker = thread::Builder::new()
            .name("phantom-dns-configuration".into())
            .spawn(move || {
                let watch = match ConfigurationWatch::start() {
                    Ok(watch) => watch,
                    Err(error) => {
                        // Transfer the original failure to the constructor.
                        // Linux I/O errors have one owner rather than Copy.
                        return ready
                            .send(Err(error))
                            .map_err(|_| failure(ConfigurationFailure::WorkerStopped));
                    }
                };
                if ready.send(Ok(watch.observer())).is_err() {
                    return watch
                        .shutdown()
                        .map_err(|error| failure(ConfigurationFailure::Watch(error)));
                }
                while let Ok(request) = receive.recv() {
                    let result = refresh(&watch, &request.generation);
                    let outcome = match worker_snapshots.lock() {
                        Ok(mut snapshots) => snapshots.finish(&request.token, result),
                        Err(_) => Err(Arc::new(failure(ConfigurationFailure::StatePoisoned))),
                    };
                    // Waking consumers never holds the snapshot mutex.
                    drop(request.reply.send_replace(Some(outcome)));
                }
                // No resolver/cache mutex is held. All native registrations are joined here.
                watch
                    .shutdown()
                    .map_err(|error| failure(ConfigurationFailure::Watch(error)))
            })
            .map_err(|error| failure(ConfigurationFailure::ThreadStart(error)))?;
        match started.recv() {
            Ok(Ok(observer)) => Ok(Arc::new(Self {
                observer,
                generation: Mutex::new(None),
                snapshots,
                requests: Some(requests),
                worker: Some(worker),
            })),
            result => {
                drop(requests);
                let joined = worker.join();
                match result {
                    Ok(Err(error)) => Err(failure(ConfigurationFailure::Watch(error))),
                    _ => joined
                        .unwrap_or_else(|_| Err(failure(ConfigurationFailure::WorkerStopped)))
                        .and(Err(failure(ConfigurationFailure::WorkerStopped))),
                }
            }
        }
    }

    fn token(&self) -> io::Result<(ConfigurationGeneration, DnsConfigurationToken)> {
        let observed = self
            .observer
            .observed()
            .map_err(|error| failure(ConfigurationFailure::Watch(error)))?;
        let mut generation = self
            .generation
            .lock()
            .map_err(|_| failure(ConfigurationFailure::StatePoisoned))?;
        if let Some((known, token)) = &*generation
            && *known == observed
        {
            token.require_current()?;
            return Ok((observed, token.clone()));
        }
        let observer = self.observer.clone();
        let expected = observed.clone();
        let token = DnsConfigurationToken::new(move || {
            observer
                .observed()
                .map(|current| current == expected)
                .map_err(|error| failure(ConfigurationFailure::Watch(error)))
        });
        token.require_current()?;
        *generation = Some((observed.clone(), token.clone()));
        Ok((observed, token))
    }

    async fn snapshot(&self, token: &DnsConfigurationToken) -> io::Result<Arc<Snapshot>> {
        loop {
            let (generation, current) = self.token()?;
            if current != *token {
                return Err(configuration_changed());
            }
            let selected = self
                .snapshots
                .lock()
                .map_err(|_| failure(ConfigurationFailure::StatePoisoned))?
                .select(token)?;
            let (mut receiver, same_generation) = match selected {
                SnapshotSelection::Cached(snapshot) => {
                    token.require_current()?;
                    return Ok(snapshot);
                }
                SnapshotSelection::Waiting {
                    receiver,
                    same_generation,
                } => (receiver, same_generation),
                SnapshotSelection::Start { receiver, reply } => {
                    let request = Refresh {
                        generation,
                        token: token.clone(),
                        reply,
                    };
                    let send = match self.requests.as_ref() {
                        Some(requests) => requests.try_send(request).map_err(|error| match error {
                            mpsc::TrySendError::Full(request) => {
                                (request, ConfigurationFailure::RefreshCapacity)
                            }
                            mpsc::TrySendError::Disconnected(request) => {
                                (request, ConfigurationFailure::WorkerStopped)
                            }
                        }),
                        None => Err((request, ConfigurationFailure::WorkerStopped)),
                    };
                    if let Err((request, error)) = send {
                        let outcome = self
                            .snapshots
                            .lock()
                            .map_err(|_| failure(ConfigurationFailure::StatePoisoned))?
                            .finish(&request.token, Err(failure(error)));
                        drop(request.reply.send_replace(Some(outcome)));
                    }
                    (receiver, true)
                }
            };
            let result = completed(&mut receiver).await?;
            token.require_current()?;
            if same_generation {
                return result
                    .map_err(|error| io::Error::new(error.kind(), SharedRefreshError(error)));
            }
            // Another generation's refresh was already owned. Its completion
            // releases admission for this generation's first settings read.
        }
    }
}

impl Drop for SystemDnsOwner {
    fn drop(&mut self) {
        // Tokens hold only the native read-only observer, never this owner.
        // Disconnect first, then join the one thread that shuts down the watch.
        // Native cancellation and joining can block the dropping thread.
        drop(self.requests.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn refresh(
    watch: &ConfigurationWatch,
    expected: &ConfigurationGeneration,
) -> io::Result<Arc<Snapshot>> {
    let observe = || {
        #[cfg(windows)]
        let result = watch.observer().observed();
        #[cfg(target_os = "linux")]
        let result = watch.check();
        result.map_err(|error| failure(ConfigurationFailure::Watch(error)))
    };
    read_current_snapshot(
        || observe().map(|generation| generation == *expected),
        || {
            #[cfg(windows)]
            let result = read_windows_settings();
            #[cfg(target_os = "linux")]
            let result = watch.read_configuration();
            result.map_err(|error| failure(ConfigurationFailure::Read(error)))
        },
        |settings| {
            #[cfg(windows)]
            let eligibility = chromium_windows(&settings)
                .map_err(|error| failure(ConfigurationFailure::Read(error)))?;
            #[cfg(target_os = "linux")]
            let eligibility = settings;
            Snapshot::new(eligibility).map(Arc::new)
        },
    )
}

fn read_current_snapshot<R, S>(
    current: impl Fn() -> io::Result<bool>,
    read: impl FnOnce() -> io::Result<R>,
    prepare: impl FnOnce(R) -> io::Result<S>,
) -> io::Result<S> {
    if !current()? {
        return Err(configuration_changed());
    }
    let raw = read()?;
    if !current()? {
        return Err(configuration_changed());
    }
    let prepared = prepare(raw)?;
    if !current()? {
        return Err(configuration_changed());
    }
    Ok(prepared)
}

enum Snapshot {
    BuiltIn([Arc<AddressLookup>; 3]),
    SystemOnly(ConfigurationIneligibility),
}
impl Snapshot {
    fn new(eligibility: ConfigurationEligibility) -> io::Result<Self> {
        match eligibility {
            ConfigurationEligibility::BuiltIn(configuration) => {
                #[cfg(windows)]
                let base = Arc::new(AddressLookup::from_configuration(&configuration)?);
                #[cfg(target_os = "linux")]
                let base = Arc::new(AddressLookup::from_linux_configuration(&configuration)?);
                Ok(Self::BuiltIn([
                    Arc::clone(&base),
                    Arc::new(base.with_udp_settings(UdpSettings {
                        port_randomization: false,
                    })),
                    Arc::new(base.with_udp_settings(UdpSettings {
                        port_randomization: true,
                    })),
                ]))
            }
            ConfigurationEligibility::SystemOnly { reasons, .. } => Ok(Self::SystemOnly(reasons)),
        }
    }
    async fn resolve_address(
        &self,
        host: &str,
        udp: Option<UdpSettings>,
    ) -> io::Result<crate::host_resolver::Resolved> {
        match self {
            Self::BuiltIn(_) => self.lookup(udp)?.resolve(host).await,
            Self::SystemOnly(_) => AddressLookup::system_only(host).await,
        }
    }

    fn lookup(&self, udp: Option<UdpSettings>) -> io::Result<Arc<AddressLookup>> {
        match self {
            Self::BuiltIn(views) => Ok(Arc::clone(
                &views[match udp {
                    None => 0,
                    Some(UdpSettings {
                        port_randomization: false,
                    }) => 1,
                    Some(UdpSettings {
                        port_randomization: true,
                    }) => 2,
                }],
            )),
            Self::SystemOnly(reasons) => {
                #[cfg(windows)]
                let reasons = *reasons;
                #[cfg(target_os = "linux")]
                let reasons = reasons.clone();
                Err(failure(ConfigurationFailure::SystemOnly(reasons)))
            }
        }
    }
}

// Erase the shared owner's structural auto-trait graph at its existing Arc.
// Lookup futures still borrow the same concrete owner and are checked locally.
trait SystemDnsState: fmt::Debug + Send + Sync {
    fn state(&self) -> &SystemDnsOwner;
}

impl SystemDnsState for SystemDnsOwner {
    fn state(&self) -> &SystemDnsOwner {
        self
    }
}

#[derive(Clone, Debug)]
pub(super) struct SystemDnsView {
    owner: Arc<dyn SystemDnsState>,
    udp: Option<UdpSettings>,
}
impl SystemDnsView {
    pub(super) fn with_udp_settings(&self, udp: UdpSettings) -> Self {
        Self {
            owner: Arc::clone(&self.owner),
            udp: Some(udp),
        }
    }
    pub(super) fn udp_settings(&self) -> Option<UdpSettings> {
        self.udp
    }
    pub(super) fn configuration_token(&self) -> io::Result<DnsConfigurationToken> {
        self.owner.state().token().map(|(_, token)| token)
    }
    pub(super) async fn https(
        &self,
        host: &str,
        port: u16,
        token: DnsConfigurationToken,
    ) -> Result<HttpsRecordLookup, HttpsLookupError> {
        let snapshot = self
            .owner
            .state()
            .snapshot(&token)
            .await
            .map_err(HttpsLookupError::configuration)?;
        // Mode selection precedes any query socket or address probe.
        let lookup = snapshot
            .lookup(self.udp)
            .map_err(HttpsLookupError::configuration)?;
        let nameservers: Nameservers = lookup.nameservers();
        token
            .require_current()
            .map_err(HttpsLookupError::configuration)?;
        let result = super::lookup_dns(&nameservers, host, port).await;
        token
            .require_current()
            .map_err(HttpsLookupError::configuration)?;
        result
    }
}
impl DnsLookup for SystemDnsView {
    fn start(self: Arc<Self>, host: String) -> ResolveFuture {
        let token = self.configuration_token();
        Box::pin(async move {
            let token = token?;
            Arc::clone(&self)
                .start_with_configuration(host, Some(token))
                .await
        })
    }
    fn start_with_configuration(
        self: Arc<Self>,
        host: String,
        token: Option<DnsConfigurationToken>,
    ) -> ResolveFuture {
        Box::pin(async move {
            let token = token.ok_or_else(configuration_changed)?;
            let snapshot = self.owner.state().snapshot(&token).await?;
            token.require_current()?;
            let result = snapshot.resolve_address(&host, self.udp).await;
            token.require_current()?;
            result
        })
    }
    fn opened_with(&self, settings: UdpSettings) -> Arc<dyn DnsLookup> {
        Arc::new(self.with_udp_settings(settings))
    }
    fn socket_settings(&self) -> Option<UdpSettings> {
        self.udp
    }
    fn configuration_token(&self) -> io::Result<Option<DnsConfigurationToken>> {
        SystemDnsView::configuration_token(self).map(Some)
    }
}

/// Constructs an explicitly paired Windows address/HTTPS resolver.
///
/// Apply the two returned values through the existing client builder methods.
/// Callers own HTTPS cache invalidation with the opaque token methods. Known
/// configuration changes fail the current lookup; there is no automatic retry.
/// Dropping the final resolver waits for its native watcher to stop and
/// can block the dropping thread. Requires Windows and `https-records`.
///
/// # Errors
///
/// Returns runtime, worker-startup, or native configuration-watch errors.
#[cfg(windows)]
pub async fn chromium_windows_resolvers() -> io::Result<(AddressResolver, HttpsRecordResolver)> {
    let owner = tokio::task::spawn_blocking(SystemDnsOwner::start)
        .await
        .map_err(io::Error::other)??;
    let view = SystemDnsView { owner, udp: None };
    Ok((
        AddressResolver::from_dns_backend(Arc::new(view.clone())),
        HttpsRecordResolver::from_system(view),
    ))
}

/// Constructs paired Linux address and HTTPS resolvers from one watched configuration.
///
/// Search domains, NSS eligibility, ordered servers, retries and rotation come
/// from the effective supported glibc configuration. Unsupported settings use
/// the OS address resolver and reject raw HTTPS queries before opening sockets.
/// Fixed nameservers and callback resolvers are unaffected.
///
/// Delivered file, network and hostname changes invalidate both views and
/// their UDP clones. Callers must fence caches with the opaque token methods.
/// A changed generation fails the lookup without an automatic retry. Dropping
/// the final resolver joins its native watcher and can block the dropping thread.
/// Requires Linux and `https-records`.
///
/// # Errors
///
/// Returns runtime, worker-startup or configuration-watch errors.
#[cfg(target_os = "linux")]
pub async fn chromium_linux_resolvers() -> io::Result<(AddressResolver, HttpsRecordResolver)> {
    let owner = tokio::task::spawn_blocking(SystemDnsOwner::start)
        .await
        .map_err(io::Error::other)??;
    let view = SystemDnsView { owner, udp: None };
    Ok((
        AddressResolver::from_dns_backend(Arc::new(view.clone())),
        HttpsRecordResolver::from_system(view),
    ))
}

#[cfg(test)]
mod tests;
