//! Reusable native clients and environment ownership.

use std::sync::{
    Arc, Mutex, PoisonError, Weak,
    atomic::{AtomicBool, Ordering},
};

use napi::Result;
use phantom::{Client, HttpProxy, Route, SessionSharing, Socks5Proxy};
use tokio::sync::Semaphore;

use crate::{error::failure, ffi::ClientOptions, profile::ProfileState, response::Exchange};

const MAXIMUM_CLIENTS_PER_ENV: usize = 128;

#[derive(Debug, Default)]
pub(crate) struct Environment {
    closed: AtomicBool,
    clients: Mutex<Vec<Weak<ClientState>>>,
}

impl Environment {
    pub(crate) fn register(&self, client: &Arc<ClientState>) -> Result<()> {
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        if self.closed.load(Ordering::Acquire) {
            return Err(failure("ClientClosed", "Node environment is closed"));
        }
        clients.retain(|client| {
            client
                .upgrade()
                .is_some_and(|client| !client.is_closed() || !client.is_quiescent())
        });
        if clients.len() >= MAXIMUM_CLIENTS_PER_ENV {
            return Err(failure(
                "Capacity",
                "too many clients in this Node environment",
            ));
        }
        clients.push(Arc::downgrade(client));
        Ok(())
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let clients = {
            let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *clients)
        };
        for client in clients.into_iter().filter_map(|client| client.upgrade()) {
            client.close();
        }
    }
}

#[derive(Debug)]
pub(crate) struct ClientState {
    pub(crate) core: Client,
    pub(crate) profile: Arc<ProfileState>,
    pub(crate) admission: Arc<Semaphore>,
    pub(crate) timeouts: phantom::RequestTimeouts,
    maximum: usize,
    shutdown_pending: AtomicBool,
    closed: AtomicBool,
    exchanges: Mutex<Vec<Weak<Exchange>>>,
}

impl ClientState {
    pub(crate) fn fork(
        &self,
        sharing: SessionSharing,
        environment: &Environment,
    ) -> Result<Arc<Self>> {
        let state = Arc::new(Self {
            core: self.core.fork(sharing),
            profile: Arc::clone(&self.profile),
            admission: Arc::new(Semaphore::new(self.maximum)),
            timeouts: self.timeouts,
            maximum: self.maximum,
            shutdown_pending: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            exchanges: Mutex::new(Vec::new()),
        });
        environment.register(&state)?;
        Ok(state)
    }

    pub(crate) fn build(
        options: ClientOptions,
        profile: Arc<ProfileState>,
        roots: Vec<Vec<u8>>,
        proxy_roots: Vec<Vec<u8>>,
        environment: &Environment,
    ) -> Result<Arc<Self>> {
        let maximum = options.maximum_active_requests.unwrap_or(32);
        if !(1..=1024).contains(&maximum) {
            return Err(failure(
                "InvalidConfiguration",
                "maximumActiveRequests must be 1..1024",
            ));
        }
        // Every request selects its context explicitly, including attached templates.
        let settings = profile.settings.clone().without_request_template();
        let mut builder = Client::builder(settings).route(route(
            &options.route,
            options.proxy.as_deref(),
            options.proxy_username.as_deref(),
            options.proxy_password.as_deref(),
        )?);
        if let Some(policy) = options.redirect_policy {
            builder = builder.redirect_policy(policy.policy()?);
        }
        if options.cookies.unwrap_or(false) {
            builder = builder.cookies();
        }
        for root in roots {
            builder = builder.add_root_certificate_der(root);
        }
        for root in proxy_roots {
            builder = builder.add_proxy_root_certificate_der(root);
        }
        if let Some(url) = options.base_url {
            builder = builder.base_url(&url).map_err(|_| {
                failure(
                    "InvalidConfiguration",
                    "baseUrl must be a supported absolute HTTP URL",
                )
            })?;
        }
        let timeouts = options
            .timeouts
            .unwrap_or_default()
            .overrides()?
            .resolve(phantom::RequestTimeouts::new());
        builder = builder.request_timeouts(timeouts);
        let core = builder
            .build()
            .map_err(|error| failure(&format!("{:?}", error.kind()), &error.to_string()))?;
        let state = Arc::new(Self {
            core,
            profile,
            admission: Arc::new(Semaphore::new(maximum as usize)),
            timeouts,
            maximum: maximum as usize,
            shutdown_pending: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            exchanges: Mutex::new(Vec::new()),
        });
        environment.register(&state)?;
        Ok(state)
    }

    pub(crate) fn register(&self, exchange: &Arc<Exchange>) -> Result<()> {
        let mut exchanges = self
            .exchanges
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.is_closed() {
            return Err(failure("ClientClosed", "client is closed"));
        }
        exchanges.retain(|entry| entry.upgrade().is_some_and(|entry| entry.is_active()));
        exchanges.push(Arc::downgrade(exchange));
        Ok(())
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn check_open(&self) -> Result<()> {
        if self.is_closed() {
            Err(failure("ClientClosed", "client is closed"))
        } else {
            Ok(())
        }
    }

    fn is_quiescent(&self) -> bool {
        self.admission.available_permits() == self.maximum
            && !self.shutdown_pending.load(Ordering::Acquire)
    }

    pub(crate) fn shutdown(self: &Arc<Self>) -> Result<Shutdown> {
        self.shutdown_pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| failure("ShutdownInProgress", "client shutdown is already pending"))?;
        Ok(Shutdown(Arc::clone(self)))
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.admission.close();
        let exchanges = {
            let mut exchanges = self
                .exchanges
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *exchanges)
        };
        for exchange in exchanges.into_iter().filter_map(|entry| entry.upgrade()) {
            exchange.cancel();
        }
    }
}

pub(crate) fn route(
    kind: &str,
    proxy: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Route> {
    if username.is_some() != password.is_some() || (kind == "direct" && username.is_some()) {
        return Err(failure(
            "InvalidProxy",
            "proxy credentials require a proxy and both username and password",
        ));
    }
    match (kind, proxy) {
        ("direct", None) => Ok(Route::direct()),
        ("proxy", Some(uri)) if uri.starts_with("http://") || uri.starts_with("https://") => {
            let mut proxy = HttpProxy::new(uri)
                .map_err(|_| failure("InvalidProxy", "invalid HTTP proxy configuration"))?;
            if let (Some(username), Some(password)) = (username, password) {
                proxy = proxy
                    .with_basic_auth(username, password)
                    .map_err(|_| failure("InvalidProxy", "invalid HTTP proxy credentials"))?;
            }
            Ok(Route::http_proxy(proxy))
        }
        ("proxy", Some(uri)) if uri.starts_with("socks5://") || uri.starts_with("socks5h://") => {
            let mut proxy = Socks5Proxy::new(uri)
                .map_err(|_| failure("InvalidProxy", "invalid SOCKS5 proxy configuration"))?;
            if let (Some(username), Some(password)) = (username, password) {
                proxy = proxy
                    .with_username_password(username, password)
                    .map_err(|_| failure("InvalidProxy", "invalid SOCKS5 proxy credentials"))?;
            }
            Ok(Route::socks5(proxy))
        }
        _ => Err(failure(
            "InvalidProxy",
            "choose direct without a proxy, or an explicit HTTP/SOCKS5 proxy URI",
        )),
    }
}

impl Drop for ClientState {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) struct Shutdown(Arc<ClientState>);

impl Drop for Shutdown {
    fn drop(&mut self) {
        self.0.shutdown_pending.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::Pending;

    #[test]
    fn closed_clients_stay_registered_until_owned_setup_and_shutdown_settle() -> Result<()> {
        let identifier = if cfg!(windows) {
            "chrome/154.0.8037.97/windows-11-26200/r1"
        } else if cfg!(target_os = "macos") {
            "chrome/154.0.8037.95/macos-15.5-arm64/r1"
        } else {
            "chrome/154.0.8037.57/android-17-pixel7-emulator/r1"
        };
        let profile = ProfileState::catalog(identifier, None)?;
        let settings = profile.settings.clone();
        let core = Client::builder(settings)
            .route(Route::direct())
            .build()
            .map_err(|_| failure("TestProfile", "client could not be built"))?;
        let state = || {
            Arc::new(ClientState {
                core: core.clone(),
                profile: Arc::clone(&profile),
                admission: Arc::new(Semaphore::new(1)),
                timeouts: phantom::RequestTimeouts::new(),
                maximum: 1,
                shutdown_pending: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                exchanges: Mutex::new(Vec::new()),
            })
        };
        let environment = Environment::default();
        let mut pending = Vec::new();
        for _ in 0..MAXIMUM_CLIENTS_PER_ENV {
            let client = state();
            let exchange = Exchange::new();
            let permit = Arc::clone(&client.admission)
                .try_acquire_owned()
                .map_err(|_| failure("TestAdmission", "admission failed"))?;
            exchange.claim(permit, None)?;
            let guard = Pending::new(Arc::clone(&exchange), Arc::clone(&client));
            client.register(&exchange)?;
            environment.register(&client)?;
            client.close();
            pending.push(guard);
        }
        let replacement = state();
        assert!(environment.register(&replacement).is_err());
        pending.clear();
        environment.register(&replacement)?;
        let shutdown = replacement.shutdown()?;
        replacement.close();
        assert!(!replacement.is_quiescent());
        assert!(replacement.shutdown().is_err());
        drop(shutdown);
        assert!(replacement.is_quiescent());
        Ok(())
    }
}
