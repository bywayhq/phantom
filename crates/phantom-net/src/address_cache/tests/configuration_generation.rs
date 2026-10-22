use super::*;
use crate::host_resolver::{
    DnsConfigurationToken, DnsLookup, ResolveFuture, configuration_changed,
};
use phantom_profile::UdpSettings;

#[derive(Debug)]
struct Generational {
    generation: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    gate: watch::Receiver<bool>,
    tokens: Arc<Mutex<Vec<DnsConfigurationToken>>>,
    terminal: Arc<std::sync::atomic::AtomicBool>,
}
impl Generational {
    fn new(gate: watch::Receiver<bool>) -> Arc<Self> {
        Arc::new(Self {
            generation: Arc::new(AtomicUsize::new(0)),
            calls: Arc::default(),
            gate,
            tokens: Arc::default(),
            terminal: Arc::default(),
        })
    }
    fn resolver(self: &Arc<Self>) -> AddressResolver {
        AddressResolver::from_dns_backend(self.clone())
    }
    fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}
impl DnsLookup for Generational {
    fn start(self: Arc<Self>, host: String) -> ResolveFuture {
        let token = self.configuration_token();
        Box::pin(async move {
            let token = token?;
            self.start_with_configuration(host, token).await
        })
    }
    fn start_with_configuration(
        self: Arc<Self>,
        _host: String,
        token: Option<DnsConfigurationToken>,
    ) -> ResolveFuture {
        let mut gate = self.gate.clone();
        Box::pin(async move {
            let token = token.ok_or_else(configuration_changed)?;
            token.require_current()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            gate.wait_for(|open| *open)
                .await
                .map_err(io::Error::other)?;
            token.require_current()?;
            Ok(Resolved::without_ttl([V4]))
        })
    }
    fn opened_with(&self, _: UdpSettings) -> Arc<dyn DnsLookup> {
        Arc::new(Self {
            generation: self.generation.clone(),
            calls: self.calls.clone(),
            gate: self.gate.clone(),
            tokens: self.tokens.clone(),
            terminal: self.terminal.clone(),
        })
    }
    fn socket_settings(&self) -> Option<UdpSettings> {
        None
    }
    fn configuration_token(&self) -> io::Result<Option<DnsConfigurationToken>> {
        if self.terminal.load(Ordering::SeqCst) {
            return Err(io::Error::other("synthetic terminal configuration error"));
        }
        let now = self.generation.load(Ordering::SeqCst);
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| io::Error::other("test token lock"))?;
        while tokens.len() <= now {
            let generation = self.generation.clone();
            let terminal = self.terminal.clone();
            let expected = tokens.len();
            tokens.push(DnsConfigurationToken::new(move || {
                if terminal.load(Ordering::SeqCst) {
                    return Err(io::Error::other("synthetic terminal configuration error"));
                }
                Ok(generation.load(Ordering::SeqCst) == expected)
            }));
        }
        Ok(Some(tokens[now].clone()))
    }
}

#[tokio::test]
async fn invalidation_rejects_ready_and_terminal_results_without_reusing_old_answers() -> TestResult
{
    let backend = Generational::new(watch::channel(true).1);
    let cache = AddressCache::with_resolver(long_lived(), backend.resolver());
    assert_eq!(
        cache.lookup("origin.phantom.test", 443).await?,
        [SocketAddr::new(V4, 443)]
    );
    assert!(
        cache
            .lookup_noting_cache("origin.phantom.test", 443)
            .await?
            .1
    );
    backend.invalidate();
    assert!(
        !cache
            .lookup_noting_cache("origin.phantom.test", 443)
            .await?
            .1
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    backend.terminal.store(true, Ordering::SeqCst);
    assert!(cache.lookup("origin.phantom.test", 443).await.is_err());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn old_pending_work_stays_counted_and_cannot_remove_or_publish_a_new_generation() -> TestResult
{
    tokio::time::timeout(Duration::from_secs(5), async {
        let (open, gate) = watch::channel(false);
        let backend = Generational::new(gate);
        let cache = AddressCache::with_resolver(
            settings(2, Duration::from_secs(600), None),
            backend.resolver(),
        );
        let old = cache.cached_or_pending("origin.phantom.test".into())?;
        while backend.calls.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
        backend.invalidate();
        let new = cache.cached_or_pending("origin.phantom.test".into())?;
        while backend.calls.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(cache.lock().shared_resolutions, 2);
        assert_eq!(cache.lock().pending.len(), 1);
        open.send(true)?;
        assert!(cache.consume_answer(old, 443).await.is_err());
        assert_eq!(
            cache.consume_answer(new, 443).await?.0,
            [SocketAddr::new(V4, 443)]
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.lock().shared_resolutions, 0);
        Ok::<_, Box<dyn Error>>(())
    })
    .await?
}

#[tokio::test]
async fn repeated_invalidation_preserves_shared_bound_and_explicit_clear_fences() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (open, gate) = watch::channel(false);
        let backend = Generational::new(gate);
        let cache = AddressCache::with_resolver(
            settings(1, Duration::from_secs(600), None),
            backend.resolver(),
        );
        let old = cache.cached_or_pending("origin.phantom.test".into())?;
        while backend.calls.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
        for _ in 0..3 {
            backend.invalidate();
            let next = cache.cached_or_pending("origin.phantom.test".into())?;
            assert!(matches!(next, Answer::Inline { .. }));
            drop(next);
            assert_eq!(cache.lock().shared_resolutions, 1);
        }
        cache.clear();
        open.send(true)?;
        assert!(cache.consume_answer(old, 443).await.is_err());
        assert_eq!(cache.lock().shared_resolutions, 0);
        assert!(cache.is_empty());
        Ok::<_, Box<dyn Error>>(())
    })
    .await?
}

#[test]
fn udp_views_share_generation_but_independent_owners_do_not() -> TestResult {
    let owner = Generational::new(watch::channel(true).1);
    let view = owner.resolver();
    let changed_udp = view.clone().with_udp_settings(UdpSettings {
        port_randomization: true,
    });
    assert_eq!(
        view.configuration_token()?,
        changed_udp.configuration_token()?
    );
    assert_ne!(
        view.configuration_token()?,
        Generational::new(watch::channel(true).1)
            .resolver()
            .configuration_token()?
    );
    let token = view.configuration_token()?.ok_or("token missing")?;
    owner.invalidate();
    assert!(!token.is_current()?);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn configuration_change_rejects_a_grace_renewal_and_starts_current_work() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (open, gate) = watch::channel(true);
        let backend = Generational::new(gate);
        let mut config = long_lived();
        config.stale_grace = Duration::from_secs(600);
        let cache = AddressCache::with_resolver(config, backend.resolver());
        cache.lookup("origin.phantom.test", 443).await?;
        open.send(false)?;
        cache
            .lock()
            .entries
            .get_mut("origin.phantom.test")
            .ok_or("missing entry")?
            .expires_at = Some(std::time::Instant::now());
        assert!(
            cache
                .lookup_noting_cache("origin.phantom.test", 443)
                .await?
                .1
        );
        while backend.calls.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
        let key = (
            Box::from("origin.phantom.test"),
            Some(tokio::runtime::Handle::current().id()),
        );
        let old = Answer::Wait(
            cache
                .lock()
                .pending
                .get(&key)
                .cloned()
                .ok_or("old renewal")?,
        );
        backend.invalidate();
        let new = cache.cached_or_pending("origin.phantom.test".into())?;
        assert!(
            matches!(new, Answer::Wait(_)),
            "old grace crossed configuration generations"
        );
        while backend.calls.load(Ordering::SeqCst) != 3 {
            tokio::task::yield_now().await;
        }
        open.send(true)?;
        assert!(cache.consume_answer(old, 443).await.is_err());
        cache.consume_answer(new, 443).await?;
        assert_eq!(
            cache.lookup("origin.phantom.test", 443).await?,
            [SocketAddr::new(V4, 443)]
        );
        assert_eq!(cache.lock().shared_resolutions, 0);
        assert_eq!(backend.calls.load(Ordering::SeqCst), 3);
        Ok::<_, Box<dyn Error>>(())
    })
    .await?
}
