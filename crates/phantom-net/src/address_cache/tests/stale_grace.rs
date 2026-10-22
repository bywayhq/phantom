use std::{collections::VecDeque, time::Instant};

use super::*;
use crate::address_cache::Outcome;
use tokio::sync::oneshot;

mod lifecycle;
mod lifetimes;

const HOST: &str = "origin.phantom.test";
const TTL: Duration = Duration::from_secs(60);
const GRACE: Duration = Duration::from_secs(600);
type Reply = oneshot::Sender<io::Result<Resolved>>;

fn grace_settings(capacity: usize) -> DnsCacheSettings {
    let mut config = settings(capacity, TTL, Some(TTL));
    config.stale_grace = GRACE;
    config
}

fn scripted(
    config: DnsCacheSettings,
    count: usize,
) -> (AddressCache, Arc<AtomicUsize>, Vec<Reply>) {
    let mut replies = Vec::new();
    let mut responses = VecDeque::new();
    for _ in 0..count {
        let (reply, response) = oneshot::channel();
        replies.push(reply);
        responses.push_back(response);
    }
    let responses = Arc::new(Mutex::new(responses));
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let resolver = AddressResolver::from_resolved_fn(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        let response = responses
            .lock()
            .map_err(|_| io::Error::other("scripted response lock poisoned"))
            .and_then(|mut queue| {
                queue
                    .pop_front()
                    .ok_or_else(|| io::Error::other("unexpected extra lookup"))
            });
        async move { response?.await.map_err(io::Error::other)? }
    });
    (
        AddressCache::with_resolver(config, resolver),
        calls,
        replies,
    )
}

fn respond(reply: Reply, result: io::Result<Resolved>) -> TestResult {
    reply.send(result).map_err(|_| "lookup was retired".into())
}

fn enter_grace(cache: &AddressCache) -> TestResult {
    let now = Instant::now();
    let mut state = cache.lock();
    let entry = state
        .entries
        .get_mut(HOST)
        .ok_or("missing positive entry")?;
    entry.expires_at = Some(now);
    entry.stale_until = now.checked_add(GRACE);
    Ok(())
}

fn expire(cache: &AddressCache) -> TestResult {
    let mut state = cache.lock();
    let entry = state
        .entries
        .get_mut(HOST)
        .ok_or("missing positive entry")?;
    let now = Instant::now();
    entry.expires_at = Some(now);
    entry.stale_until = entry.stale_until.map(|_| now);
    Ok(())
}

fn pending(cache: &AddressCache) -> TestResult<Answer> {
    let key = (
        Box::from(HOST),
        Some(tokio::runtime::Handle::current().id()),
    );
    cache
        .lock()
        .pending
        .get(&key)
        .cloned()
        .map(Answer::Wait)
        .ok_or_else(|| "missing pending renewal".into())
}

#[tokio::test(flavor = "current_thread")]
async fn grace_hits_return_immediately_share_one_renewal_and_expired_callers_wait() -> TestResult {
    let (cache, calls, replies) = scripted(grace_settings(4), 2);
    let mut replies = replies.into_iter();
    respond(
        replies.next().ok_or("initial reply")?,
        Ok(Resolved::without_ttl([V4])),
    )?;
    cache.lookup(HOST, 443).await?;
    assert!(cache.lookup_noting_cache(HOST, 443).await?.1);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "fresh hits do not renew");
    enter_grace(&cache)?;

    for _ in 0..8 {
        let selected = cache.cached_or_pending(HOST.into())?;
        assert!(matches!(selected, Answer::Stored(_)));
        assert_eq!(
            cache.consume_answer(selected, 8443).await?,
            (vec![SocketAddr::new(V4, 8443)], true)
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(cache.lock().shared_resolutions, 1);
    expire(&cache)?;
    let mut waiter = cache.cached_or_pending(HOST.into())?;
    assert!(matches!(waiter, Answer::Wait(_)));
    let mut lookup = Box::pin(cache.lookup(HOST, 443));
    assert!(
        poll_fn(|cx| Poll::Ready(lookup.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(lookup);
    respond(
        replies.next().ok_or("renewal reply")?,
        Ok(Resolved::without_ttl([V6, V4_OTHER])),
    )?;
    wait_until_published(&mut waiter).await?;
    assert_eq!(
        cache.consume_answer(waiter, 443).await?.0,
        [SocketAddr::new(V6, 443), SocketAddr::new(V4_OTHER, 443)]
    );
    assert!(cache.lock().entries[HOST].is_fresh(Instant::now()));
    assert_eq!(cache.lock().shared_resolutions, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn renewal_preserves_failed_ip_history_and_retires_old_selection_witnesses() -> TestResult {
    let mut config = grace_settings(4);
    config.address_failure_policy = phantom_profile::DnsAddressFailurePolicy::Record {
        max_unusable_addresses: NonZeroUsize::new(4).ok_or("capacity")?,
    };
    for replacement in [[V4, V4_OTHER], [V4_OTHER, V4]] {
        let (cache, _, replies) = scripted(config, 2);
        let mut replies = replies.into_iter();
        respond(
            replies.next().ok_or("initial reply")?,
            Ok(Resolved::without_ttl([V4, V4_OTHER])),
        )?;
        let first = cache.lookup_tcp_noting_cache(HOST, 443).await?.0;
        first
            .cursor()
            .next()
            .ok_or("first address")?
            .failed_connect()?;
        let old = cache
            .lookup_tcp_noting_cache(HOST, 443)
            .await?
            .0
            .cursor()
            .next()
            .ok_or("second address")?;
        enter_grace(&cache)?;
        assert!(cache.lookup_tcp_noting_cache(HOST, 443).await?.1);
        let mut renewal = pending(&cache)?;
        respond(
            replies.next().ok_or("renewal reply")?,
            Ok(Resolved::without_ttl(replacement)),
        )?;
        wait_until_published(&mut renewal).await?;
        cache.consume_answer(renewal, 443).await?;
        old.failed_connect()?;
        let current = cache.lookup_tcp_noting_cache(HOST, 8443).await?.0;
        assert_eq!(
            current.cursor().next().ok_or("current address")?.address(),
            SocketAddr::new(V4_OTHER, 8443)
        );
        let state = cache.lock();
        let entry = state.entries.get(HOST).ok_or("renewed entry")?;
        assert!(entry.is_fresh(Instant::now()));
        assert_eq!(
            entry.stale_until,
            entry.expires_at.and_then(|fresh| fresh.checked_add(GRACE))
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_saturated_grace_hit_does_not_start_unshared_background_work() -> TestResult {
    let (cache, calls, replies) = scripted(grace_settings(1), 2);
    let mut replies = replies.into_iter();
    respond(
        replies.next().ok_or("initial reply")?,
        Ok(Resolved::without_ttl([V4])),
    )?;
    cache.lookup(HOST, 443).await?;
    enter_grace(&cache)?;
    let mut held = cache.cached_or_pending("held.phantom.test".into())?;
    for _ in 0..8 {
        let selected = cache.cached_or_pending(HOST.into())?;
        assert!(matches!(selected, Answer::Stored(_)));
        assert_eq!(
            cache.consume_answer(selected, 443).await?.0,
            [SocketAddr::new(V4, 443)]
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(cache.lock().shared_resolutions, 1);
    assert_eq!(cache.lock().pending.len(), 1);
    respond(
        replies.next().ok_or("held reply")?,
        Ok(Resolved::without_ttl([V6])),
    )?;
    wait_until_published(&mut held).await?;
    cache.consume_answer(held, 443).await?;
    assert_eq!(cache.lock().shared_resolutions, 0);
    assert_eq!(cache.len(), 1);
    Ok(())
}
