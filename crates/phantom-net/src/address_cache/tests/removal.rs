use super::*;
use std::{collections::VecDeque, time::Instant};
use tokio::sync::oneshot;

const HOST: &str = "origin.phantom.test";
const OTHER: &str = "other.phantom.test";
type Reply = oneshot::Sender<io::Result<Resolved>>;

mod runtimes;

fn scripted(config: DnsCacheSettings, blocking: bool, count: usize) -> (AddressCache, Vec<Reply>) {
    let (replies, responses): (Vec<_>, VecDeque<_>) =
        (0..count).map(|_| oneshot::channel()).unzip();
    let responses = Arc::new(Mutex::new(responses));
    let lookup = move |_: Box<str>| -> crate::address_cache::ResolverFuture {
        let response = responses
            .lock()
            .map_err(|_| io::Error::other("scripted response lock poisoned"))
            .and_then(|mut queue| {
                queue
                    .pop_front()
                    .ok_or_else(|| io::Error::other("unexpected lookup"))
            });
        Box::pin(async move { response?.await.map_err(io::Error::other)? })
    };
    let cache = if blocking {
        AddressCache::with_blocking_lookup(config, lookup)
    } else {
        AddressCache::with_resolver(
            config,
            AddressResolver::from_resolved_fn(move |host| lookup(host.into())),
        )
    };
    (cache, replies)
}

fn reply(sender: Reply, address: IpAddr) -> TestResult {
    sender
        .send(Ok(Resolved::without_ttl([address])))
        .map_err(|_| "lookup no longer owns its reply".into())
}

async fn finish(
    cache: &AddressCache,
    answer: Answer,
    sender: Reply,
    address: IpAddr,
) -> TestResult {
    reply(sender, address)?;
    let (actual, stored) =
        tokio::time::timeout(Duration::from_secs(5), cache.consume_answer(answer, 443)).await??;
    assert_eq!(actual, [SocketAddr::new(address, 443)]);
    assert!(!stored);
    Ok(())
}

async fn retired(cache: &AddressCache) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let retired = {
                let state = cache.lock();
                state.shared_resolutions == 0 && state.publications.is_empty()
            };
            if retired {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(cache.lock().publications.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn removal_forgets_case_insensitive_answers_failures_and_failed_address_history() -> TestResult
{
    let mut config = long_lived();
    config.address_failure_policy = phantom_profile::DnsAddressFailurePolicy::Record {
        max_unusable_addresses: NonZeroUsize::MIN,
    };
    let cache = AddressCache::with_resolver(
        config,
        AddressResolver::from_fn(|_| async { Ok(vec![V4, V4_OTHER]) }),
    );
    let old = cache.lookup_tcp_noting_cache(HOST, 443).await?.0;
    let held = old.cursor().next().ok_or("missing first address")?;
    held.failed_connect()?;
    assert_eq!(
        cache
            .lookup_tcp_noting_cache(HOST, 443)
            .await?
            .0
            .cursor()
            .next()
            .ok_or("missing next address")?
            .address()
            .ip(),
        V4_OTHER
    );
    cache.lookup(OTHER, 443).await?;
    cache.remove("ORIGIN.Phantom.TEST");
    assert_eq!(cache.len(), 1);
    assert!(cache.lookup_noting_cache(OTHER, 443).await?.1);
    let (fresh, stored) = cache.lookup_tcp_noting_cache(HOST, 443).await?;
    assert!(!stored);
    assert_eq!(
        fresh
            .cursor()
            .next()
            .ok_or("missing fresh address")?
            .address()
            .ip(),
        V4
    );
    held.failed_connect()?;
    assert_eq!(
        cache
            .lookup_tcp_noting_cache(HOST, 443)
            .await?
            .0
            .cursor()
            .next()
            .ok_or("missing current address")?
            .address()
            .ip(),
        V4
    );

    let recorder = Recorder::open();
    let failed = recorder.cache(
        settings(2, Duration::from_secs(60), Some(Duration::from_secs(60))),
        not_found,
    );
    assert!(failed.lookup(HOST, 443).await.is_err());
    assert!(failed.lookup(HOST, 443).await.is_err());
    assert_eq!(recorder.calls(), 1);
    failed.remove(HOST);
    assert!(failed.lookup(HOST, 443).await.is_err());
    assert_eq!(recorder.calls(), 2);
    Ok(())
}

async fn shared_isolation(blocking: bool) -> TestResult {
    for old_first in [true, false] {
        let (cache, replies) = scripted(long_lived(), blocking, 3);
        let mut replies = replies.into_iter();
        let old = cache.cached_or_pending(HOST.into())?;
        let joined = cache.cached_or_pending(HOST.into())?;
        let other = cache.cached_or_pending(OTHER.into())?;
        cache.remove("ORIGIN.PHANTOM.TEST");
        let fresh = cache.cached_or_pending(HOST.into())?;
        let old_reply = replies.next().ok_or("missing old reply")?;
        let other_reply = replies.next().ok_or("missing other reply")?;
        let fresh_reply = replies.next().ok_or("missing fresh reply")?;
        finish(&cache, other, other_reply, V6).await?;
        assert!(cache.lookup_noting_cache(OTHER, 8443).await?.1);
        if old_first {
            finish(&cache, old, old_reply, V4).await?;
            assert!(!cache.lock().entries.contains_key(HOST));
            assert_eq!(
                cache.lock().pending.len(),
                1,
                "old completion removed fresh pending work"
            );
            finish(&cache, fresh, fresh_reply, V4_OTHER).await?;
        } else {
            finish(&cache, fresh, fresh_reply, V4_OTHER).await?;
            finish(&cache, old, old_reply, V4).await?;
        }
        assert_eq!(
            cache.consume_answer(joined, 443).await?.0,
            [SocketAddr::new(V4, 443)]
        );
        assert_eq!(
            cache.lookup_noting_cache(HOST, 443).await?,
            (vec![SocketAddr::new(V4_OTHER, 443)], true)
        );
        assert!(cache.lookup_noting_cache(OTHER, 443).await?.1);
        retired(&cache).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn removal_detaches_shared_async_work_without_changing_other_host_publication() -> TestResult
{
    shared_isolation(false).await
}

#[tokio::test(flavor = "current_thread")]
async fn removal_detaches_blocking_work_without_changing_other_host_publication() -> TestResult {
    shared_isolation(true).await
}

#[tokio::test(flavor = "current_thread")]
async fn overflow_inline_and_blocking_publications_cannot_revive_a_removed_answer() -> TestResult {
    for blocking in [false, true] {
        let (cache, replies) = scripted(settings(1, Duration::from_secs(60), None), blocking, 3);
        let mut replies = replies.into_iter();
        let blocker = cache.cached_or_pending(OTHER.into())?;
        let old = cache.cached_or_pending(HOST.into())?;
        if !blocking {
            assert!(matches!(old, Answer::Inline { .. }));
        }
        cache.remove(HOST);
        let fresh = cache.cached_or_pending(HOST.into())?;
        assert_eq!(cache.lock().shared_resolutions, 1);
        let blocker_reply = replies.next().ok_or("missing blocker reply")?;
        let old_reply = replies.next().ok_or("missing old reply")?;
        let fresh_reply = replies.next().ok_or("missing fresh reply")?;
        finish(&cache, fresh, fresh_reply, V4_OTHER).await?;
        finish(&cache, old, old_reply, V4).await?;
        assert_eq!(
            cache.lookup_noting_cache(HOST, 443).await?,
            (vec![SocketAddr::new(V4_OTHER, 443)], true)
        );
        finish(&cache, blocker, blocker_reply, V6).await?;
        retired(&cache).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn removal_detaches_grace_renewal_and_returns_old_answer_only_to_existing_waiters()
-> TestResult {
    let mut config = long_lived();
    config.stale_grace = Duration::from_secs(600);
    let (cache, replies) = scripted(config, false, 3);
    let mut replies = replies.into_iter();
    let initial = cache.cached_or_pending(HOST.into())?;
    finish(&cache, initial, replies.next().ok_or("initial reply")?, V4).await?;
    cache
        .lock()
        .entries
        .get_mut(HOST)
        .ok_or("missing entry")?
        .expires_at = Some(Instant::now());
    assert!(cache.lookup_noting_cache(HOST, 443).await?.1);
    let old = Answer::Wait(
        cache
            .lock()
            .pending
            .values()
            .next()
            .cloned()
            .ok_or("missing renewal")?,
    );
    cache.remove(HOST);
    let fresh = cache.cached_or_pending(HOST.into())?;
    finish(&cache, old, replies.next().ok_or("renewal reply")?, V6).await?;
    assert!(!cache.lock().entries.contains_key(HOST));
    finish(
        &cache,
        fresh,
        replies.next().ok_or("fresh reply")?,
        V4_OTHER,
    )
    .await?;
    assert_eq!(
        cache.lookup_noting_cache(HOST, 443).await?,
        (vec![SocketAddr::new(V4_OTHER, 443)], true)
    );
    retired(&cache).await?;
    Ok(())
}
