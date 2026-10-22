use super::*;

#[test]
fn removal_detaches_all_runtime_keys_and_old_runtime_drop_preserves_the_new_identity() -> TestResult
{
    let (cache, replies) = scripted(long_lived(), false, 3);
    let mut replies = replies.into_iter();
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let old_first = first.block_on(async { cache.cached_or_pending(HOST.into()) })?;
    let old_second = second.block_on(async { cache.cached_or_pending(HOST.into()) })?;
    assert_eq!(cache.lock().pending.len(), 2);
    assert_eq!(cache.lock().publications.len(), 1);
    cache.remove(HOST);
    let fresh = second.block_on(async { cache.cached_or_pending(HOST.into()) })?;
    assert_eq!(cache.lock().pending.len(), 1);
    drop(first);
    drop(replies.next().ok_or("missing cancelled runtime reply")?);
    second.block_on(async {
        assert!(
            tokio::time::timeout(Duration::from_secs(5), cache.consume_answer(old_first, 443))
                .await?
                .is_err()
        );
        assert_eq!(cache.lock().pending.len(), 1);
        assert_eq!(cache.lock().publications.len(), 1);
        let old_reply = replies.next().ok_or("missing old reply")?;
        let fresh_reply = replies.next().ok_or("missing fresh reply")?;
        finish(&cache, fresh, fresh_reply, V4_OTHER).await?;
        finish(&cache, old_second, old_reply, V4).await?;
        assert_eq!(
            cache.lookup_noting_cache(HOST, 443).await?,
            (vec![SocketAddr::new(V4_OTHER, 443)], true)
        );
        retired(&cache).await
    })
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_inline_identity_cannot_remove_a_newer_same_host_publication() -> TestResult {
    let (cache, replies) = scripted(settings(1, Duration::from_secs(60), None), false, 4);
    let mut replies = replies.into_iter();
    let blocker = cache.cached_or_pending(OTHER.into())?;
    let old = cache.cached_or_pending(HOST.into())?;
    assert!(matches!(old, Answer::Inline { .. }));
    let mut cancelled = Box::pin(cache.consume_answer(old, 443));
    assert!(
        poll_fn(|cx| Poll::Ready(cancelled.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    cache.remove(HOST);
    let fresh = cache.cached_or_pending(HOST.into())?;
    let sibling = cache.cached_or_pending(HOST.into())?;
    drop(cancelled);
    assert_eq!(cache.lock().publications.len(), 2);
    let blocker_reply = replies.next().ok_or("missing blocker reply")?;
    drop(replies.next().ok_or("missing cancelled reply")?);
    let fresh_reply = replies.next().ok_or("missing fresh reply")?;
    drop(replies.next().ok_or("missing sibling reply")?);
    drop(sibling);
    assert_eq!(
        cache.lock().publications.len(),
        2,
        "one same-host caller lost the other's authority"
    );
    finish(&cache, fresh, fresh_reply, V4_OTHER).await?;
    assert_eq!(cache.lock().publications.len(), 1);
    finish(&cache, blocker, blocker_reply, V6).await?;
    retired(&cache).await?;
    Ok(())
}

#[test]
fn concurrent_last_publication_owners_prune_the_weak_index() -> TestResult {
    let (cache, _) = scripted(long_lived(), false, 0);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let (mut first, mut second) = {
        let mut state = cache.lock();
        (
            crate::address_cache::PublicationGuard::new(&cache, &mut state, HOST.into()),
            crate::address_cache::PublicationGuard::new(&cache, &mut state, HOST.into()),
        )
    };
    first.drop_barrier = Some(barrier.clone());
    second.drop_barrier = Some(barrier);
    std::thread::scope(|scope| -> TestResult {
        let first = scope.spawn(move || drop(first));
        let second = scope.spawn(move || drop(second));
        first
            .join()
            .map_err(|_| "first publication owner panicked")?;
        second
            .join()
            .map_err(|_| "second publication owner panicked")?;
        Ok(())
    })?;
    assert!(cache.lock().publications.is_empty());
    Ok(())
}
