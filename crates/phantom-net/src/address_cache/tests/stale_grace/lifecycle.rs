use super::*;

#[tokio::test(flavor = "current_thread")]
async fn clear_prevents_old_renewal_from_removing_or_overwriting_new_pending_work() -> TestResult {
    let (cache, _, replies) = scripted(grace_settings(3), 3);
    let mut replies = replies.into_iter();
    respond(
        replies.next().ok_or("initial reply")?,
        Ok(Resolved::without_ttl([V4])),
    )?;
    cache.lookup(HOST, 443).await?;
    enter_grace(&cache)?;
    assert!(cache.lookup_noting_cache(HOST, 443).await?.1);
    let mut old = pending(&cache)?;
    cache.clear();
    let mut new = cache.cached_or_pending(HOST.into())?;
    assert_eq!(cache.lock().shared_resolutions, 2);
    respond(
        replies.next().ok_or("old reply")?,
        Ok(Resolved::without_ttl([V6])),
    )?;
    wait_until_published(&mut old).await?;
    assert_eq!(
        cache.consume_answer(old, 443).await?.0,
        [SocketAddr::new(V6, 443)]
    );
    assert!(cache.is_empty());
    assert_eq!(cache.lock().pending.len(), 1);
    assert_eq!(cache.lock().shared_resolutions, 1);
    respond(
        replies.next().ok_or("new reply")?,
        Ok(Resolved::without_ttl([V4_OTHER])),
    )?;
    wait_until_published(&mut new).await?;
    cache.consume_answer(new, 443).await?;
    assert_eq!(
        cache.lookup(HOST, 443).await?,
        [SocketAddr::new(V4_OTHER, 443)]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_an_expired_waiter_does_not_cancel_its_background_renewal() -> TestResult {
    let (cache, calls, replies) = scripted(grace_settings(3), 2);
    let mut replies = replies.into_iter();
    respond(
        replies.next().ok_or("initial reply")?,
        Ok(Resolved::without_ttl([V4])),
    )?;
    cache.lookup(HOST, 443).await?;
    enter_grace(&cache)?;
    assert!(cache.lookup_noting_cache(HOST, 443).await?.1);
    let mut renewal = pending(&cache)?;
    expire(&cache)?;
    let mut cancelled = Box::pin(cache.lookup(HOST, 443));
    assert!(
        poll_fn(|cx| Poll::Ready(cancelled.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(cancelled);
    respond(
        replies.next().ok_or("renewal reply")?,
        Ok(Resolved::without_ttl([V6])),
    )?;
    wait_until_published(&mut renewal).await?;
    cache.consume_answer(renewal, 443).await?;
    assert_eq!(
        cache.lookup_noting_cache(HOST, 8443).await?,
        (vec![SocketAddr::new(V6, 8443)], true)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(cache.lock().shared_resolutions, 0);
    Ok(())
}

#[test]
fn another_runtime_renews_independently_and_dropping_the_old_runtime_releases_its_slot()
-> TestResult {
    let (cache, calls, replies) = scripted(grace_settings(3), 3);
    let mut replies = replies.into_iter();
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    respond(
        replies.next().ok_or("initial reply")?,
        Ok(Resolved::without_ttl([V4])),
    )?;
    first.block_on(cache.lookup(HOST, 443))?;
    enter_grace(&cache)?;
    first.block_on(async {
        assert!(cache.lookup_noting_cache(HOST, 443).await?.1);
        Ok::<_, Box<dyn Error>>(())
    })?;
    // Keep this runtime alive without driving its pending renewal.
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut second_renewal = second.block_on(async {
        assert!(cache.lookup_noting_cache(HOST, 443).await?.1);
        pending(&cache)
    })?;
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(cache.lock().shared_resolutions, 2);
    drop(first);
    assert_eq!(cache.lock().shared_resolutions, 1);
    drop(replies.next().ok_or("abandoned reply")?);
    respond(
        replies.next().ok_or("current reply")?,
        Ok(Resolved::without_ttl([V6])),
    )?;
    second.block_on(async {
        wait_until_published(&mut second_renewal).await?;
        cache.consume_answer(second_renewal, 443).await?;
        assert_eq!(cache.lookup(HOST, 443).await?, [SocketAddr::new(V6, 443)]);
        Ok::<_, Box<dyn Error>>(())
    })?;
    assert_eq!(cache.lock().shared_resolutions, 0);
    Ok(())
}
