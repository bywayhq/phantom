use super::*;
use peer::lifecycle::{RecoveryGate, serve_cancelled_owner, serve_refreshed, serve_siblings};

const H2_TRANSPORTS: [Transport; 2] = [Transport::Http2, Transport::NegotiatedHttp2];

#[tokio::test]
async fn cancelling_the_h2_recovery_owner_wakes_its_waiter_without_redialing() -> TestResult<()> {
    for transport in H2_TRANSPORTS {
        let mut server = None;
        let result = bounded(async {
            let identity = origin_identity()?;
            let offers = Offers::default();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            let session = discovering_client(&identity, port)?;
            let acceptor = acceptor_for(&identity, &offers, H2_ALPN)?;
            peer::set_key(&acceptor, 1, &TEST_ECH_KEYS[0])?;
            let (closed, seed_closed) = oneshot::channel();
            let (arrived, recovery_arrived) = oneshot::channel();
            server = Some(ConnectionPeer::spawn(async move {
                serve_cancelled_owner(listener, acceptor, transport, closed, arrived).await
            }));
            let seed = format!("https://{ORIGIN_NAME}:{port}/seed");
            transport.request(&session, Method::GET, &seed)?.send().await?
                .into_body().collect().await?;
            seed_closed.await?;

            let budget = HttpAttemptBudget::new(3);
            let url = format!("https://{ORIGIN_NAME}:{port}/owner");
            let mut owner = Box::pin(transport.request(&session, Method::GET, &url)?
                .attempt_budget(budget.clone()).send());
            tokio::select! {
                biased;
                _ = &mut owner => return Err("recovery owner finished before its fresh handshake".into()),
                result = recovery_arrived => result?,
            }
            let url = format!("https://{ORIGIN_NAME}:{port}/waiter");
            let mut waiter = Box::pin(transport.request(&session, Method::GET, &url)?
                .attempt_budget(budget.clone()).send());
            let pending = poll_fn(|context| Poll::Ready(waiter.as_mut().poll(context).is_pending())).await;
            if !pending {
                return Err("H2 follower did not wait for the recovery owner".into());
            }
            drop(owner);

            let error = tokio::time::timeout(Duration::from_secs(2), waiter).await?
                .err().ok_or("cancelled ECH recovery unexpectedly succeeded")?;
            if error.kind() != RequestErrorKind::Tls || !has_ech_rejection(&error) {
                return Err("cancelled recovery lost the original authenticated ECH failure".into());
            }
            if budget.remaining() != 0 {
                return Err("owner and waiter did not share their HTTP allowance".into());
            }
            // A live client must not retain or replace the cancelled setup.
            join(&mut server).await?;
            drop(session);
            let observed = offers.take();
            if observed.len() != 2 || observed.first() != Some(&FRESH) {
                return Err("cancelled recovery authenticated an unexpected connection".into());
            }
            Ok(())
        }).await;
        finish(result, server).await?;
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_h2_waiters_and_streams_preserves_the_recovered_sibling() -> TestResult<()> {
    for transport in H2_TRANSPORTS {
        let mut server = None;
        let result = bounded(async {
            let identity = origin_identity()?;
            let offers = Offers::default();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            let session = discovering_client(&identity, port)?;
            let acceptor = acceptor_for(&identity, &offers, H2_ALPN)?;
            peer::set_key(&acceptor, 1, &TEST_ECH_KEYS[0])?;
            let (closed, seed_closed) = oneshot::channel();
            let (arrived, recovery_arrived) = oneshot::channel();
            let (release, released) = oneshot::channel();
            let (reset, reset_observed) = oneshot::channel();
            server = Some(ConnectionPeer::spawn(async move {
                serve_siblings(listener, acceptor, transport, closed,
                    RecoveryGate { arrived, released }, reset).await
            }));
            let seed = format!("https://{ORIGIN_NAME}:{port}/seed");
            transport.request(&session, Method::GET, &seed)?.send().await?
                .into_body().collect().await?;
            seed_closed.await?;

            let url = format!("https://{ORIGIN_NAME}:{port}/owner");
            let mut owner = Box::pin(transport.request(&session, Method::GET, &url)?.send());
            tokio::select! {
                biased;
                _ = &mut owner => return Err("recovery owner finished before its fresh handshake".into()),
                result = recovery_arrived => result?,
            }
            let url = format!("https://{ORIGIN_NAME}:{port}/cancel-waiter");
            let mut waiter = Box::pin(transport.request(&session, Method::GET, &url)?.send());
            let pending = poll_fn(|context| Poll::Ready(waiter.as_mut().poll(context).is_pending())).await;
            if !pending {
                return Err("H2 follower did not wait for the recovery owner".into());
            }
            drop(waiter);
            release.send(()).map_err(|_| "fresh ECH peer stopped")?;
            let held = owner.await?.into_body();

            let url = format!("https://{ORIGIN_NAME}:{port}/cancel-stream");
            let cancelled = transport.request(&session, Method::GET, &url)?.send().await?;
            if cancelled.status() != StatusCode::OK {
                return Err("cancellation stream returned the wrong status".into());
            }
            drop(cancelled);
            reset_observed.await?;

            let url = format!("https://{ORIGIN_NAME}:{port}/sibling");
            let response = transport.request(&session, Method::GET, &url)?.send().await?;
            if response.status() != StatusCode::NO_CONTENT {
                return Err("healthy recovered sibling returned the wrong status".into());
            }
            response.into_body().collect().await?;
            if held.collect().await?.to_bytes() != "held-done" {
                return Err("cancelling an H2 sibling changed the active recovered body".into());
            }
            drop(session);
            join(&mut server).await?;
            let observed = offers.take();
            if observed.len() != 3 || observed.first() != Some(&FRESH)
                || observed.last() != Some(&FRESH)
            {
                return Err("H2 cancellation opened another ECH connection".into());
            }
            Ok(())
        }).await;
        finish(result, server).await?;
    }
    Ok(())
}

#[tokio::test]
async fn refresh_keeps_inflight_h2_recovery_out_of_the_new_pool_generation() -> TestResult<()> {
    for transport in H2_TRANSPORTS {
        let mut server = None;
        let result = bounded(async {
            let identity = origin_identity()?;
            let offers = Offers::default();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            // Both generations may own one TCP setup until the old one
            // finishes. Refresh preserves their aggregate admission bound.
            let two = NonZeroUsize::new(2).ok_or("zero connection bound")?;
            let session = discovering_client_with_slots(&identity, port, two)?;
            let acceptor = acceptor_for(&identity, &offers, H2_ALPN)?;
            peer::set_key(&acceptor, 1, &TEST_ECH_KEYS[0])?;
            let (closed, seed_closed) = oneshot::channel();
            let (arrived, recovery_arrived) = oneshot::channel();
            let (release, released) = oneshot::channel();
            server = Some(ConnectionPeer::spawn(async move {
                serve_refreshed(listener, acceptor, transport, closed,
                    RecoveryGate { arrived, released }).await
            }));
            let seed = format!("https://{ORIGIN_NAME}:{port}/seed");
            transport.request(&session, Method::GET, &seed)?.send().await?
                .into_body().collect().await?;
            seed_closed.await?;

            let url = format!("https://{ORIGIN_NAME}:{port}/before-refresh");
            let mut old = Box::pin(transport.request(&session, Method::GET, &url)?.send());
            tokio::select! {
                biased;
                _ = &mut old => return Err("old ECH recovery finished before refresh".into()),
                result = recovery_arrived => result?,
            }
            session.clone().refresh_connections().await;
            let url = format!("https://{ORIGIN_NAME}:{port}/after-refresh");
            let mut fresh = Box::pin(transport.request(&session, Method::GET, &url)?.send());
            let response = tokio::select! {
                biased;
                _ = &mut old => return Err("refresh completed or cancelled the withheld old recovery".into()),
                result = &mut fresh => result?,
            };
            if response.status() != StatusCode::OK {
                return Err("refreshed request returned the wrong status".into());
            }
            response.into_body().collect().await?;
            release.send(()).map_err(|_| "old ECH peer stopped")?;
            old.await?.into_body().collect().await?;

            let url = format!("https://{ORIGIN_NAME}:{port}/new-reuse");
            transport.request(&session, Method::GET, &url)?.send().await?
                .into_body().collect().await?;
            drop(session);
            join(&mut server).await?;
            Ok(())
        }).await;
        finish(result, server).await?;
    }
    Ok(())
}
