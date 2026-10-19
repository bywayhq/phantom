use super::*;
use phantom_profile::browser::chrome;

#[tokio::test]
async fn selected_stores_persist_and_leave_preexisting_preparations_valid() -> TestResult {
    let tcp = tcp()?;
    let quic = quic()?;
    let pool = ConnectUdpProxyPool::new();
    let tcp_source = tcp.with_isolated_session_cache();
    let quic_source = quic.with_isolated_session_cache();
    let tcp_owner = tcp_source
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("TCP cache absent")?;
    let quic_owner = quic_source
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("QUIC cache absent")?;
    let old_h2 =
        tcp.prepare_connect_udp_outer(&pool, "localhost", 443, "localhost:443", &[], None)?;
    let old_h3 =
        quic.prepare_connect_udp_outer(&quic, &pool, "localhost", 443, "localhost:443", &[], None)?;
    let selected_h2 = tcp.prepare_connect_udp_outer_with_ticket_cache(
        &pool,
        "localhost",
        443,
        "localhost:443",
        &[],
        &tcp_owner,
        None,
    )?;
    let selected_h3 = quic.prepare_connect_udp_outer_with_ticket_cache(
        &quic,
        &pool,
        "localhost",
        443,
        "localhost:443",
        &[],
        &quic_owner,
        None,
    )?;
    assert!(!same_cache(&old_h2, &selected_h2)?);
    assert!(!same_cache(&old_h3, &selected_h3)?);
    for token in [&old_h2, &old_h3, &selected_h2, &selected_h3] {
        drop(pool.acquire_prepared(token.key.clone(), token).await?);
    }
    let tcp_weak = selected_h2
        .session_ticket_cache()
        .ok_or("TCP control absent")?;
    let quic_weak = selected_h3
        .session_ticket_cache()
        .ok_or("QUIC control absent")?;
    drop((
        selected_h2,
        selected_h3,
        tcp_owner,
        quic_owner,
        tcp_source,
        quic_source,
    ));
    assert!(tcp_weak.is_live());
    assert!(quic_weak.is_live());
    drop((old_h2, old_h3));
    pool.clear();
    assert!(!tcp_weak.is_live());
    assert!(!quic_weak.is_live());
    Ok(())
}

#[tokio::test]
async fn an_existing_selected_outer_rejects_a_different_group_without_changing_it() -> TestResult {
    let tcp = tcp()?;
    let quic = quic()?;
    let pool = ConnectUdpProxyPool::new();
    let tcp_one = tcp.with_isolated_session_cache();
    let tcp_two = tcp.with_isolated_session_cache();
    let quic_one = quic.with_isolated_session_cache();
    let quic_two = quic.with_isolated_session_cache();
    let tcp_owner = tcp_one
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("TCP owner absent")?;
    let tcp_other = tcp_two
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("TCP owner absent")?;
    let quic_owner = quic_one
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("QUIC owner absent")?;
    let quic_other = quic_two
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("QUIC owner absent")?;
    let h2 = tcp.prepare_connect_udp_outer_with_ticket_cache(
        &pool,
        "localhost",
        443,
        "localhost:443",
        &[],
        &tcp_owner,
        None,
    )?;
    let h3 = quic.prepare_connect_udp_outer_with_ticket_cache(
        &quic,
        &pool,
        "localhost",
        443,
        "localhost:443",
        &[],
        &quic_owner,
        None,
    )?;
    let h2_error = tcp
        .prepare_connect_udp_outer_with_ticket_cache(
            &pool,
            "localhost",
            443,
            "localhost:443",
            &[],
            &tcp_other,
            None,
        )
        .err()
        .ok_or("conflicting group accepted")?;
    let h3_error = quic
        .prepare_connect_udp_outer_with_ticket_cache(
            &quic,
            &pool,
            "localhost",
            443,
            "localhost:443",
            &[],
            &quic_other,
            None,
        )
        .err()
        .ok_or("conflicting group accepted")?;
    for error in [h2_error, h3_error] {
        assert_eq!(error.kind(), ConnectUdpErrorKind::Configuration);
        assert!(error.to_string().contains("different shared ticket store"));
    }
    for token in [&h2, &h3] {
        drop(pool.acquire_prepared(token.key.clone(), token).await?);
    }
    Ok(())
}

#[tokio::test]
async fn refresh_keeps_prepared_caches_and_isolates_old_setup() -> TestResult {
    let tcp = tcp()?;
    let quic = quic()?;
    let pool = ConnectUdpProxyPool::new();
    let h2 = tcp.prepare_connect_udp_outer(&pool, "localhost", 443, "localhost:443", &[], None)?;
    let h3 =
        quic.prepare_connect_udp_outer(&quic, &pool, "localhost", 443, "localhost:443", &[], None)?;
    for prepared in [&h2, &h3] {
        let old = pool.entry(prepared.key.clone())?;
        let Acquisition::Setup(pending) = pool
            .acquire_prepared(prepared.key.clone(), prepared)
            .await?
        else {
            return Err("old setup absent".into());
        };
        pool.refresh_connections();
        let fresh = pool.entry(prepared.key.clone())?;
        assert!(!Arc::ptr_eq(&old, &fresh));
        let Acquisition::Setup(current) = pool
            .acquire_prepared(prepared.key.clone(), prepared)
            .await?
        else {
            return Err("fresh setup absent".into());
        };
        drop(pending);
        assert!(
            lock(&fresh.state).connecting.is_some(),
            "old cancellation cleared fresh setup"
        );
        match &prepared.connector {
            Connector::Http2(expected) => {
                assert!(Arc::ptr_eq(&current.prepared_http2(prepared)?, expected))
            }
            Connector::Http3(expected) => {
                assert!(Arc::ptr_eq(&current.prepared_http3(prepared)?, expected))
            }
        }
        drop(current);
        let weak = Arc::downgrade(&old);
        drop(old);
        assert!(
            weak.upgrade().is_none(),
            "prepared cache retained old session owner"
        );
    }
    let fresh_h2 =
        tcp.prepare_connect_udp_outer(&pool, "localhost", 443, "localhost:443", &[], None)?;
    let fresh_h3 =
        quic.prepare_connect_udp_outer(&quic, &pool, "localhost", 443, "localhost:443", &[], None)?;
    assert!(same_cache(&h2, &fresh_h2)?);
    assert!(same_cache(&h3, &fresh_h3)?);
    Ok(())
}

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn tcp() -> Result<HttpsProxyConnector, Box<dyn std::error::Error + Send + Sync>> {
    Ok(HttpsProxyConnector::new(&chrome::v154_tcp_tls())?
        .with_protocol(super::super::super::HttpsProxyProtocol::Http2)
        .with_http2_settings(&chrome::v154_http2()))
}

fn quic() -> Result<Http3Connector, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Http3Connector::new(
        &chrome::v154_quic_tls(),
        &chrome::v154_quic(),
        &chrome::v154_http3(),
        &chrome::v154_http3_request(),
    )?)
}

fn same_cache(
    left: &PreparedConnectUdpOuter,
    right: &PreparedConnectUdpOuter,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let left = left
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("left cache absent")?;
    let right = right
        .session_ticket_cache()
        .and_then(|cache| cache.upgrade())
        .ok_or("right cache absent")?;
    Ok(left.same_cache(&right))
}

#[tokio::test]
async fn h2_and_h3_setup_select_the_actual_registered_cache() -> TestResult {
    let tcp = tcp()?;
    let quic = quic()?;
    let pool = ConnectUdpProxyPool::new();
    let h2 = tcp.prepare_connect_udp_outer(&pool, "localhost", 443, "localhost:443", &[], None)?;
    let h2_again =
        tcp.prepare_connect_udp_outer(&pool, "localhost", 443, "localhost:443", &[], None)?;
    assert!(same_cache(&h2, &h2_again)?);
    let h3 =
        quic.prepare_connect_udp_outer(&quic, &pool, "localhost", 443, "localhost:443", &[], None)?;
    let h3_again =
        quic.prepare_connect_udp_outer(&quic, &pool, "localhost", 443, "localhost:443", &[], None)?;
    assert!(same_cache(&h3, &h3_again)?);
    for prepared in [&h2, &h3] {
        let Acquisition::Setup(setup) = pool
            .acquire_prepared(prepared.key.clone(), prepared)
            .await?
        else {
            return Err("unexpected reuse".into());
        };
        let selected = match &prepared.connector {
            Connector::Http2(_) => setup.prepared_http2(prepared)?.session_ticket_cache(),
            Connector::Http3(_) => setup.prepared_http3(prepared)?.session_ticket_cache(),
        }
        .and_then(|cache| cache.upgrade())
        .ok_or("selected cache absent")?;
        let registered = prepared
            .session_ticket_cache()
            .and_then(|cache| cache.upgrade())
            .ok_or("registered cache absent")?;
        assert!(selected.same_cache(&registered));
        drop(setup);
    }
    Ok(())
}

#[tokio::test]
async fn pool_clear_rejects_old_tokens_without_late_cache_creation() -> TestResult {
    let tcp = tcp()?;
    let quic = quic()?;
    let pool = ConnectUdpProxyPool::new();
    let h2 = tcp.prepare_connect_udp_outer(&pool, "localhost", 443, "localhost:443", &[], None)?;
    let h3 =
        quic.prepare_connect_udp_outer(&quic, &pool, "localhost", 443, "localhost:443", &[], None)?;
    let controls = [
        h2.session_ticket_cache().ok_or("H2 cache absent")?,
        h3.session_ticket_cache().ok_or("H3 cache absent")?,
    ];
    pool.clear();
    for prepared in [&h2, &h3] {
        assert_eq!(
            pool.acquire_prepared(prepared.key.clone(), prepared)
                .await
                .err()
                .ok_or("stale token accepted")?
                .kind(),
            ConnectUdpErrorKind::Configuration
        );
        let state = lock(&prepared.connectors);
        assert!(state.http2_connector.is_none());
        assert!(state.http3_connector.is_none());
    }
    assert!(controls.iter().all(crate::SessionTicketCache::is_live));
    let new_h2 =
        tcp.prepare_connect_udp_outer(&pool, "localhost", 443, "localhost:443", &[], None)?;
    let new_h3 =
        quic.prepare_connect_udp_outer(&quic, &pool, "localhost", 443, "localhost:443", &[], None)?;
    assert!(!same_cache(&h2, &new_h2)?);
    assert!(!same_cache(&h3, &new_h3)?);
    Ok(())
}

#[tokio::test]
async fn prepared_cache_cannot_cross_pool_headers_or_credentials() -> TestResult {
    let base = tcp()?;
    let pool = ConnectUdpProxyPool::new();
    let credentials =
        super::super::super::HttpBasicCredentials::new("private-user", "private-password")?;
    let headers = [crate::request::RequestHeader::new(
        "x-private",
        "private-value",
    )];
    let prepared = base.prepare_connect_udp_outer(
        &pool,
        "localhost",
        443,
        "localhost:443",
        &headers,
        Some(&credentials),
    )?;
    assert_eq!(
        prepared
            .validate(&pool.fresh(), &prepared.key)
            .err()
            .ok_or("other pool accepted")?
            .kind(),
        ConnectUdpErrorKind::Configuration
    );
    for key in [
        PoolKey::http2(
            &base,
            "localhost",
            443,
            "localhost:443",
            &[],
            Some(&credentials),
        )?,
        PoolKey::http2(&base, "localhost", 443, "localhost:443", &headers, None)?,
    ] {
        assert_eq!(
            prepared
                .validate(&pool, &key)
                .err()
                .ok_or("other configuration accepted")?
                .kind(),
            ConnectUdpErrorKind::Configuration
        );
    }
    let debug = format!("{prepared:?}");
    for secret in [
        "private-user",
        "private-password",
        "private-value",
        "localhost",
    ] {
        assert!(!debug.contains(secret));
    }
    Ok(())
}

#[tokio::test]
async fn native_unprepared_acquisition_keeps_lazy_connector_selection() -> TestResult {
    let base = tcp()?;
    let pool = ConnectUdpProxyPool::new();
    let key = PoolKey::http2(&base, "localhost", 443, "localhost:443", &[], None)?;
    let Acquisition::Setup(setup) = pool.acquire(key).await? else {
        return Err("unexpected reuse".into());
    };
    assert!(
        lock(&setup.lease.as_ref().ok_or("lease absent")?.entry.connectors)
            .http2_connector
            .is_none()
    );
    let selected = setup.http2_connector(&base)?;
    assert!(selected.session_ticket_cache().is_some());
    drop(setup);
    Ok(())
}

#[tokio::test]
async fn prepared_owners_preserve_live_key_bound_and_h1_rejection() -> TestResult {
    let base = tcp()?;
    let pool = ConnectUdpProxyPool::new();
    let mut owners = Vec::new();
    for port in 1..=super::super::MAX_CONNECT_UDP_POOL_KEYS {
        owners.push(base.prepare_connect_udp_outer(
            &pool,
            "localhost",
            u16::try_from(port)?,
            "localhost",
            &[],
            None,
        )?);
    }
    assert_eq!(
        base.prepare_connect_udp_outer(&pool, "localhost", 100, "localhost", &[], None)
            .err()
            .ok_or("live key evicted")?
            .kind(),
        ConnectUdpErrorKind::Capacity
    );
    drop(owners.pop());
    let _next = base.prepare_connect_udp_outer(&pool, "localhost", 100, "localhost", &[], None)?;
    let h1 = HttpsProxyConnector::new(&chrome::v154_tcp_tls())?;
    assert_eq!(
        h1.prepare_connect_udp_outer(&pool, "localhost", 443, "localhost", &[], None)
            .err()
            .ok_or("H1 prepared")?
            .kind(),
        ConnectUdpErrorKind::Configuration
    );
    Ok(())
}
