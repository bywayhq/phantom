use super::*;
use crate::{http3::Http3Connector, tls::TlsConnector};
use phantom_profile::browser::chrome;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn tcp() -> Result<TlsConnector, Box<dyn std::error::Error + Send + Sync>> {
    Ok(TlsConnector::new(&chrome::v154_tcp_tls())?)
}

fn quic() -> Result<Http3Connector, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Http3Connector::new(
        &chrome::v154_quic_tls(),
        &chrome::v154_quic(),
        &chrome::v154_http3(),
        &chrome::v154_http3_request(),
    )?)
}

fn owner(
    control: Option<SessionTicketCache>,
) -> Result<SessionTicketCacheOwner, Box<dyn std::error::Error + Send + Sync>> {
    control
        .and_then(|control| control.upgrade())
        .ok_or_else(|| "cache absent".into())
}

#[test]
fn opposite_registry_orders_select_identical_actual_lock_order() -> TestResult {
    let tcp = tcp()?;
    let quic = quic()?;
    let first_tcp = tcp.with_isolated_session_cache();
    let second_tcp = tcp.with_isolated_session_cache();
    let first_quic = quic.with_isolated_session_cache();
    let second_quic = quic.with_isolated_session_cache();
    let mut owners = vec![
        owner(first_quic.session_ticket_cache())?,
        owner(second_tcp.session_ticket_cache())?,
        owner(second_quic.session_ticket_cache())?,
        owner(first_tcp.session_ticket_cache())?,
    ];
    let order = SessionTicketCacheOwner::clear_order(&owners)?;
    assert!(
        order[..2]
            .iter()
            .all(|index| matches!(&owners[*index].cache, OwnedCache::Tcp(_)))
    );
    assert!(
        order[2..]
            .iter()
            .all(|index| matches!(&owners[*index].cache, OwnedCache::Quic(_)))
    );
    owners.reverse();
    let reversed = SessionTicketCacheOwner::clear_order(&owners)?;
    let mapped: Vec<_> = reversed
        .into_iter()
        .map(|index| owners.len() - 1 - index)
        .collect();
    assert_eq!(order, mapped);
    assert_eq!(SessionTicketCacheOwner::clear_stores(&owners)?, 0);
    Ok(())
}

#[test]
fn clear_deduplicates_real_aliases_without_transfer_binding() -> TestResult {
    let tcp = tcp()?.with_isolated_session_cache();
    let quic = quic()?.with_isolated_session_cache();
    let owners = vec![
        owner(tcp.session_ticket_cache())?,
        owner(quic.session_ticket_cache())?,
        owner(tcp.session_ticket_cache())?,
        owner(quic.session_ticket_cache())?,
    ];
    assert_eq!(SessionTicketCacheOwner::clear_order(&owners)?.len(), 2);
    assert_eq!(SessionTicketCacheOwner::clear_stores(&owners)?, 0);
    Ok(())
}

#[test]
fn clear_accepts_more_than_256_tcp_and_quic_owners() -> TestResult {
    let tcp = tcp()?;
    let quic = quic()?;
    let mut owners = Vec::new();
    for _ in 0..257 {
        owners.push(owner(
            tcp.with_isolated_session_cache().session_ticket_cache(),
        )?);
        owners.push(owner(
            quic.with_isolated_session_cache().session_ticket_cache(),
        )?);
    }
    assert_eq!(owners.len(), 514);
    assert_eq!(SessionTicketCacheOwner::clear_order(&owners)?.len(), 514);
    assert_eq!(SessionTicketCacheOwner::clear_stores(&owners)?, 0);
    assert!(matches!(
        SessionTicketCacheOwner::capture_tcp_stores(
            &owners
                .iter()
                .map(|owner| (owner, "example.test"))
                .collect::<Vec<_>>()
        ),
        Err(btls::ssl::SessionTransferError::TooLarge)
    ));
    Ok(())
}

#[test]
fn clear_empty_owner_set_changes_nothing() -> TestResult {
    assert_eq!(SessionTicketCacheOwner::clear_stores(&[])?, 0);
    Ok(())
}
