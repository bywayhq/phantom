use super::super::super::*;
use super::peer::{Fixture, arrivals};
use crate::tls::test_support::{TEST_SERVER_NAME as NAME, TestResult};
use btls::ssl::SslVersion;

#[tokio::test]
async fn a_permit_for_another_native_scope_cannot_replace_this_cache() -> TestResult<()> {
    let source = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let authorized = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    let other = Fixture::new(TicketOrder::Newest, 2, SslVersion::TLS1_3)?;
    source.seed(1).await?;
    other.seed(1).await?;
    let before = arrivals(&other.cache);
    let (header, permits) = source.authorized(&authorized)?;
    let owner = other.cache.control().upgrade().ok_or("owner missing")?;
    assert!(matches!(
        owner.prepare_replacement(NAME.into(), header, permits),
        Err(SessionTransferError::Policy)
    ));
    let after = arrivals(&other.cache);
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert!(Arc::ptr_eq(&after.2, &before.2));
    Ok(())
}

#[tokio::test]
async fn reverse_physical_record_order_is_rejected_without_store_mutation() -> TestResult<()> {
    let source = Fixture::new(TicketOrder::Oldest, 10, SslVersion::TLS1_3)?;
    let recipient = Fixture::new(TicketOrder::Oldest, 10, SslVersion::TLS1_3)?;
    source.seed(2).await?;
    recipient.seed(1).await?;
    let before = arrivals(&recipient.cache);
    let (header, mut permits) = source.authorized(&recipient)?;
    assert!(permits.len() >= 2);
    permits.reverse();
    let owner = recipient.cache.control().upgrade().ok_or("owner missing")?;
    assert!(matches!(
        owner.prepare_replacement(NAME.into(), header, permits),
        Err(SessionTransferError::Malformed)
    ));
    let after = arrivals(&recipient.cache);
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert!(Arc::ptr_eq(&after.2, &before.2));
    Ok(())
}
