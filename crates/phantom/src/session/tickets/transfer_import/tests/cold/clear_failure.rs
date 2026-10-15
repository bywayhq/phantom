use super::*;

#[tokio::test]
async fn poisoned_registry_clear_preserves_live_and_cold_custody() -> TestResult {
    let fixture = ImportFixture::new()?;
    let decoding = decoding_context()?;
    let source = fixture.owner()?;
    let first = fixture.store(&source, 443)?;
    let second = fixture.store(&source, 444)?;
    fixture.exchange(&first, false).await?;
    fixture.exchange(&second, false).await?;
    let recipient = fixture.owner()?;
    let live = fixture.store(&recipient, 443)?;
    recipient.import_tcp(&live_snapshot(&source, None)?, &KEY, &decoding)?;
    let live_before = store_header(&live)?;
    let cold_before = cold_snapshot(&recipient)?;
    assert!(live_before.record_count() > 0);
    assert_eq!(cold_before.owners.len(), 1);
    assert!(!cold_before.native.is_empty());

    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _registry = recipient.registry();
        panic!("controlled registry poison");
    }));
    assert!(poisoned.is_err());
    let failure = recipient.clear().err().ok_or("poisoned clear succeeded")?;
    assert_eq!(failure.kind(), crate::SessionTicketErrorKind::Backend);
    assert_eq!(store_header(&live)?, live_before);
    let cold_after = cold_snapshot(&recipient)?;
    assert_eq!(cold_after.owners.len(), cold_before.owners.len());
    assert_eq!(cold_after.native.len(), cold_before.native.len());
    assert_eq!(cold_after.owners[0].header, cold_before.owners[0].header);
    // The failed clear neither consumes native custody nor retires live tickets.
    fixture.exchange(&live, true).await?;
    Ok(())
}
