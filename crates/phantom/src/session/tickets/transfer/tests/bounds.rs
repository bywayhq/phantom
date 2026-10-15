use super::*;

#[test]
fn empty_owner_export_matches_the_complete_frame_admission_budget() -> TestResult {
    let (owner, _connector, _) = empty_fixture()?;
    let sealed = owner.export_tcp(&KEY)?;
    let cache_registry = owner.registry();
    let registry = &cache_registry.caches;
    let registered = &registry[0];
    let registration = registered.binding.as_ref().map_err(|error| *error)?;
    let binding = registered.native_binding.as_ref().map_err(|error| *error)?;
    let live = LiveOwner {
        cache: registered.cache.upgrade().ok_or("cache dead")?,
        registration,
        native_binding: binding,
    };
    assert_eq!(sealed.as_bytes().len(), owner_frame_budget(&[live])?);
    Ok(())
}

#[test]
fn aggregate_record_budget_rejects_overflow_without_admitting_the_record() -> TestResult {
    let mut budget = MAX_FRAME - 7;
    charge_frame(&mut budget, 7)?;
    assert_eq!(budget, MAX_FRAME);
    assert!(matches!(
        charge_frame(&mut budget, 1),
        Err(TcpExportError::TooLarge)
    ));
    assert_eq!(budget, MAX_FRAME);
    assert!(matches!(
        charge_frame(&mut budget, usize::MAX),
        Err(TcpExportError::TooLarge)
    ));
    assert_eq!(budget, MAX_FRAME);
    Ok(())
}
