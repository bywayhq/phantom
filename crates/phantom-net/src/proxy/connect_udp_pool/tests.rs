mod admission;
mod family;
mod http2;
mod http3;

#[test]
fn shared_scope_preserves_auto_traits_and_clone_identity() {
    fn assert_traits<
        T: Send + Sync + Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe,
    >() {
    }

    assert_traits::<super::ConnectUdpProxyPool>();
    assert_traits::<super::Pool>();

    let pool = super::ConnectUdpProxyPool::new();
    let clone = pool.clone();
    let fresh = pool.fresh();
    assert!(pool.shares_scope(&clone));
    assert!(!pool.shares_scope(&fresh));
    assert_eq!(pool.max_active(), fresh.max_active());
    assert_eq!(pool.max_pending(), fresh.max_pending());
}
