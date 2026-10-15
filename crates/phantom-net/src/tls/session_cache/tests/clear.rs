use super::super::*;

#[test]
fn ordered_all_store_clear_retires_each_capture_and_preserves_fresh_publication()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let first = TlsSessionCache::new(2, TicketOrder::Newest, super::context()?);
    let second = TlsSessionCache::new(2, TicketOrder::OldestConnection, super::context()?);
    let first_capture = first.begin_handshake("first.test");
    let second_capture = second.begin_handshake("second.test");
    let owners = [
        crate::SessionTicketCache::tcp(second.control())
            .upgrade()
            .ok_or("live second cache absent")?,
        crate::SessionTicketCache::tcp(first.control())
            .upgrade()
            .ok_or("live first cache absent")?,
    ];
    assert_eq!(crate::SessionTicketCacheOwner::clear_stores(&owners)?, 0);
    assert!(first_capture.state().retired);
    assert!(second_capture.state().retired);
    let fresh_first = first.begin_handshake("first.test");
    let fresh_second = second.begin_handshake("second.test");
    assert!(!fresh_first.state().retired);
    assert!(!fresh_second.state().retired);
    assert!(!Arc::ptr_eq(
        &first_capture.generation,
        &fresh_first.generation
    ));
    assert!(!Arc::ptr_eq(
        &second_capture.generation,
        &fresh_second.generation
    ));
    Ok(())
}

#[test]
fn reversed_clear_input_locks_lower_store_before_waiting_on_upper_store()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::{
        sync::{TryLockError, mpsc},
        thread,
        time::{Duration, Instant},
    };

    let first = TlsSessionCache::new(2, TicketOrder::Newest, super::context()?);
    let second = TlsSessionCache::new(2, TicketOrder::Newest, super::context()?);
    let (lower, upper) = if Arc::as_ptr(&first.inner) < Arc::as_ptr(&second.inner) {
        (&first, &second)
    } else {
        (&second, &first)
    };
    let owners = [
        crate::SessionTicketCache::tcp(upper.control())
            .upgrade()
            .ok_or("upper cache absent")?,
        crate::SessionTicketCache::tcp(lower.control())
            .upgrade()
            .ok_or("lower cache absent")?,
    ];
    let held_upper = upper.store();
    let (start_tx, start_rx) = mpsc::channel();
    let deadline = Instant::now() + Duration::from_secs(10);
    let worker = thread::Builder::new()
        .name("ticket-clear-order".into())
        .spawn(move || {
            let started = start_tx.send(());
            let cleared = crate::SessionTicketCacheOwner::clear_stores(&owners);
            (started, cleared)
        })?;
    let started = start_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    let lower_blocked = if started.is_ok() {
        loop {
            match lower.inner.store.try_lock() {
                Err(TryLockError::WouldBlock) => break Ok(true),
                Err(TryLockError::Poisoned(_)) => break Err("lower store poisoned"),
                Ok(guard) => drop(guard),
            }
            if Instant::now() >= deadline {
                break Ok(false);
            }
            thread::yield_now();
        }
    } else {
        Ok(false)
    };
    // Even a reversed-order regression can finish after this release. Join it
    // before reporting failure so the control cannot strand a blocked thread.
    drop(held_upper);
    let result = worker.join();
    started?;
    let (sent, cleared) = result.map_err(|_| "clear worker panicked")?;
    sent?;
    assert_eq!(cleared?, 0);
    assert!(
        lower_blocked?,
        "clear waited on upper without first locking lower"
    );
    Ok(())
}
