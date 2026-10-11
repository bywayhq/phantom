use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;

fn poison(captured: &Captured) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if let Ok(_guard) = captured.quic_serving_fault.lock() {
            panic!("controlled QUIC observation poisoning");
        }
    }));
    assert!(outcome.is_err());
    assert!(captured.quic_serving_fault.is_poisoned());
}

#[test]
fn poisoned_response_observation_reports_consumption_without_invoking_the_fault() -> TestResult {
    let captured = Captured::default();
    let reached = Arc::new(AtomicBool::new(false));
    install_fault(
        &captured,
        QuicServingFault {
            slot: 0,
            error: StreamError::Undefined(Box::new(LocalQuicServingFailure(Arc::new(())))),
            reached: Arc::clone(&reached),
        },
    )?;
    poison(&captured);

    let error = observe_response(Ok(()), &captured, 0)
        .err()
        .ok_or("poisoned response observation reported success")?;
    let StreamError::Undefined(cause) = error else {
        return Err("poisoned response observation changed its error variant".into());
    };
    let observation = cause
        .downcast_ref::<QuicObservationFailure>()
        .ok_or("poisoned response observation lost its typed prerequisite failure")?;
    assert_eq!(observation.boundary, "response consumption");
    assert!(!observation.diagnostic.is_empty());
    assert!(!reached.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn poisoned_fault_installation_reports_its_boundary_without_invoking_the_fault() -> TestResult {
    let captured = Captured::default();
    let reached = Arc::new(AtomicBool::new(false));
    poison(&captured);

    let error = install_fault(
        &captured,
        QuicServingFault {
            slot: 0,
            error: StreamError::Undefined(Box::new(LocalQuicServingFailure(Arc::new(())))),
            reached: Arc::clone(&reached),
        },
    )
    .err()
    .ok_or("poisoned fault installation reported success")?;
    assert_eq!(error.boundary, "fault installation");
    assert!(!error.diagnostic.is_empty());
    assert!(!reached.load(Ordering::Acquire));
    Ok(())
}
