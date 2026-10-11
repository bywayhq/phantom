use std::{error::Error, sync::Arc, time::Duration};

use h3::error::StreamError;
use tokio::{sync::Notify, time::timeout};

use super::super::TestResult;
use super::{QuicObservationFailure, observe_response};
use crate::{CaptureFailures, Captured};

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub(crate) struct ResponseDelivery {
    slot: usize,
    completed: Arc<Notify>,
    observed: Arc<Notify>,
}

pub(super) fn install(captured: &Captured, slot: usize) -> Result<(), QuicObservationFailure> {
    *captured
        .quic_response_delivery
        .lock()
        .map_err(|error| QuicObservationFailure {
            boundary: "delivery installation",
            diagnostic: error.to_string(),
        })? = Some(ResponseDelivery {
        slot,
        completed: Arc::new(Notify::new()),
        observed: Arc::new(Notify::new()),
    });
    Ok(())
}

pub(super) async fn completed(captured: &Captured, slot: usize) -> TestResult {
    let delivery = {
        let delivery = captured
            .quic_response_delivery
            .lock()
            .map_err(|error| QuicObservationFailure {
                boundary: "client delivery",
                diagnostic: error.to_string(),
            })?;
        delivery
            .as_ref()
            .filter(|delivery| delivery.slot == slot)
            .cloned()
    };
    if let Some(delivery) = delivery {
        delivery.completed.notify_one();
        timeout(DELIVERY_TIMEOUT, delivery.observed.notified()).await?;
    }
    Ok(())
}

pub(crate) async fn observe_response_delivery(
    result: Result<(), StreamError>,
    captured: &Captured,
    slot: usize,
) -> Result<(), StreamError> {
    if result.is_err() {
        return result;
    }

    let delivery = {
        let delivery = match captured.quic_response_delivery.lock() {
            Ok(delivery) => delivery,
            Err(error) => {
                let diagnostic = error.to_string();
                drop(error);
                return Err(undelivered_response(
                    captured,
                    slot,
                    Box::new(QuicObservationFailure {
                        boundary: "delivery consumption",
                        diagnostic,
                    }),
                ));
            }
        };
        delivery
            .as_ref()
            .filter(|delivery| delivery.slot == slot)
            .cloned()
    };
    if let Some(delivery) = &delivery
        && let Err(prerequisite) = timeout(DELIVERY_TIMEOUT, delivery.completed.notified()).await
    {
        return Err(undelivered_response(captured, slot, Box::new(prerequisite)));
    }

    let result = observe_response(result, captured, slot);
    if let Some(delivery) = delivery {
        delivery.observed.notify_one();
    }
    result
}

fn undelivered_response(
    captured: &Captured,
    slot: usize,
    prerequisite: Box<dyn Error + Send + Sync>,
) -> StreamError {
    let mut failures: Vec<Box<dyn Error + Send + Sync>> = Vec::new();
    let mut fault = match captured.quic_serving_fault.lock() {
        Ok(fault) => fault,
        Err(error) => {
            failures.push(Box::new(QuicObservationFailure {
                boundary: "undelivered fault retention",
                diagnostic: error.to_string(),
            }));
            // Recover only to retain the installed error alongside the observation failure.
            error.into_inner()
        }
    };
    if fault.as_ref().is_some_and(|fault| fault.slot == slot)
        && let Some(fault) = fault.take()
    {
        failures.insert(0, Box::new(fault.error));
    }
    failures.push(prerequisite);
    StreamError::Undefined(Box::new(CaptureFailures(failures)))
}

#[tokio::test]
async fn missing_client_delivery_retains_the_original_fault_and_deadline() -> TestResult {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{LocalQuicServingFailure, QuicServingFault, install_fault};

    let captured = Captured::default();
    let identity = Arc::new(());
    let reached = Arc::new(AtomicBool::new(false));
    install_fault(
        &captured,
        QuicServingFault {
            slot: 0,
            error: StreamError::Undefined(Box::new(LocalQuicServingFailure(Arc::clone(&identity)))),
            reached: Arc::clone(&reached),
        },
    )?;

    let error = observe_response_delivery(Ok(()), &captured, 0)
        .await
        .err()
        .ok_or("missing client delivery reported success")?;
    let StreamError::Undefined(cause) = error else {
        return Err("missing delivery lost the retained failures".into());
    };
    let failures = cause
        .downcast_ref::<CaptureFailures>()
        .ok_or("missing delivery replaced the retained failure collection")?;
    assert_eq!(failures.0.len(), 2);
    let stream = failures.0[0]
        .downcast_ref::<StreamError>()
        .ok_or("missing delivery replaced the original HTTP/3 error")?;
    let StreamError::Undefined(cause) = stream else {
        return Err("missing delivery changed the original error variant".into());
    };
    let original = cause
        .downcast_ref::<LocalQuicServingFailure>()
        .ok_or("missing delivery replaced the original local marker")?;
    assert!(Arc::ptr_eq(&original.0, &identity));
    assert!(failures.0[1].is::<tokio::time::error::Elapsed>());
    assert!(!reached.load(Ordering::Acquire));
    Ok(())
}
