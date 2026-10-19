//! Pull-driven body ownership and cancellation without JavaScript references.

use std::{
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Instant,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use napi::Result;
use phantom::ResponseBody;
use tokio::sync::{OwnedSemaphorePermit, watch};

use crate::{
    client::ClientState,
    error::{failure, request},
};

const ACTIVE: u8 = 0;
const EOF: u8 = 1;
const CANCELLED: u8 = 2;
const FAILED: u8 = 3;
pub(crate) const MAXIMUM_READ_BYTES: usize = 64 * 1024;

#[derive(Debug)]
struct Body {
    stream: ResponseBody,
    pending: Bytes,
}

#[derive(Debug)]
pub(crate) struct Exchange {
    claimed: AtomicBool,
    terminal: AtomicU8,
    reading: AtomicBool,
    setting_up: AtomicBool,
    cancelled: watch::Sender<bool>,
    body: Mutex<Option<Body>>,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    deadline: Mutex<Option<Instant>>,
}

impl Exchange {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            claimed: AtomicBool::new(false),
            terminal: AtomicU8::new(ACTIVE),
            reading: AtomicBool::new(false),
            setting_up: AtomicBool::new(false),
            cancelled: watch::channel(false).0,
            body: Mutex::new(None),
            permit: Mutex::new(None),
            deadline: Mutex::new(None),
        })
    }

    pub(crate) fn claim(
        &self,
        permit: OwnedSemaphorePermit,
        deadline: Option<Instant>,
    ) -> Result<()> {
        if self.claimed.swap(true, Ordering::AcqRel) {
            return Err(failure(
                "InvalidOperation",
                "a cancellation handle belongs to one request",
            ));
        }
        self.setting_up.store(true, Ordering::Release);
        *self.permit.lock().unwrap_or_else(PoisonError::into_inner) = Some(permit);
        *self.deadline.lock().unwrap_or_else(PoisonError::into_inner) = deadline;
        if let Err(error) = self.check() {
            self.setting_up.store(false, Ordering::Release);
            self.fail();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn is_active(&self) -> bool {
        self.terminal.load(Ordering::Acquire) == ACTIVE
    }

    pub(crate) fn check(&self) -> Result<()> {
        if *self.cancelled.borrow() {
            return Err(failure("Cancelled", "request was cancelled"));
        }
        if self
            .deadline
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(failure("Timeout", "request deadline expired"));
        }
        Ok(())
    }

    pub(crate) async fn interrupted(&self) -> napi::Error {
        let mut cancelled = self.cancelled.subscribe();
        let deadline = *self.deadline.lock().unwrap_or_else(PoisonError::into_inner);
        let cancellation = async {
            if !*cancelled.borrow_and_update() {
                let _ = cancelled.wait_for(|cancelled| *cancelled).await;
            }
            failure("Cancelled", "request was cancelled")
        };
        match deadline {
            Some(deadline) => tokio::select! {
                error = cancellation => error,
                () = tokio::time::sleep_until(deadline.into()) => failure("Timeout", "request deadline expired"),
            },
            None => cancellation.await,
        }
    }

    pub(crate) fn attach(&self, stream: ResponseBody) -> Result<()> {
        let mut body = self.body.lock().unwrap_or_else(PoisonError::into_inner);
        self.check()?;
        *body = Some(Body {
            stream,
            pending: Bytes::new(),
        });
        Ok(())
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.send_replace(true);
        self.finish(CANCELLED);
    }

    pub(crate) fn fail(&self) {
        self.finish(FAILED);
    }

    fn finish(&self, outcome: u8) {
        let _ =
            self.terminal
                .compare_exchange(ACTIVE, outcome, Ordering::AcqRel, Ordering::Acquire);
        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if !self.reading.load(Ordering::Acquire) && !self.setting_up.load(Ordering::Acquire) {
            self.release();
        }
    }

    fn release(&self) {
        self.permit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    pub(crate) async fn read(self: Arc<Self>, maximum: u32) -> Result<Option<Vec<u8>>> {
        if maximum == 0 || maximum as usize > MAXIMUM_READ_BYTES {
            return Err(failure("InputLimit", "read size must be 1..65536 bytes"));
        }
        if self
            .reading
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(failure(
                "ConcurrentRead",
                "only one body read may be pending",
            ));
        }
        let _reading = Reading(Arc::clone(&self));
        if self.terminal.load(Ordering::Acquire) == EOF {
            return Ok(None);
        }
        if let Err(error) = self.check() {
            self.fail();
            return Err(error);
        }
        let mut body = self
            .body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| failure("BodyClosed", "response body is closed"))?;
        let next = async {
            loop {
                if !body.pending.is_empty() {
                    return Ok(Some(
                        body.pending
                            .split_to((maximum as usize).min(body.pending.len()))
                            .to_vec(),
                    ));
                }
                match body.stream.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(bytes) = frame.into_data() {
                            body.pending = bytes;
                        }
                    }
                    Some(Err(error)) => return Err(request(error)),
                    None => return Ok(None),
                }
            }
        };
        let result = tokio::select! {
            biased;
            error = self.interrupted() => Err(error),
            result = next => result,
        };
        match &result {
            Ok(Some(_)) => {
                let mut retained = self.body.lock().unwrap_or_else(PoisonError::into_inner);
                if let Err(error) = self.check() {
                    drop(retained);
                    self.fail();
                    return Err(error);
                }
                *retained = Some(body);
            }
            Ok(None) => self.finish(EOF),
            Err(_) => self.fail(),
        }
        result
    }
}

struct Reading(Arc<Exchange>);

impl Drop for Reading {
    fn drop(&mut self) {
        self.0.reading.store(false, Ordering::Release);
        if !self.0.is_active() && !self.0.setting_up.load(Ordering::Acquire) {
            self.0.release();
        }
    }
}

pub(crate) struct Pending {
    exchange: Arc<Exchange>,
    _owner: Option<Arc<ClientState>>,
}

impl Pending {
    pub(crate) fn new(exchange: Arc<Exchange>, owner: Arc<ClientState>) -> Self {
        Self {
            exchange,
            _owner: Some(owner),
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.exchange.setting_up.store(false, Ordering::Release);
        let missing_body = self
            .exchange
            .body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none();
        if missing_body {
            self.exchange.fail();
        } else if !self.exchange.is_active() {
            self.exchange.release();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    #[test]
    fn cancelled_setup_keeps_its_slot_until_the_owned_future_is_dropped() -> Result<()> {
        let admission = Arc::new(Semaphore::new(1));
        let exchange = Exchange::new();
        let permit = Arc::clone(&admission)
            .try_acquire_owned()
            .map_err(|_| failure("TestAdmission", "initial admission failed"))?;
        exchange.claim(permit, None)?;
        let pending = Pending {
            exchange: Arc::clone(&exchange),
            _owner: None,
        };
        exchange.cancel();
        assert_eq!(admission.available_permits(), 0);
        assert!(Arc::clone(&admission).try_acquire_owned().is_err());
        drop(pending);
        assert_eq!(admission.available_permits(), 1);
        Ok(())
    }
}
