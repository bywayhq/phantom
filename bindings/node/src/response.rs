//! Pull-driven body ownership and cancellation without JavaScript references.

use std::{
    fmt,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Instant,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use napi::Result;
use phantom::{ResponseBody, ResponseTrailers};
use tokio::sync::{OwnedSemaphorePermit, watch};

use crate::{
    client::ClientState,
    error::{failure, request, total_timeout},
};

pub(crate) mod sse;

const ACTIVE: u8 = 0;
const EOF: u8 = 1;
const CANCELLED: u8 = 2;
const FAILED: u8 = 3;
pub(crate) const MAXIMUM_READ_BYTES: usize = 64 * 1024;
const COLLECTION_YIELD_BYTES: usize = 64 * 1024;
const COLLECTION_YIELD_ITERATIONS: usize = 16;

struct Body {
    response: http::Response<ResponseBody>,
    pending: Bytes,
    started: bool,
}

impl fmt::Debug for Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Body")
            .field("status", &self.response.status())
            .field("protocol", &self.response.version())
            .field("header_count", &self.response.headers().len())
            .field("pending_bytes", &self.pending.len())
            .field("started", &self.started)
            .finish()
    }
}

#[derive(Debug)]
enum RetainedBody {
    Http(Body),
    Events(phantom::SseStream),
}

#[derive(Debug)]
enum Admission {
    Request { _permit: OwnedSemaphorePermit },
    RejectedUpgrade { _permit: Arc<OwnedSemaphorePermit> },
}

#[derive(Debug)]
pub(crate) struct Exchange {
    claimed: AtomicBool,
    terminal: AtomicU8,
    reading: AtomicBool,
    setting_up: AtomicBool,
    uploading: AtomicBool,
    upload: Mutex<Option<Arc<crate::upload::Upload>>>,
    cancelled: watch::Sender<bool>,
    finished: watch::Sender<bool>,
    body: Mutex<Option<RetainedBody>>,
    event_state: Mutex<sse::EventState>,
    trailers: Mutex<ResponseTrailers>,
    permit: Mutex<Option<Admission>>,
    deadline: Mutex<Option<Instant>>,
}

impl Exchange {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            claimed: AtomicBool::new(false),
            terminal: AtomicU8::new(ACTIVE),
            reading: AtomicBool::new(false),
            setting_up: AtomicBool::new(false),
            uploading: AtomicBool::new(false),
            upload: Mutex::new(None),
            cancelled: watch::channel(false).0,
            finished: watch::channel(false).0,
            body: Mutex::new(None),
            event_state: Mutex::new(sse::EventState::default()),
            trailers: Mutex::new(ResponseTrailers::Pending),
            permit: Mutex::new(None),
            deadline: Mutex::new(None),
        })
    }

    pub(crate) fn claim(
        &self,
        permit: OwnedSemaphorePermit,
        deadline: Option<Instant>,
    ) -> Result<()> {
        self.claim_admission(Admission::Request { _permit: permit }, deadline)
    }

    pub(crate) fn claim_shared(
        &self,
        permit: Arc<OwnedSemaphorePermit>,
        deadline: Option<Instant>,
    ) -> Result<()> {
        self.claim_admission(Admission::RejectedUpgrade { _permit: permit }, deadline)
    }

    fn claim_admission(&self, permit: Admission, deadline: Option<Instant>) -> Result<()> {
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
        if self
            .upload
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|upload| upload.failed())
        {
            return Err(failure("UploadSource", "upload source failed"));
        }
        if *self.cancelled.borrow() {
            return Err(failure("Cancelled", "request was cancelled"));
        }
        if self
            .deadline
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(total_timeout());
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
                () = tokio::time::sleep_until(deadline.into()) => total_timeout(),
            },
            None => cancellation.await,
        }
    }

    pub(crate) async fn finished(&self) {
        let mut finished = self.finished.subscribe();
        if !*finished.borrow_and_update() {
            let _ = finished.wait_for(|finished| *finished).await;
        }
    }

    pub(crate) fn attach(&self, response: http::Response<ResponseBody>) -> Result<()> {
        let mut body = self.body.lock().unwrap_or_else(PoisonError::into_inner);
        self.check()?;
        *body = Some(RetainedBody::Http(Body {
            response,
            pending: Bytes::new(),
            started: false,
        }));
        Ok(())
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.send_replace(true);
        self.finish(CANCELLED, ResponseTrailers::Unavailable);
    }

    pub(crate) fn fail(&self) {
        self.finish(FAILED, ResponseTrailers::Unavailable);
    }

    pub(crate) fn trailers(&self) -> std::sync::MutexGuard<'_, ResponseTrailers> {
        self.trailers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn finish(&self, outcome: u8, trailers: ResponseTrailers) {
        let mut retained = self.trailers.lock().unwrap_or_else(PoisonError::into_inner);
        if self
            .terminal
            .compare_exchange(ACTIVE, outcome, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            *retained = trailers;
        }
        drop(retained);
        self.finished.send_replace(true);
        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(upload) = self
            .upload
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            upload.stop();
        }
        if !self.reading.load(Ordering::Acquire) && !self.setting_up.load(Ordering::Acquire) {
            self.release();
        }
    }

    fn release(&self) {
        if self.uploading.load(Ordering::Acquire) {
            return;
        }
        self.permit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    pub(crate) fn upload(self: &Arc<Self>, upload: Arc<crate::upload::Upload>) {
        self.uploading.store(true, Ordering::Release);
        upload.bind(self);
        *self.upload.lock().unwrap_or_else(PoisonError::into_inner) = Some(upload);
    }

    pub(crate) fn upload_settled(&self) {
        self.uploading.store(false, Ordering::Release);
        if !self.is_active()
            && !self.setting_up.load(Ordering::Acquire)
            && !self.reading.load(Ordering::Acquire)
        {
            self.release();
        }
    }

    pub(crate) fn upload_state(&self) -> Option<Arc<crate::upload::Upload>> {
        self.upload
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) async fn read(self: Arc<Self>, maximum: u32) -> Result<Option<Vec<u8>>> {
        if maximum == 0 || maximum as usize > MAXIMUM_READ_BYTES {
            return Err(failure("InputLimit", "read size must be 1..65536 bytes"));
        }
        let _reading = self.start_reading()?;
        if self.terminal.load(Ordering::Acquire) == EOF {
            return Ok(None);
        }
        let mut body = self.acquire_body()?;
        let next = async {
            loop {
                if !body.pending.is_empty() {
                    return Ok(Some(
                        body.pending
                            .split_to((maximum as usize).min(body.pending.len()))
                            .to_vec(),
                    ));
                }
                match body.response.body_mut().frame().await {
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
                *retained = Some(RetainedBody::Http(body));
            }
            Ok(None) => self.finish(EOF, body.response.into_body().into_trailers()),
            Err(_) => self.fail(),
        }
        result
    }

    pub(crate) async fn collect(self: Arc<Self>, maximum: u32) -> Result<Vec<u8>> {
        let _reading = self.start_reading()?;
        if self.terminal.load(Ordering::Acquire) == EOF {
            return Ok(Vec::new());
        }
        let mut body = self.acquire_body()?;
        let collect = async {
            let mut output = Vec::new();
            let mut consumed = 0usize;
            let mut iterations = 0usize;
            loop {
                self.check()?;
                append_body(&mut output, &body.pending, maximum as usize)?;
                consumed = consumed.saturating_add(body.pending.len());
                body.pending = Bytes::new();
                iterations += 1;
                if consumed >= COLLECTION_YIELD_BYTES || iterations >= COLLECTION_YIELD_ITERATIONS {
                    // Ready frames need not yield, including empty or non-data frames.
                    tokio::task::yield_now().await;
                    consumed = 0;
                    iterations = 0;
                    self.check()?;
                }
                match body.response.body_mut().frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(bytes) = frame.into_data() {
                            body.pending = bytes;
                        }
                    }
                    Some(Err(error)) => return Err(request(error)),
                    None => return Ok(output),
                }
            }
        };
        let result = tokio::select! {
            biased;
            error = self.interrupted() => Err(error),
            result = collect => result.and_then(|output| self.check().map(|()| output)),
        };
        match &result {
            Ok(_) => self.finish(EOF, body.response.into_body().into_trailers()),
            Err(_) => self.fail(),
        }
        result
    }

    fn acquire_body(&self) -> Result<Body> {
        let mut body = self.body.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*body, Some(RetainedBody::Events(_))) {
            return Err(failure(
                "BodyUsed",
                "response body belongs to its event stream",
            ));
        }
        // Cancellation removes the idle body under this lock. Check while it is
        // held so that removal cannot turn a cancellation into BodyClosed.
        if let Err(error) = self.check() {
            drop(body);
            self.fail();
            return Err(error);
        }
        match body.take() {
            Some(RetainedBody::Http(mut body)) => {
                body.started = true;
                Ok(body)
            }
            _ => Err(failure("BodyClosed", "response body is closed")),
        }
    }

    fn start_reading(self: &Arc<Self>) -> Result<Reading> {
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
        Ok(Reading(Arc::clone(self)))
    }
}

fn append_body(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<()> {
    if bytes.len() > maximum.saturating_sub(output.len()) {
        return Err(failure(
            "ResponseBodyLimit",
            "response exceeds maximumBytes",
        ));
    }
    let length = output.len() + bytes.len();
    if length > output.capacity() {
        // Grow from received bytes instead of reserving the caller's entire bound.
        let capacity = length.max(output.capacity().saturating_mul(2)).min(maximum);
        output
            .try_reserve_exact(capacity - output.len())
            .map_err(|_| failure("Allocation", "response body allocation failed"))?;
    }
    output.extend_from_slice(bytes);
    Ok(())
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

    #[test]
    fn a_rejected_upgrade_retains_its_existing_slot_until_both_owners_release() -> Result<()> {
        let admission = Arc::new(Semaphore::new(1));
        let opening = Arc::new(
            Arc::clone(&admission)
                .try_acquire_owned()
                .map_err(|_| failure("TestAdmission", "initial admission failed"))?,
        );
        let exchange = Exchange::new();
        exchange.claim_shared(Arc::clone(&opening), None)?;
        let pending = Pending {
            exchange: Arc::clone(&exchange),
            _owner: None,
        };
        drop(opening);
        assert_eq!(admission.available_permits(), 0);
        exchange.cancel();
        assert_eq!(admission.available_permits(), 0);
        drop(pending);
        assert_eq!(admission.available_permits(), 1);
        Ok(())
    }

    #[test]
    fn cancelled_upload_retains_admission_until_javascript_cleanup_acknowledges() -> Result<()> {
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
        let upload = crate::upload::Upload::new(None);
        exchange.upload(Arc::clone(&upload));
        exchange.cancel();
        drop(pending);
        assert_eq!(admission.available_permits(), 0);
        upload.settled();
        assert_eq!(admission.available_permits(), 1);
        Ok(())
    }

    #[test]
    fn cancellation_after_a_precheck_keeps_its_category_when_the_body_is_absent() -> Result<()> {
        let exchange = Exchange::new();
        exchange.check()?;
        exchange.cancel();
        assert!(
            exchange
                .body
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_none()
        );

        let error = exchange
            .acquire_body()
            .err()
            .ok_or_else(|| failure("TestBody", "cancelled acquisition succeeded"))?;
        assert_eq!(error.reason, "PHANTOM:Cancelled:request was cancelled");
        Ok(())
    }

    #[test]
    fn a_deadline_after_a_precheck_keeps_its_category_when_the_body_is_absent() -> Result<()> {
        let exchange = Exchange::new();
        exchange.check()?;
        *exchange
            .deadline
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());

        let error = exchange
            .acquire_body()
            .err()
            .ok_or_else(|| failure("TestBody", "expired acquisition succeeded"))?;
        assert_eq!(error.reason, total_timeout().reason);
        Ok(())
    }

    #[test]
    fn an_absent_body_without_cancellation_or_deadline_remains_closed() -> Result<()> {
        let exchange = Exchange::new();
        exchange.check()?;
        let error = exchange
            .acquire_body()
            .err()
            .ok_or_else(|| failure("TestBody", "absent body acquisition succeeded"))?;
        assert_eq!(error.reason, "PHANTOM:BodyClosed:response body is closed");
        Ok(())
    }

    #[test]
    fn collection_allocates_from_received_bytes_and_accepts_an_exact_bound() -> Result<()> {
        let mut output = Vec::new();
        append_body(&mut output, b"", usize::MAX)?;
        assert_eq!(output.capacity(), 0);
        append_body(&mut output, b"hello", 5)?;
        append_body(&mut output, b"", 5)?;
        assert_eq!(output, b"hello");
        Ok(())
    }

    #[test]
    fn collection_rejects_overflow_before_appending_or_allocating() -> Result<()> {
        let mut output = Vec::new();
        append_body(&mut output, b"he", 4)?;
        let capacity = output.capacity();
        assert!(append_body(&mut output, b"llo", 4).is_err());
        assert_eq!(output, b"he");
        assert_eq!(output.capacity(), capacity);
        let mut empty = Vec::new();
        assert!(append_body(&mut empty, b"x", 0).is_err());
        assert_eq!(empty.capacity(), 0);
        Ok(())
    }
}
