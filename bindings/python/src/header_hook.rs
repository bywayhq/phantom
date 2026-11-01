//! Request-owned rendezvous for callbacks on the caller's Python loop.

use crate::error;
use phantom::{
    HeaderHookContext, HeaderHookError, RedirectAttempt, RedirectCallbackError, RedirectDecision,
    RequestHeader,
};
use pyo3::{
    prelude::*,
    types::{PyBool, PyBytes, PyList, PyString},
};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::{Notify, oneshot};

const MAXIMUM_FIELDS: usize = 256;
const MAXIMUM_BYTES: usize = 65536;
const MAXIMUM_REDIRECT_BYTES: usize = 256 * 1024;

type Fields = Vec<(String, Vec<u8>, bool)>;

enum Invocation {
    Header(u64, usize, String, String, Fields),
    Redirect(u64, String, String, u16, String, String, usize),
}

enum CallbackReply {
    Header(Vec<Edit>),
    Redirect(RedirectDecision),
}

type Reply = Result<CallbackReply, PyErr>;

enum Edit {
    Append(RequestHeader),
    Set(RequestHeader),
    Remove(String),
}

#[derive(Default)]
struct State {
    closed: bool,
    serial: u64,
    pending: Option<Invocation>,
    reply: Option<(u64, oneshot::Sender<Reply>)>,
    limits: Option<(usize, usize)>,
}

#[derive(Default)]
pub(super) struct Owner {
    state: Mutex<State>,
    changed: Notify,
}

impl Owner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn close(&self) {
        let mut state = self.state();
        state.closed = true;
        state.pending = None;
        state.reply = None;
        drop(state);
        self.changed.notify_waiters();
    }

    pub(super) async fn run(
        self: &Arc<Self>,
        index: usize,
        context: &mut HeaderHookContext<'_>,
        trailers: (usize, usize),
    ) -> Result<(), HeaderHookError> {
        let mut guard = Guard(Some(Arc::clone(self)));
        let (send, receive) = oneshot::channel();
        let limits = {
            let mut state = self.state();
            if state.closed || state.reply.is_some() {
                return Err(closed());
            }
            // Prepared-body metadata can exceed the caller-input allowance.
            // Keep its initial ceiling across callbacks instead of granting growth.
            let limits = *state
                .limits
                .get_or_insert_with(|| field_limits(context.headers(), trailers));
            bounded(context.headers(), trailers, limits)?;
            state.serial = state.serial.checked_add(1).ok_or_else(closed)?;
            state.pending = Some(Invocation::Header(
                state.serial,
                index,
                context.method().to_string(),
                context.uri().to_string(),
                context
                    .headers()
                    .iter()
                    .map(|header| {
                        (
                            header.name().to_owned(),
                            header.value().to_vec(),
                            header.is_sensitive(),
                        )
                    })
                    .collect(),
            ));
            state.reply = Some((state.serial, send));
            limits
        };
        self.changed.notify_waiters();
        let edits = receive
            .await
            .map_err(|_| closed())?
            .map_err(HeaderHookError::new)?;
        let CallbackReply::Header(edits) = edits else {
            return Err(closed());
        };
        if self.state().closed {
            return Err(closed());
        }
        for edit in edits {
            match edit {
                Edit::Append(header) => context.append(header)?,
                Edit::Set(header) => context.set(header)?,
                Edit::Remove(name) => context.remove(&name)?,
            }
            bounded(context.headers(), trailers, limits)?;
        }
        guard.0 = None;
        Ok(())
    }

    pub(super) async fn redirect(
        self: &Arc<Self>,
        attempt: &RedirectAttempt<'_>,
    ) -> Result<RedirectDecision, RedirectCallbackError> {
        let mut guard = Guard(Some(Arc::clone(self)));
        let size = [
            attempt.from_url().as_str(),
            attempt.to_url().as_str(),
            attempt.method().as_str(),
            attempt.next_method().as_str(),
        ]
        .iter()
        .try_fold(0_usize, |size, value| size.checked_add(value.len()));
        if size.is_none_or(|size| size > MAXIMUM_REDIRECT_BYTES) {
            return Err(RedirectCallbackError::new(std::io::Error::other(
                "redirect callback metadata limit",
            )));
        }
        let (send, receive) = oneshot::channel();
        {
            let mut state = self.state();
            if state.closed || state.reply.is_some() {
                return Err(redirect_closed());
            }
            state.serial = state.serial.checked_add(1).ok_or_else(redirect_closed)?;
            state.pending = Some(Invocation::Redirect(
                state.serial,
                attempt.from_url().as_str().to_owned(),
                attempt.to_url().as_str().to_owned(),
                attempt.status().as_u16(),
                attempt.method().as_str().to_owned(),
                attempt.next_method().as_str().to_owned(),
                attempt.hop(),
            ));
            state.reply = Some((state.serial, send));
        }
        self.changed.notify_waiters();
        let reply = receive
            .await
            .map_err(|_| redirect_closed())?
            .map_err(RedirectCallbackError::new)?;
        if self.state().closed {
            return Err(redirect_closed());
        }
        let CallbackReply::Redirect(decision) = reply else {
            return Err(redirect_closed());
        };
        guard.0 = None;
        Ok(decision)
    }

    fn complete(&self, serial: u64, reply: Reply) -> PyResult<()> {
        let mut state = self.state();
        if state.closed || state.reply.as_ref().is_none_or(|(id, _)| *id != serial) {
            return Err(error::input("header_hook_closed"));
        }
        let Some((_, send)) = state.reply.take() else {
            return Err(error::input("header_hook_closed"));
        };
        send.send(reply)
            .map_err(|_| error::input("header_hook_closed"))
    }
}

fn closed() -> HeaderHookError {
    HeaderHookError::new(std::io::Error::other("header callback closed"))
}

fn redirect_closed() -> RedirectCallbackError {
    RedirectCallbackError::new(std::io::Error::other("redirect callback closed"))
}

fn field_limits(headers: &[RequestHeader], trailers: (usize, usize)) -> (usize, usize) {
    (
        headers.len().saturating_add(trailers.0).max(MAXIMUM_FIELDS),
        headers
            .iter()
            .fold(trailers.1, |size, header| {
                size.saturating_add(header.name().len())
                    .saturating_add(header.value().len())
            })
            .max(MAXIMUM_BYTES),
    )
}

fn bounded(
    headers: &[RequestHeader],
    trailers: (usize, usize),
    limits: (usize, usize),
) -> Result<(), HeaderHookError> {
    let bytes = headers.iter().try_fold(trailers.1, |size, header| {
        size.checked_add(header.name().len())?
            .checked_add(header.value().len())
    });
    if headers.len().saturating_add(trailers.0) > limits.0
        || bytes.is_none_or(|size| size > limits.1)
    {
        return Err(HeaderHookError::new(std::io::Error::other(
            "header callback field limit",
        )));
    }
    Ok(())
}

pub(super) struct Guard(pub(super) Option<Arc<Owner>>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(owner) = &self.0 {
            owner.close();
        }
    }
}

#[pyclass]
pub(super) struct NativeHeaderHooks {
    pub(super) owner: Arc<Owner>,
    pub(super) count: usize,
    pub(super) redirects: bool,
}

#[pymethods]
impl NativeHeaderHooks {
    #[new]
    #[pyo3(signature = (count, redirects=false))]
    fn new(count: usize, redirects: bool) -> PyResult<Self> {
        if (count == 0 && !redirects) || count > MAXIMUM_FIELDS {
            return Err(error::input("header_hook_limit"));
        }
        Ok(Self {
            owner: Arc::default(),
            count,
            redirects,
        })
    }

    fn next<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.owner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            loop {
                let changed = owner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let mut state = owner.state();
                    if state.closed {
                        return Ok(None);
                    }
                    if let Some(invocation) = state.pending.take() {
                        return Python::attach(|py| {
                            let value = match invocation {
                                Invocation::Header(id, index, method, uri, fields) => {
                                    let fields = fields
                                        .into_iter()
                                        .map(|(name, value, sensitive)| {
                                            (name, PyBytes::new(py, &value).unbind(), sensitive)
                                        })
                                        .collect::<Vec<_>>();
                                    (id, index, method, uri, fields)
                                        .into_pyobject(py)?
                                        .into_any()
                                        .unbind()
                                }
                                Invocation::Redirect(id, from, to, status, method, next, hop) => {
                                    (id, "redirect", from, to, status, method, next, hop)
                                        .into_pyobject(py)?
                                        .into_any()
                                        .unbind()
                                }
                            };
                            Ok(Some(value))
                        });
                    }
                }
                changed.await;
            }
        })
    }

    fn terminal<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.owner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            loop {
                let changed = owner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if owner.state().closed {
                    return Ok(());
                }
                changed.await;
            }
        })
    }

    fn complete(&self, id: u64, edits: &Bound<'_, PyList>) -> PyResult<()> {
        if edits.len() > MAXIMUM_FIELDS {
            return Err(error::input("header_hook_edit_limit"));
        }
        let mut remaining = MAXIMUM_BYTES;
        let mut owned = Vec::with_capacity(edits.len());
        for edit in edits.iter() {
            let (operation, name, value, sensitive): (
                Bound<'_, PyString>,
                Bound<'_, PyString>,
                Bound<'_, PyBytes>,
                Bound<'_, PyBool>,
            ) = edit
                .extract()
                .map_err(|_| error::input("invalid_header_hook_edit"))?;
            let name = name
                .to_str()
                .map_err(|_| error::input("invalid_header_hook_edit"))?;
            remaining = remaining
                .checked_sub(name.len())
                .and_then(|size| size.checked_sub(value.as_bytes().len()))
                .ok_or_else(|| error::input("header_hook_edit_limit"))?;
            let header = || {
                let header = RequestHeader::new(name.to_owned(), value.as_bytes());
                if sensitive.is_true() {
                    header.sensitive()
                } else {
                    header
                }
            };
            owned.push(match operation.to_str()? {
                "append" => Edit::Append(header()),
                "set" => Edit::Set(header()),
                "remove" if value.as_bytes().is_empty() && !sensitive.is_true() => {
                    Edit::Remove(name.to_owned())
                }
                _ => return Err(error::input("invalid_header_hook_edit")),
            });
        }
        self.owner.complete(id, Ok(CallbackReply::Header(owned)))
    }

    fn complete_redirect(&self, id: u64, decision: &str) -> PyResult<()> {
        let decision = match decision {
            "follow" => RedirectDecision::Follow,
            "stop" => RedirectDecision::Stop,
            "reject" => RedirectDecision::Reject,
            _ => return Err(error::input("invalid_redirect_decision")),
        };
        self.owner
            .complete(id, Ok(CallbackReply::Redirect(decision)))
    }

    fn fail(&self, id: u64, exception: Bound<'_, PyAny>) -> PyResult<()> {
        if !exception.is_instance_of::<pyo3::exceptions::PyBaseException>() {
            return Err(error::input("invalid_header_hook_exception"));
        }
        self.owner.complete(id, Err(PyErr::from_value(exception)))
    }

    fn abort(&self) {
        self.owner.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_is_single_use_and_dropping_an_owner_rejects_late_replies() -> PyResult<()> {
        Python::initialize();
        let owner = Arc::new(Owner::default());
        let (send, mut receive) = oneshot::channel();
        owner.state().reply = Some((7, send));
        assert!(
            owner
                .complete(6, Ok(CallbackReply::Header(Vec::new())))
                .is_err()
        );
        owner.complete(7, Ok(CallbackReply::Header(Vec::new())))?;
        assert!(receive.try_recv().is_ok());
        assert!(
            owner
                .complete(7, Ok(CallbackReply::Header(Vec::new())))
                .is_err()
        );
        let (send, mut receive) = oneshot::channel();
        owner.state().reply = Some((8, send));
        drop(Guard(Some(Arc::clone(&owner))));
        assert!(owner.state().closed);
        assert!(receive.try_recv().is_err());
        assert!(
            owner
                .complete(8, Ok(CallbackReply::Header(Vec::new())))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn prepared_metadata_preserves_initial_capacity_without_granting_growth() {
        let mut headers = vec![RequestHeader::new("X", "a"); MAXIMUM_FIELDS];
        headers.push(RequestHeader::new("content-type", "text/plain"));
        let trailers = (1, MAXIMUM_BYTES);
        let limits = field_limits(&headers, trailers);
        assert!(bounded(&headers, trailers, limits).is_ok());

        headers.push(RequestHeader::new("X-Extra", "b"));
        assert!(bounded(&headers, trailers, limits).is_err());
        headers.truncate(MAXIMUM_FIELDS + 1);
        headers[0] = RequestHeader::new("X", "longer");
        assert!(bounded(&headers, trailers, limits).is_err());
    }

    #[test]
    fn completion_bounds_edits_and_resulting_fields_include_trailers() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let hooks = NativeHeaderHooks::new(1, false)?;
            let edit = ("append", "X", PyBytes::new(py, b"a"), false);
            let too_many = PyList::new(py, std::iter::repeat_n(edit, MAXIMUM_FIELDS + 1))?;
            assert!(hooks.complete(1, &too_many).is_err());
            let oversized = PyList::new(
                py,
                [("set", "X", PyBytes::new(py, &vec![0; MAXIMUM_BYTES]), false)],
            )?;
            assert!(hooks.complete(1, &oversized).is_err());
            let headers = vec![RequestHeader::new("X", "a"); MAXIMUM_FIELDS];
            assert!(bounded(&headers, (0, 0), (MAXIMUM_FIELDS, MAXIMUM_BYTES)).is_ok());
            assert!(bounded(&headers, (1, 0), (MAXIMUM_FIELDS, MAXIMUM_BYTES)).is_err());
            assert!(
                bounded(
                    &[RequestHeader::new("X", "a")],
                    (0, MAXIMUM_BYTES - 1),
                    (MAXIMUM_FIELDS, MAXIMUM_BYTES)
                )
                .is_err()
            );
            Ok(())
        })
    }

    #[test]
    fn redirect_only_owner_requires_explicit_decisions_and_one_reply() -> PyResult<()> {
        Python::initialize();
        assert!(NativeHeaderHooks::new(0, false).is_err());
        let hooks = NativeHeaderHooks::new(0, true)?;
        let (send, mut receive) = oneshot::channel();
        hooks.owner.state().reply = Some((1, send));
        assert!(hooks.complete_redirect(1, "FOLLOW").is_err());
        hooks.complete_redirect(1, "stop")?;
        assert!(matches!(
            receive.try_recv(),
            Ok(Ok(CallbackReply::Redirect(RedirectDecision::Stop)))
        ));
        assert!(hooks.complete_redirect(1, "follow").is_err());
        Ok(())
    }
}
