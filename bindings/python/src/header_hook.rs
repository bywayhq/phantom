//! Request-owned rendezvous for callbacks on the caller's Python loop.

use crate::error;
use phantom::{HeaderHookContext, HeaderHookError, RequestHeader};
use pyo3::{
    prelude::*,
    types::{PyBool, PyBytes, PyList, PyString},
};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::{Notify, oneshot};

const MAXIMUM_FIELDS: usize = 256;
const MAXIMUM_BYTES: usize = 65536;
type Fields = Vec<(String, Vec<u8>, bool)>;
type Invocation = (u64, usize, String, String, Fields);
type Reply = Result<Vec<Edit>, PyErr>;

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
        bounded(context.headers(), trailers)?;
        let (send, receive) = oneshot::channel();
        {
            let mut state = self.state();
            if state.closed || state.reply.is_some() {
                return Err(closed());
            }
            state.serial = state.serial.checked_add(1).ok_or_else(closed)?;
            state.pending = Some((
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
        }
        self.changed.notify_waiters();
        let edits = receive
            .await
            .map_err(|_| closed())?
            .map_err(HeaderHookError::new)?;
        if self.state().closed {
            return Err(closed());
        }
        for edit in edits {
            match edit {
                Edit::Append(header) => context.append(header)?,
                Edit::Set(header) => context.set(header)?,
                Edit::Remove(name) => context.remove(&name)?,
            }
            bounded(context.headers(), trailers)?;
        }
        guard.0 = None;
        Ok(())
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

fn bounded(headers: &[RequestHeader], trailers: (usize, usize)) -> Result<(), HeaderHookError> {
    let bytes = headers.iter().try_fold(trailers.1, |size, header| {
        size.checked_add(header.name().len())?
            .checked_add(header.value().len())
    });
    if headers.len().saturating_add(trailers.0) > MAXIMUM_FIELDS
        || bytes.is_none_or(|size| size > MAXIMUM_BYTES)
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
}

#[pymethods]
impl NativeHeaderHooks {
    #[new]
    fn new(count: usize) -> PyResult<Self> {
        if count == 0 || count > MAXIMUM_FIELDS {
            return Err(error::input("header_hook_limit"));
        }
        Ok(Self {
            owner: Arc::default(),
            count,
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
                    if let Some((id, index, method, uri, fields)) = state.pending.take() {
                        return Python::attach(|py| {
                            let fields = fields
                                .into_iter()
                                .map(|(name, value, sensitive)| {
                                    (name, PyBytes::new(py, &value).unbind(), sensitive)
                                })
                                .collect::<Vec<_>>();
                            Ok(Some((id, index, method, uri, fields)))
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
        self.owner.complete(id, Ok(owned))
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
        assert!(owner.complete(6, Ok(Vec::new())).is_err());
        owner.complete(7, Ok(Vec::new()))?;
        assert!(receive.try_recv().is_ok());
        assert!(owner.complete(7, Ok(Vec::new())).is_err());
        let (send, mut receive) = oneshot::channel();
        owner.state().reply = Some((8, send));
        drop(Guard(Some(Arc::clone(&owner))));
        assert!(owner.state().closed);
        assert!(receive.try_recv().is_err());
        assert!(owner.complete(8, Ok(Vec::new())).is_err());
        Ok(())
    }

    #[test]
    fn completion_bounds_edits_and_resulting_fields_include_trailers() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let hooks = NativeHeaderHooks::new(1)?;
            let edit = ("append", "X", PyBytes::new(py, b"a"), false);
            let too_many = PyList::new(py, std::iter::repeat_n(edit, MAXIMUM_FIELDS + 1))?;
            assert!(hooks.complete(1, &too_many).is_err());
            let oversized = PyList::new(
                py,
                [("set", "X", PyBytes::new(py, &vec![0; MAXIMUM_BYTES]), false)],
            )?;
            assert!(hooks.complete(1, &oversized).is_err());
            let headers = vec![RequestHeader::new("X", "a"); MAXIMUM_FIELDS];
            assert!(bounded(&headers, (0, 0)).is_ok());
            assert!(bounded(&headers, (1, 0)).is_err());
            assert!(bounded(&[RequestHeader::new("X", "a")], (0, MAXIMUM_BYTES - 1)).is_err());
            Ok(())
        })
    }
}
