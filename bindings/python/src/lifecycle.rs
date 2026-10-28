//! Binding admission includes file preparation before the core request begins.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError, Weak},
};

use pyo3::PyResult;
use tokio::sync::Notify;

use crate::{
    error, event_source::Owner as EventSourceOwner, response::BodyOwner,
    websocket::Owner as SocketOwner,
};

enum Owner {
    Response(Weak<BodyOwner>),
    Socket(Weak<SocketOwner>),
    EventSource(Weak<EventSourceOwner>),
}

impl Owner {
    fn key(&self) -> usize {
        match self {
            Self::Response(owner) => owner.as_ptr().addr(),
            Self::Socket(owner) => owner.as_ptr().addr(),
            Self::EventSource(owner) => owner.as_ptr().addr(),
        }
    }

    fn abort(self) {
        match self {
            Self::Response(owner) => {
                if let Some(owner) = owner.upgrade() {
                    owner.abort();
                }
            }
            Self::Socket(owner) => {
                if let Some(owner) = owner.upgrade() {
                    owner.abort();
                }
            }
            Self::EventSource(owner) => {
                if let Some(owner) = owner.upgrade() {
                    owner.abort();
                }
            }
        }
    }
}

#[derive(Default, PartialEq, Eq)]
enum AdmissionState {
    #[default]
    Open,
    Draining,
    Aborted,
}

#[derive(Default)]
struct State {
    admission: AdmissionState,
    preparing: usize,
    owners: HashMap<usize, Owner>,
}

#[derive(Default)]
pub(super) struct Lifecycle {
    state: Mutex<State>,
    changed: Notify,
}

impl Lifecycle {
    pub(super) fn admit(self: &Arc<Self>, operation: &'static str) -> PyResult<Admission> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.admission != AdmissionState::Open {
            return Err(error::NativeError::new_err((
                operation,
                "client_closed",
                None::<String>,
                None::<String>,
            )));
        }
        state.preparing = state
            .preparing
            .checked_add(1)
            .ok_or_else(|| error::input("request_capacity"))?;
        Ok(Admission(Arc::clone(self)))
    }

    pub(super) fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .admission
            != AdmissionState::Open
    }

    pub(super) fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.admission == AdmissionState::Open {
            state.admission = AdmissionState::Draining;
        }
    }

    pub(super) fn abort(&self) {
        let owners = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.admission = AdmissionState::Aborted;
            std::mem::take(&mut state.owners)
        };
        self.changed.notify_waiters();
        for owner in owners.into_values() {
            owner.abort();
        }
    }

    pub(super) async fn drained(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .preparing
                == 0
            {
                return;
            }
            changed.await;
        }
    }

    pub(super) fn response(self: &Arc<Self>, owner: Weak<BodyOwner>) -> Registration {
        self.register(Owner::Response(owner))
    }

    pub(super) fn socket(self: &Arc<Self>, owner: Weak<SocketOwner>) -> Registration {
        self.register(Owner::Socket(owner))
    }

    pub(super) fn event_source(self: &Arc<Self>, owner: Weak<EventSourceOwner>) -> Registration {
        self.register(Owner::EventSource(owner))
    }

    fn register(self: &Arc<Self>, owner: Owner) -> Registration {
        let key = owner.key();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.admission == AdmissionState::Aborted {
            drop(state);
            owner.abort();
        } else {
            state.owners.insert(key, owner);
        }
        Registration {
            lifecycle: Arc::downgrade(self),
            key,
        }
    }
}

pub(super) struct Admission(Arc<Lifecycle>);

impl Admission {
    pub(super) fn lifecycle(&self) -> &Arc<Lifecycle> {
        &self.0
    }

    pub(super) async fn aborted(&self) {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self
                .0
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .admission
                == AdmissionState::Aborted
            {
                return;
            }
            changed.await;
        }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.preparing -= 1;
        drop(state);
        self.0.changed.notify_waiters();
    }
}

pub(super) struct Registration {
    lifecycle: Weak<Lifecycle>,
    key: usize,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(lifecycle) = self.lifecycle.upgrade() {
            lifecycle
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .owners
                .remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Lifecycle;
    use std::{sync::Arc, time::Duration};

    #[test]
    fn graceful_close_waits_for_admitted_preparation_without_aborting_it()
    -> Result<(), Box<dyn std::error::Error>> {
        pyo3::Python::initialize();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        runtime.block_on(async {
            let lifecycle = Arc::new(Lifecycle::default());
            let preparation = lifecycle.admit("request")?;
            lifecycle.close();
            assert!(lifecycle.is_closed());
            assert!(lifecycle.admit("request").is_err());
            assert!(
                tokio::time::timeout(Duration::ZERO, lifecycle.drained())
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(Duration::ZERO, preparation.aborted())
                    .await
                    .is_err()
            );
            drop(preparation);
            tokio::time::timeout(Duration::from_secs(1), lifecycle.drained()).await?;
            Ok(())
        })
    }

    #[test]
    fn abort_wakes_preparation_and_keeps_its_lease_until_it_exits()
    -> Result<(), Box<dyn std::error::Error>> {
        pyo3::Python::initialize();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        runtime.block_on(async {
            let lifecycle = Arc::new(Lifecycle::default());
            let preparation = lifecycle.admit("request")?;
            lifecycle.abort();
            tokio::time::timeout(Duration::from_secs(1), preparation.aborted()).await?;
            assert!(
                tokio::time::timeout(Duration::ZERO, lifecycle.drained())
                    .await
                    .is_err()
            );
            drop(preparation);
            tokio::time::timeout(Duration::from_secs(1), lifecycle.drained()).await?;
            assert!(lifecycle.admit("websocket").is_err());
            Ok(())
        })
    }
}
