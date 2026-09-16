use std::{
    num::NonZeroUsize,
    sync::{Arc, Weak},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{HttpProtocol, RequestError};

pub(super) struct AdmissionRegistry<Key> {
    entries: Vec<(Key, Weak<Admission>)>,
}

impl<Key> Default for AdmissionRegistry<Key> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<Key> AdmissionRegistry<Key>
where
    Key: Clone + Eq,
{
    pub(super) fn get(
        &mut self,
        key: &Key,
        max_active: NonZeroUsize,
        max_pending: NonZeroUsize,
    ) -> Arc<Admission> {
        self.entries
            .retain(|(_, admission)| admission.strong_count() != 0);
        if let Some(admission) = self.entries.iter().find_map(|(candidate, admission)| {
            (candidate == key).then(|| admission.upgrade()).flatten()
        }) {
            return admission;
        }

        let admission = Arc::new(Admission::new(max_active, max_pending));
        self.entries.push((key.clone(), Arc::downgrade(&admission)));
        admission
    }
}

pub(super) struct Admission {
    active: Arc<Semaphore>,
    pending: Arc<Semaphore>,
}

impl Admission {
    fn new(max_active: NonZeroUsize, max_pending: NonZeroUsize) -> Self {
        Self {
            active: Arc::new(Semaphore::new(max_active.get())),
            pending: Arc::new(Semaphore::new(max_pending.get())),
        }
    }

    pub(super) async fn admit(
        self: Arc<Self>,
        protocol: HttpProtocol,
    ) -> Result<AdmissionPermit, RequestError> {
        if let Ok(permit) = Arc::clone(&self.active).try_acquire_owned() {
            return Ok(AdmissionPermit {
                _admission: self,
                _permit: permit,
            });
        }
        let pending = Arc::clone(&self.pending)
            .try_acquire_owned()
            .map_err(|_| RequestError::capacity(protocol))?;
        let active = Arc::clone(&self.active)
            .acquire_owned()
            .await
            .map_err(|_| RequestError::capacity(protocol))?;
        drop(pending);
        Ok(AdmissionPermit {
            _admission: self,
            _permit: active,
        })
    }

    #[cfg(test)]
    pub(super) fn available_active(&self) -> usize {
        self.active.available_permits()
    }
}

pub(super) struct AdmissionPermit {
    _admission: Arc<Admission>,
    _permit: OwnedSemaphorePermit,
}

#[cfg(test)]
impl AdmissionPermit {
    pub(super) fn admission(&self) -> &Arc<Admission> {
        &self._admission
    }
}
