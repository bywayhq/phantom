//! Blocking state work keeps its admission reservation until actual completion.

use std::sync::Arc;

use super::{Outcome, Target, global};
use crate::{
    error::Failure,
    state_transfer::{Input, ResultData},
};

pub(crate) fn submit(client: u64, input: Input) -> Result<u64, Failure> {
    let global = global()?;
    let mut state = global.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let owner = state
        .clients
        .get(&client)
        .ok_or_else(|| Failure::new("client_closed"))?;
    if owner.closing {
        return Err(Failure::new("client_closed"));
    }
    let native = owner.client.clone();
    let (id, mut cancel) = state.reserve(Target::StateTransfer(client))?;
    drop(state);
    // Unlike an I/O future, dropping a blocking job cannot stop a commit. Keep
    // custody until it exits, even when the caller abandons its result.
    let work = global.runtime.spawn_blocking(move || {
        if cancel.try_recv().is_ok() {
            return Err(Failure::new("cancelled"));
        }
        Ok(Outcome::StateTransfer(crate::state_transfer::execute(
            &native, input,
        )))
    });
    global.runtime.spawn(async move {
        global.finish(
            id,
            work.await.unwrap_or_else(|_| Err(Failure::new("internal"))),
        );
    });
    Ok(id)
}

pub(crate) fn result(id: u64) -> Result<Arc<ResultData>, Failure> {
    let state = global()?.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let operation = state
        .operations
        .get(&id)
        .ok_or_else(|| Failure::new("invalid_handle"))?;
    if !matches!(operation.target, Target::StateTransfer(_))
        || !operation.finished
        || !operation.delivered
    {
        return Err(Failure::new("operation_pending"));
    }
    operation
        .state_transfer
        .clone()
        .ok_or_else(|| Failure::new("invalid_handle"))
}
