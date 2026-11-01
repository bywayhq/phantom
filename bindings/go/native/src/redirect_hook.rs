//! Owned redirect proposals for the request's calling Go goroutine.

pub(crate) struct Invocation {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) method: String,
    pub(crate) next_method: String,
    pub(crate) status: u16,
    pub(crate) hop: usize,
}
