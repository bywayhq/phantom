//! Sizes of async functions' futures, for tests that bound them.
//!
//! An async function's future holds each future it awaits inline, so the
//! future of an entry point is at least as large as the largest path through
//! everything it awaits. A debug build also builds each callee's future in
//! its caller's poll frame before moving it into place, so the stack a call
//! needs grows with these sizes along the deepest call chain. A test thread
//! has a 2 MiB stack, and a debug build that outgrows it aborts the test
//! process.
//!
//! An async function also holds a future it takes by value twice, as the
//! argument and as the awaited value. A wrapper that encloses a large
//! operation, such as one that traces a whole connection setup, takes it as
//! `Pin<&mut F>`, which the caller makes with `std::pin::pin!`.
//!
//! A future over [`FUTURE_BUDGET`](crate::future_size::FUTURE_BUDGET), or a
//! setup future over
//! [`SETUP_FUTURE_BUDGET`](crate::future_size::SETUP_FUTURE_BUDGET), should
//! box a cold or large branch (`Box::pin`) instead of holding it inline.

/// The largest future, in bytes, that a function on a request path may
/// return in a debug build.
///
/// It leaves about a quarter of headroom over the largest measured request
/// future, so a small change or a toolchain upgrade does not fail the check.
pub const FUTURE_BUDGET: usize = 20 * 1024;

/// The largest future, in bytes, that opening a connection may return in a
/// debug build, whether through a connector or through a pool.
///
/// It leaves about a quarter of headroom over the largest setup future
/// measured, on Windows only. Setup runs below a request's future, so the
/// two budgets together bound the stack a new connection needs.
pub const SETUP_FUTURE_BUDGET: usize = 12 * 1024;

/// A function whose return value has a size known without calling it.
///
/// Implemented for every function and closure of up to 20 arguments.
pub trait ReturnSize<Arguments> {
    /// Returns the size of the function's return value, such as an async
    /// function's future.
    fn return_size(&self) -> usize;
}

macro_rules! return_size {
    ($($argument:ident),*) => {
        impl<Function, Output, $($argument),*> ReturnSize<($($argument,)*)> for Function
        where
            Function: FnOnce($($argument),*) -> Output,
        {
            fn return_size(&self) -> usize {
                std::mem::size_of::<Output>()
            }
        }
    };
}

return_size!();
return_size!(A);
return_size!(A, B);
return_size!(A, B, C);
return_size!(A, B, C, D);
return_size!(A, B, C, D, E);
return_size!(A, B, C, D, E, F);
return_size!(A, B, C, D, E, F, G);
return_size!(A, B, C, D, E, F, G, H);
return_size!(A, B, C, D, E, F, G, H, I);
return_size!(A, B, C, D, E, F, G, H, I, J);
return_size!(A, B, C, D, E, F, G, H, I, J, K);
return_size!(A, B, C, D, E, F, G, H, I, J, K, L);
return_size!(A, B, C, D, E, F, G, H, I, J, K, L, M);
return_size!(A, B, C, D, E, F, G, H, I, J, K, L, M, N);
return_size!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O);
return_size!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P);
return_size!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q);
return_size!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R);
return_size!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S);
return_size!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T);

/// Returns the size of the future that an async function returns, without
/// calling it.
///
/// ```
/// use phantom_testkit::future_size::future_size;
///
/// async fn holds_a_buffer(length: usize) -> usize {
///     let buffer = [0_u8; 1024];
///     std::future::ready(()).await;
///     buffer.len().min(length)
/// }
///
/// assert!(future_size(&holds_a_buffer) >= 1024);
/// ```
pub fn future_size<Arguments>(function: &impl ReturnSize<Arguments>) -> usize {
    function.return_size()
}

/// Asserts that each named future is within [`FUTURE_BUDGET`].
///
/// Prints every size, largest first, which `cargo test -- --nocapture`
/// shows.
///
/// # Panics
///
/// Panics, naming each one, when a future exceeds the budget.
pub fn assert_within_budget(futures: &[(&str, usize)]) {
    assert_within(FUTURE_BUDGET, futures);
}

/// Asserts that each named future is within `budget` bytes, such as
/// [`SETUP_FUTURE_BUDGET`].
///
/// Prints every size, largest first, which `cargo test -- --nocapture`
/// shows.
///
/// # Panics
///
/// Panics, naming each one, when a future exceeds `budget`.
pub fn assert_within(budget: usize, futures: &[(&str, usize)]) {
    let mut sorted = futures.to_vec();
    sorted.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(right.0)));
    for (name, size) in &sorted {
        println!("{size:>8} bytes  {name}");
    }
    let over: Vec<_> = sorted.iter().filter(|(_, size)| *size > budget).collect();
    assert!(
        over.is_empty(),
        "futures over the {budget}-byte budget: {over:?}"
    );
}
