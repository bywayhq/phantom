use std::{
    any::Any,
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    task::Poll,
};

use phantom_profile::TcpSettings;
use tokio::net::TcpStream;

const TOKIO_IO_DISABLED_PANIC: &str = "A Tokio 1.x context was found, but IO is disabled. Call `enable_io` on the runtime builder to enable IO.";

#[derive(Debug)]
pub(crate) struct RuntimeUnavailable;

pub(crate) enum DirectConnectError {
    RuntimeUnavailable,
    Connect(std::io::Error),
}

/// Opens one TCP connection, applying the connector's profile socket options.
///
/// Without profile options the socket keeps its operating-system defaults and
/// Tokio's resolver-order connect is used unchanged.
pub(crate) async fn connect_tcp(
    host: &str,
    port: u16,
    tcp: Option<TcpSettings>,
) -> Result<TcpStream, DirectConnectError> {
    tokio::runtime::Handle::try_current().map_err(|_| DirectConnectError::RuntimeUnavailable)?;
    let stream = match tcp {
        Some(settings) => poll_tokio_io(|| crate::tcp::connect(host, port, settings)).await,
        None => poll_tokio_io(|| TcpStream::connect((host, port))).await,
    }
    .map_err(|RuntimeUnavailable| DirectConnectError::RuntimeUnavailable)?
    .map_err(DirectConnectError::Connect)?;
    #[cfg(test)]
    crate::tcp::observed::record(&stream);
    Ok(stream)
}

pub(crate) async fn poll_tokio_io<Operation, OperationFuture, Output>(
    operation: Operation,
) -> Result<Output, RuntimeUnavailable>
where
    Operation: FnOnce() -> OperationFuture,
    OperationFuture: Future<Output = Output>,
{
    let future = match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(future) => future,
        Err(payload) if is_io_disabled_panic(payload.as_ref()) => return Err(RuntimeUnavailable),
        Err(payload) => resume_unwind(payload),
    };
    let mut future = std::pin::pin!(future);

    poll_fn(
        |context| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) if is_io_disabled_panic(payload.as_ref()) => {
                Poll::Ready(Err(RuntimeUnavailable))
            }
            Err(payload) => resume_unwind(payload),
        },
    )
    .await
}

fn is_io_disabled_panic(payload: &(dyn Any + Send)) -> bool {
    payload
        .downcast_ref::<&str>()
        .is_some_and(|message| *message == TOKIO_IO_DISABLED_PANIC)
        || payload
            .downcast_ref::<String>()
            .is_some_and(|message| message == TOKIO_IO_DISABLED_PANIC)
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::{RuntimeUnavailable, poll_tokio_io};

    #[test]
    fn runtime_without_io_returns_runtime_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let result = runtime.block_on(poll_tokio_io(|| {
            tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, 9))
        }));

        assert!(matches!(result, Err(RuntimeUnavailable)));
        Ok(())
    }

    #[test]
    fn unrelated_panics_resume_unwinding() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(poll_tokio_io(|| async {
                panic!("unrelated panic");
            }))
        }));

        let payload = match result {
            Ok(_) => return Err("unrelated panic was swallowed".into()),
            Err(payload) => payload,
        };
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"unrelated panic"));
        Ok(())
    }
}
