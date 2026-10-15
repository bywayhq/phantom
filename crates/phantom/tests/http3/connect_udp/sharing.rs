//! Shared outer CONNECT-UDP sessions.

mod auth_reset;
mod clear;
mod native;
mod pressure;
mod python_peer;
mod stream_limit;
mod ticket_clear;

async fn checked<F>(future: F) -> super::TestResult<()>
where
    F: std::future::Future<Output = super::TestResult<()>>,
{
    use futures_util::FutureExt;
    match std::panic::AssertUnwindSafe(future).catch_unwind().await {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("CONNECT-UDP sharing assertion panicked");
            Err(std::io::Error::other(message.to_owned()).into())
        }
    }
}
