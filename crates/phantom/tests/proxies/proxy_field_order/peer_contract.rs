use std::{error::Error, fmt, net::Ipv4Addr, time::Duration};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

use super::{TestResult, collect_field_heads, read_head, record_connects};

const DEADLINE: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_secs(2);
const CONNECT: &[u8] =
    b"CONNECT origin.phantom.test:443 HTTP/1.1\r\nHost: origin.phantom.test:443\r\n\r\n";
const ACCEPTED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

struct Destroyed(Option<oneshot::Sender<()>>);

impl Drop for Destroyed {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // A failed observation may leave before backup teardown.
            let _ = sender.send(());
        }
    }
}

struct Backup(AbortHandle);

impl Drop for Backup {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn connect_once(stream: &mut TcpStream) -> TestResult<()> {
    stream.write_all(CONNECT).await?;
    assert_eq!(timeout(DEADLINE, read_head(stream)).await??, ACCEPTED);
    Ok(())
}

fn spawn_recording_peer(
    listener: TcpListener,
    count: usize,
) -> (
    JoinHandle<TestResult<Vec<String>>>,
    oneshot::Receiver<()>,
    Backup,
) {
    let (sender, destroyed) = oneshot::channel();
    let server = tokio::spawn(async move {
        let _destroyed = Destroyed(Some(sender));
        record_connects(listener, 0, count).await
    });
    let backup = Backup(server.abort_handle());
    (server, destroyed, backup)
}

async fn cancellation_observation(poll_before_drop: bool) -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (server, mut destroyed, backup) = spawn_recording_peer(listener, 2);
    let mut client = TcpStream::connect(address).await?;
    if poll_before_drop {
        let (ready, observed) = oneshot::channel();
        let mut completion = Box::pin(collect_field_heads(server, async {
            connect_once(&mut client).await?;
            ready
                .send(())
                .map_err(|_| "field-order readiness observer closed")?;
            std::future::pending::<TestResult<()>>().await
        }));
        timeout(DEADLINE, async {
            tokio::select! {
                result = &mut completion => {
                    result?;
                    Err::<(), Box<dyn Error + Send + Sync>>("field-order completion ended before cancellation".into())
                }
                result = observed => Ok(result?),
            }
        }).await??;
        drop(completion);
    } else {
        connect_once(&mut client).await?;
        let completion = collect_field_heads(server, std::future::pending::<TestResult<()>>());
        drop(completion);
    }

    let captured = timeout(QUIET, &mut destroyed).await;
    let stopped = matches!(captured, Ok(Ok(())));
    // Capture before the external stream is dropped or backup abort is requested.
    // A closed observation channel is an error, never destruction evidence.
    if captured.is_err() {
        backup.0.abort();
        timeout(DEADLINE, &mut destroyed).await??;
    }
    drop(client);
    drop(backup);

    if let Ok(result) = captured {
        result?;
    }
    assert!(
        stopped,
        "cancelled field-order caller retained its actual CONNECT recorder"
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_a_driven_field_order_caller_destroys_its_connect_recorder() -> TestResult<()> {
    cancellation_observation(true).await
}

#[tokio::test]
async fn dropping_an_unpolled_field_order_completion_destroys_its_transferred_recorder()
-> TestResult<()> {
    cancellation_observation(false).await
}

#[derive(Debug)]
struct CallerFailure;

impl fmt::Display for CallerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled field-order caller failed after CONNECT")
    }
}

impl Error for CallerFailure {}

#[derive(Debug)]
struct RecorderFailure;

impl fmt::Display for RecorderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled field-order recorder failed after CONNECT")
    }
}

impl Error for RecorderFailure {}

#[tokio::test]
async fn a_failed_caller_retains_its_completed_typed_connect_recorder_failure() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let heads = record_connects(listener, 0, 1).await?;
        assert_eq!(heads, [String::from_utf8(CONNECT.to_vec())?]);
        Err::<Vec<String>, _>(Box::new(RecorderFailure) as Box<dyn Error + Send + Sync>)
    });
    let backup = Backup(server.abort_handle());
    let mut client = TcpStream::connect(address).await?;
    connect_once(&mut client).await?;
    timeout(DEADLINE, async {
        while !server.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    // The typed primary is injected only after the actual literal exchange and
    // observed task completion. Both original error objects must be retained.
    let error = collect_field_heads(server, async { Err(CallerFailure.into()) })
        .await
        .err()
        .ok_or("failed field-order caller succeeded")?;
    drop(client);
    drop(backup);

    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("field-order caller discarded its completed recorder failure")?;
    assert!(failures.primary.downcast_ref::<CallerFailure>().is_some());
    assert!(failures.cleanup.downcast_ref::<RecorderFailure>().is_some());
    Ok(())
}

#[tokio::test]
async fn a_successful_field_order_completion_retains_both_literal_connect_heads() -> TestResult<()>
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (server, destroyed, backup) = spawn_recording_peer(listener, 2);
    let mut first = TcpStream::connect(address).await?;
    let mut second = TcpStream::connect(address).await?;
    let heads = timeout(
        DEADLINE,
        collect_field_heads(server, async {
            connect_once(&mut first).await?;
            connect_once(&mut second).await
        }),
    )
    .await??;
    timeout(DEADLINE, destroyed).await??;
    drop((first, second, backup));

    assert_eq!(
        heads,
        [
            String::from_utf8(CONNECT.to_vec())?,
            String::from_utf8(CONNECT.to_vec())?
        ]
    );
    Ok(())
}
