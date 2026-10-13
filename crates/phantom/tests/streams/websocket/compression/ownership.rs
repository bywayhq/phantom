use std::{io, net::Ipv4Addr, sync::Arc, time::Duration};

use tokio::{net::TcpListener, task::AbortHandle, time::timeout};

use super::*;

async fn connected(
    owner: &mut Option<ConnectionPeer<TestResult<(Vec<u8>, ClientFrame)>>>,
) -> TestResult<phantom::WebSocket> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    *owner = Some(ConnectionPeer::spawn(transfer_peer(
        listener,
        identity.acceptor(H1_ALPN)?,
    )));
    let mut socket = test_client(&identity, false)?
        .websocket(&format!("wss://{address}/compressed"))?
        .permessage_deflate(PerMessageDeflate::new())
        .connect()
        .await?;
    assert_eq!(
        socket.receive().await?,
        WebSocketMessage::Text("hello".into())
    );
    Ok(socket)
}

async fn stopped(witness: &AbortHandle) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        while !witness.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn caller_failure_stops_the_original_compression_peer_and_keeps_its_cause() -> TestResult<()>
{
    let mut owner = None;
    let socket = match connected(&mut owner).await {
        Ok(socket) => socket,
        Err(error) => {
            let cleanup = match owner.as_mut() {
                Some(owner) => owner.shutdown().await,
                None => Ok(()),
            };
            return finish_with_cleanup(Err(error), cleanup);
        }
    };
    let witness = owner
        .as_ref()
        .ok_or("compression peer missing")?
        .abort_handle();
    assert!(!witness.is_finished());
    let token = Arc::new(());
    let primary: TestResult<()> = Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        CallerFailure {
            token: token.clone(),
        },
    )
    .into());

    let error = finish_with_cleanup(
        primary,
        owner
            .as_mut()
            .ok_or("compression peer missing")?
            .shutdown()
            .await,
    )
    .err()
    .ok_or("caller failure was discarded")?;
    let original = error
        .downcast_ref::<io::Error>()
        .ok_or("original caller I/O error missing")?;
    let payload = original
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<CallerFailure>())
        .ok_or("original caller payload missing")?;
    assert_eq!(original.kind(), io::ErrorKind::InvalidInput);
    assert!(Arc::ptr_eq(&token, &payload.token));
    stopped(&witness).await?;
    drop(socket);
    Ok(())
}

#[tokio::test]
async fn consuming_caller_deadline_leaves_the_actual_compression_peer_owned() -> TestResult<()> {
    let mut owner = None;
    let mut socket = match connected(&mut owner).await {
        Ok(socket) => socket,
        Err(error) => {
            let cleanup = match owner.as_mut() {
                Some(owner) => owner.shutdown().await,
                None => Ok(()),
            };
            return finish_with_cleanup(Err(error), cleanup);
        }
    };
    let witness = owner
        .as_ref()
        .ok_or("compression peer missing")?
        .abort_handle();
    let elapsed = timeout(Duration::ZERO, socket.receive())
        .await
        .err()
        .ok_or("compression peer unexpectedly supplied another frame")?;
    assert!(!witness.is_finished());

    let error = finish_with_cleanup(
        TestResult::<()>::Err(elapsed.into()),
        owner
            .as_mut()
            .ok_or("compression peer missing")?
            .shutdown()
            .await,
    )
    .err()
    .ok_or("caller deadline was discarded")?;
    assert!(error.is::<tokio::time::error::Elapsed>());
    stopped(&witness).await?;
    drop(socket);
    Ok(())
}

#[tokio::test]
async fn dropping_the_compression_owner_stops_its_actual_accepted_peer() -> TestResult<()> {
    let mut owner = None;
    let socket = match connected(&mut owner).await {
        Ok(socket) => socket,
        Err(error) => {
            let cleanup = match owner.as_mut() {
                Some(owner) => owner.shutdown().await,
                None => Ok(()),
            };
            return finish_with_cleanup(Err(error), cleanup);
        }
    };
    let witness = owner
        .as_ref()
        .ok_or("compression peer missing")?
        .abort_handle();
    assert!(!witness.is_finished());

    drop(owner);
    stopped(&witness).await?;
    drop(socket);
    Ok(())
}

#[derive(Debug)]
struct CallerFailure {
    token: Arc<()>,
}

impl std::fmt::Display for CallerFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("injected compression caller failure")
    }
}

impl std::error::Error for CallerFailure {}
