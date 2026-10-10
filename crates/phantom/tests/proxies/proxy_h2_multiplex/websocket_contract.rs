use std::{io, net::Ipv4Addr, time::Duration};

use tokio::{
    net::TcpListener,
    time::{sleep, timeout},
};

use super::{
    TestIdentity, TestResult, chromium_profile, client, finish_websocket_exchange,
    peer_contract::{TaskProbe, TaskRole},
    seen, spawn_proxy_fixture, websocket_origin,
};

enum Cancellation {
    Failure,
    Drop,
    Unpolled,
    Healthy,
}

async fn websocket_cancellation(kind: Cancellation) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let probe = TaskProbe::default();
    let fixture = spawn_proxy_fixture(&identity, None, Some(probe.clone())).await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let peer = probe.spawn(
        TaskRole::WebSocketOrigin,
        websocket_origin::serve_plaintext_h1_echo(listener),
    );
    let client = client(chromium_profile(), &identity, &identity, fixture.address)?;
    let mut socket = timeout(
        Duration::from_secs(5),
        client
            .websocket(&format!("ws://{address}/socket"))?
            .connect(),
    )
    .await??;
    timeout(
        Duration::from_secs(5),
        socket.send(phantom::WebSocketMessage::Text("hello".into())),
    )
    .await??;
    assert_eq!(
        timeout(Duration::from_secs(5), socket.receive()).await??,
        phantom::WebSocketMessage::Text("echo:hello".into())
    );
    let records = seen(&fixture.log);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].method, http::Method::CONNECT);
    assert_eq!(records[0].authority, address.to_string());
    assert!(!peer.is_finished());
    assert!(probe.live().contains(&TaskRole::WebSocketOrigin));
    match kind {
        Cancellation::Failure => {
            let error = finish_websocket_exchange(
                Err(
                    io::Error::new(io::ErrorKind::PermissionDenied, "caller after actual echo")
                        .into(),
                ),
                peer,
            )
            .await
            .err()
            .ok_or("WebSocket caller error disappeared")?;
            assert_eq!(
                error
                    .downcast_ref::<io::Error>()
                    .ok_or("WebSocket caller type disappeared")?
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        Cancellation::Drop => drop(peer),
        Cancellation::Unpolled => drop(finish_websocket_exchange(Ok(()), peer)),
        Cancellation::Healthy => {
            let close = phantom::WebSocketCloseFrame::new(1000, "done")?;
            timeout(Duration::from_secs(5), socket.close(Some(close))).await??;
            timeout(Duration::from_secs(5), socket.receive()).await??;
            drop(socket);
            let (head, frame) = timeout(
                Duration::from_secs(5),
                finish_websocket_exchange(Ok(()), peer),
            )
            .await??;
            assert!(head.starts_with(b"GET /socket HTTP/1.1\r\n"));
            assert_eq!(frame.opcode, 1);
            assert_eq!(frame.payload, b"hello");
            probe.backup().await?;
            drop(fixture);
            drop(client);
            return Ok(());
        }
    }
    sleep(Duration::from_millis(150)).await;
    let remaining = probe.live();
    probe.backup().await?;
    drop(socket);
    drop(fixture);
    drop(client);
    assert!(
        !remaining.contains(&TaskRole::WebSocketOrigin),
        "actual WebSocket origin survived caller cancellation before backup"
    );
    Ok(())
}

#[tokio::test]
async fn a_websocket_caller_failure_stops_its_actual_origin() -> TestResult<()> {
    websocket_cancellation(Cancellation::Failure).await
}
#[tokio::test]
async fn eager_websocket_peer_drop_stops_its_actual_origin() -> TestResult<()> {
    websocket_cancellation(Cancellation::Drop).await
}
#[tokio::test]
async fn an_unpolled_websocket_finish_owns_its_actual_origin() -> TestResult<()> {
    websocket_cancellation(Cancellation::Unpolled).await
}
#[tokio::test]
async fn a_healthy_websocket_close_keeps_actual_wire_observations() -> TestResult<()> {
    websocket_cancellation(Cancellation::Healthy).await
}
