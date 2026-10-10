use std::{error::Error, net::Ipv4Addr};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use super::super::{
    ConnectionPeer, EstablishedTunnel, TestResult, finish_with_cleanup, relay_result,
    send_http2_data, spawn_http2_relay,
};
use super::DEADLINE;

struct H2Relay {
    tunnel: EstablishedTunnel<()>,
    server: ConnectionPeer<TestResult<()>>,
    client: ConnectionPeer<TestResult<()>>,
    sender: ::http2::client::SendRequest<Bytes>,
    request: ::http2::SendStream<Bytes>,
    response: ::http2::RecvStream,
    origin: TcpStream,
}

impl H2Relay {
    async fn ready() -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (client_io, server_io) = duplex(64 * 1024);
        let (established, received) = oneshot::channel();
        let server = ConnectionPeer::spawn(async move {
            let mut connection = ::http2::server::Builder::new()
                .handshake::<_, Bytes>(server_io)
                .await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("CONNECT request was not accepted")??;
            assert_eq!(request.method(), http::Method::CONNECT);
            let send = respond.send_response(http::Response::new(()), false)?;
            let upstream = TcpStream::connect(address).await?;
            let mut peers = Vec::new();
            spawn_http2_relay(request.into_body(), send, upstream, &mut peers);
            established
                .send(EstablishedTunnel {
                    observed: (),
                    peers,
                })
                .map_err(|_| "CONNECT observation receiver was dropped")?;

            while let Some(accepted) = connection.accept().await {
                match accepted {
                    Ok(_) => return Err("unexpected second CONNECT stream".into()),
                    Err(error) => return relay_result(Err(error.into())),
                }
            }
            TestResult::Ok(())
        });
        let (sender, connection) = ::http2::client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await?;
        let client =
            ConnectionPeer::spawn(
                async move { relay_result(connection.await.map_err(Into::into)) },
            );
        let mut sender = sender.ready().await?;
        let (response, mut request) = sender.send_request(
            http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("relay.test:443")
                .body(())?,
            false,
        )?;
        let response = response.await?;
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut response = response.into_body();
        let (mut origin, _) = listener.accept().await?;
        let tunnel = received.await?;

        request.send_data(Bytes::from_static(b"request"), false)?;
        let mut observed = [0_u8; 7];
        origin.read_exact(&mut observed).await?;
        assert_eq!(&observed, b"request");
        origin.write_all(b"response").await?;
        let mut reply = Vec::new();
        while reply.len() < 8 {
            let observed = response.data().await.ok_or("relay response was absent")??;
            response.flow_control().release_capacity(observed.len())?;
            reply.extend_from_slice(&observed);
        }
        assert_eq!(&reply, b"response");

        Ok(Self {
            tunnel,
            server,
            client,
            sender,
            request,
            response,
            origin,
        })
    }

    async fn reset_and_finish(mut self, reason: ::http2::Reason) -> TestResult<()> {
        self.request.send_reset(reason);
        timeout(DEADLINE, async {
            while !self.tunnel.peers[0].is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        // The origin EOF follows an already-observed reset, so the outgoing
        // relay must retain that cause instead of attempting DATA on it.
        self.origin.shutdown().await?;
        timeout(DEADLINE, async {
            while !self.tunnel.peers[1].is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        self.finish().await
    }

    async fn finish(self) -> TestResult<()> {
        let result = self.tunnel.cancel().await;

        drop(self.request);
        drop(self.response);
        drop(self.sender);
        let client = self.client.stop().await;
        let server = self.server.stop().await;
        finish_with_cleanup(result, finish_with_cleanup(client, server))
    }
}

#[tokio::test]
async fn sending_after_a_local_end_keeps_the_original_typed_misuse() -> TestResult<()> {
    let mut relay = timeout(DEADLINE, H2Relay::ready()).await??;
    send_http2_data(&mut relay.request, Bytes::new(), true)?;
    let result = send_http2_data(&mut relay.request, Bytes::new(), false);
    relay.origin.shutdown().await?;
    relay.finish().await?;

    let error = result
        .err()
        .ok_or("local repeated-send misuse was accepted")?;
    let error = error
        .downcast_ref::<::http2::Error>()
        .ok_or("original typed HTTP/2 misuse was lost")?;
    assert_eq!(error.reason(), None);
    assert!(!error.is_remote());
    assert!(error.get_io().is_none());
    Ok(())
}

#[tokio::test]
async fn a_remote_cancel_before_origin_eof_finishes_the_actual_relay() -> TestResult<()> {
    timeout(DEADLINE, H2Relay::ready())
        .await??
        .reset_and_finish(::http2::Reason::CANCEL)
        .await
}

#[tokio::test]
async fn an_unrelated_remote_reset_keeps_its_original_protocol_cause() -> TestResult<()> {
    let error = timeout(DEADLINE, H2Relay::ready())
        .await??
        .reset_and_finish(::http2::Reason::INTERNAL_ERROR)
        .await
        .err()
        .ok_or("unrelated remote reset was accepted")?;

    let mut cause: &(dyn Error + 'static) = error.as_ref();
    loop {
        if let Some(error) = cause.downcast_ref::<::http2::Error>() {
            assert_eq!(error.reason(), Some(::http2::Reason::INTERNAL_ERROR));
            assert!(error.is_remote());
            return Ok(());
        }
        cause = cause
            .source()
            .ok_or("original HTTP/2 reset cause was lost")?;
    }
}
