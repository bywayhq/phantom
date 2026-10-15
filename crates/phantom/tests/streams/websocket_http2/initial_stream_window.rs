//! The same opening stream credit on an ordinary request and a reused WebSocket.

use super::{
    Arc, Bytes, Client, ClientProfile, ConnectionPeer, Error, H2_ALPN, HttpProtocol, Method, Mutex,
    RecordingIo, Response, TcpListener, TestIdentity, TestResult, WebSocketErrorKind,
    WebSocketMessage, accept_tls, append_server_frame, bounded, finish_with_cleanup, oneshot,
    read_client_frame, tls_settings,
};
use http_body_util::BodyExt;
use phantom::profile::browser::firefox;
use std::net::Ipv4Addr;

#[tokio::test]
async fn firefox_stream_target_reaches_ordinary_and_reused_extended_connect() -> TestResult<()> {
    reused_connection(Some(12_582_912)).await
}

#[tokio::test]
async fn absent_stream_target_adds_no_credit_to_ordinary_or_reused_extended_connect()
-> TestResult<()> {
    reused_connection(None).await
}

async fn reused_connection(target: Option<u32>) -> TestResult<()> {
    let mut server = None;
    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (done_tx, done_rx) = oneshot::channel();
        server = Some(ConnectionPeer::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let stream = RecordingIo::new(stream, Arc::clone(&recorded));
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut connection = builder.handshake::<_, Bytes>(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before ordinary request")??;
            assert_eq!(request.method(), Method::GET);
            assert_eq!(request.uri().path(), "/ordinary");
            assert!(
                request
                    .extensions()
                    .get::<::http2::ext::Protocol>()
                    .is_none()
            );
            assert_eq!(request.body().stream_id().as_u32(), 3);
            respond.send_response(Response::builder().status(200).body(())?, true)?;
            drop(request);
            drop(respond);

            // Accepting stream 5 on this same native connection proves reuse;
            // opening another TCP connection cannot satisfy this accept.
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before reused extended CONNECT")??;
            assert_eq!(request.method(), Method::CONNECT);
            assert_eq!(request.uri().path(), "/socket");
            assert_eq!(request.body().stream_id().as_u32(), 5);
            assert_eq!(
                request
                    .extensions()
                    .get::<::http2::ext::Protocol>()
                    .ok_or("extended CONNECT omitted :protocol")?
                    .as_str(),
                "websocket"
            );
            let mut send =
                respond.send_response(Response::builder().status(200).body(())?, false)?;
            let handler = async move {
                let mut body = request.into_body();
                let message = read_client_frame(&mut body).await?;
                assert_eq!(message.opcode, 1);
                assert_eq!(message.payload, b"from-client");
                let mut reply = Vec::new();
                append_server_frame(&mut reply, true, 1, b"from-server");
                send.send_data(Bytes::from(reply), false)?;
                let close = read_client_frame(&mut body).await?;
                assert_eq!(close.opcode, 8);
                let mut reply = Vec::new();
                append_server_frame(&mut reply, true, 8, &close.payload);
                send.send_data(Bytes::from(reply), false)?;
                while let Some(data) = body.data().await {
                    assert!(data?.is_empty(), "DATA followed WebSocket Close");
                }
                assert!(body.trailers().await?.is_none());
                send.send_data(Bytes::new(), true)?;
                done_rx
                    .await
                    .map_err(|_| "caller dropped completion barrier")?;
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            };
            tokio::pin!(handler);
            tokio::select! {
                biased;
                result = &mut handler => result?,
                accepted = connection.accept() => match accepted {
                    Some(Ok(_)) => return Err("unexpected third stream".into()),
                    Some(Err(error)) => return Err(error.into()),
                    None => handler.await?,
                },
            }
            let wire = recorded
                .lock()
                .map_err(|_| "recorded wire lock poisoned")?
                .clone();
            assert_openings(&wire, target)?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }));

        let mut settings = firefox::v157_http2();
        settings.initial_stream_window_target = target;
        let mut websocket = firefox::v157_websocket();
        websocket.handshake_timeout = None;
        let profile = ClientProfile::new(tls_settings())
            .with_http2(settings)
            .with_websocket(websocket);
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let response = client
            .get(HttpProtocol::Http2, &format!("https://{address}/ordinary"))?
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());
        let mut socket = client
            .websocket_with_profile_policy(&format!("wss://{address}/socket"))?
            .connect()
            .await?;
        assert_eq!(socket.handshake_response().status(), 200);
        socket
            .send(WebSocketMessage::Text("from-client".into()))
            .await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Text("from-server".into())
        );
        socket.close(None).await?;
        assert_eq!(socket.receive().await?, WebSocketMessage::Close(None));
        let terminal = match socket.receive().await {
            Ok(_) => return Err("WebSocket remained open after Close and END_STREAM".into()),
            Err(error) => error,
        };
        assert_eq!(terminal.kind(), WebSocketErrorKind::Closed);
        done_tx
            .send(())
            .map_err(|()| "peer dropped completion receiver")?;
        drop(socket);
        server
            .as_mut()
            .ok_or("peer owner missing")?
            .join()
            .await??;
        Ok(())
    })
    .await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(caller, cleanup)
}

struct Frame<'a> {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: &'a [u8],
}

fn assert_openings(wire: &[u8], target: Option<u32>) -> TestResult<()> {
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert!(wire.starts_with(preface));
    let mut wire = &wire[preface.len()..];
    let mut frames = Vec::new();
    while !wire.is_empty() {
        let header = wire.get(..9).ok_or("truncated HTTP/2 frame header")?;
        let length =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        let payload = wire
            .get(9..9 + length)
            .ok_or("truncated HTTP/2 frame payload")?;
        frames.push(Frame {
            kind: header[3],
            flags: header[4],
            stream: u32::from_be_bytes(header[5..9].try_into()?) & 0x7fff_ffff,
            payload,
        });
        wire = &wire[9 + length..];
    }
    let settings = frames
        .iter()
        .find(|frame| (frame.kind, frame.flags) == (4, 0))
        .ok_or("client SETTINGS absent")?;
    let (settings, remainder) = settings.payload.as_chunks::<6>();
    assert!(remainder.is_empty());
    assert!(
        settings
            .iter()
            .any(|setting| setting[..2] == [0, 4] && setting[2..] == 131_072_u32.to_be_bytes())
    );
    for (stream, weight) in [(3, 42), (5, 22)] {
        let opening = frames
            .iter()
            .position(|frame| frame.kind == 1 && frame.stream == stream)
            .ok_or("opening HEADERS absent")?;
        let headers = &frames[opening];
        assert_ne!(headers.flags & 0x20, 0, "profile priority absent");
        assert_eq!(
            *headers.payload.get(4).ok_or("priority weight absent")?,
            weight - 1
        );
        let mut last = opening;
        while frames[last].flags & 4 == 0 {
            last += 1;
            let continuation = frames.get(last).ok_or("CONTINUATION absent")?;
            assert_eq!((continuation.kind, continuation.stream), (9, stream));
        }
        let updates: Vec<_> = frames
            .iter()
            .filter(|frame| frame.kind == 8 && frame.stream == stream)
            .collect();
        match target {
            Some(target) => {
                assert_eq!(updates.len(), 1, "one opening grant per request");
                let next = frames.get(last + 1).ok_or("opening WINDOW_UPDATE absent")?;
                assert_eq!((next.kind, next.stream), (8, stream));
                assert_eq!(next.payload, (target - 131_072).to_be_bytes());
            }
            None => assert!(updates.is_empty()),
        }
    }
    assert_eq!(frames.iter().filter(|frame| frame.kind == 1).count(), 2);
    Ok(())
}
