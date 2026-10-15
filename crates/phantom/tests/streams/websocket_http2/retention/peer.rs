use crate::support::{
    ech::{ORIGIN_NAME, PUBLIC_NAME, Replayed, handshake},
    h2::read_frame,
    tls::TestResult,
    websocket::{ClientFrame, append_server_frame},
};
use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::{Method, Response};
use std::time::Duration;
use tokio::{
    io::AsyncReadExt as _,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

const QUIET: Duration = Duration::from_millis(100);
async fn authenticate(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
    ech: bool,
) -> TestResult<SslStream<Replayed>> {
    // The replay wrapper also works without ECH and keeps one concrete peer type.
    let (observed, stream) = handshake(tcp, acceptor).await?;
    if ech {
        assert_eq!(observed.outer_server_name.as_deref(), Some(PUBLIC_NAME));
        assert!(observed.ech_accepted);
    } else {
        assert!(!observed.ech_accepted);
    }
    assert_eq!(observed.inner_server_name.as_deref(), Some(ORIGIN_NAME));
    Ok(stream)
}
async fn observe_redundant_preface(stream: &mut SslStream<Replayed>) -> TestResult<()> {
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await?;
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let settings = read_frame(stream).await?;
    assert_eq!(settings.kind, 0x4, "backup omitted initial SETTINGS");
    assert_eq!(settings.stream_id, 0);
    assert_eq!(settings.flags & 0x1, 0, "initial SETTINGS was an ACK");
    // Retirement is already in progress. Observe its frames without racing
    // the closing client with server SETTINGS or acknowledgments.
    Ok(())
}
async fn no_application_before_close(stream: &mut SslStream<Replayed>) -> TestResult<()> {
    loop {
        let frame = read_frame(stream).await?;
        assert_ne!(frame.kind, 0x1, "redundant backup sent request HEADERS");
        assert_ne!(frame.kind, 0x0, "redundant backup sent application DATA");
        if frame.kind == 0x7 {
            assert_eq!(frame.stream_id, 0);
            assert!(frame.payload.len() >= 8);
            assert_eq!(&frame.payload[4..8], &0_u32.to_be_bytes());
            return Ok(());
        }
    }
}

pub(super) async fn serve(
    listener: TcpListener,
    acceptor: SslAcceptor,
    ech: bool,
    retired: bool,
    ready: oneshot::Sender<()>,
    completed: oneshot::Receiver<()>,
) -> TestResult<()> {
    let (winner, _) = listener.accept().await?;
    // A real refused IPv6 attempt advances to a second IPv4 TCP while TLS waits.
    let (spare, _) = listener.accept().await?;
    let winner = authenticate(winner, &acceptor, ech).await?;
    let mut spare_tcp = Some(spare);
    let mut ready = Some(ready);
    if !retired {
        let mut spare = authenticate(
            spare_tcp.take().ok_or("missing backup TCP")?,
            &acceptor,
            ech,
        )
        .await?;
        observe_redundant_preface(&mut spare).await?;
        // Primary peer SETTINGS are still withheld, hence no CONNECT exists yet.
        no_application_before_close(&mut spare).await?;
        ready
            .take()
            .ok_or("missing backup barrier")?
            .send(())
            .map_err(|_| "caller ended before quiet backup")?;
    }
    let mut builder = ::http2::server::Builder::new();
    builder.enable_connect_protocol();
    let mut connection = builder.handshake::<_, Bytes>(winner).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("missing original CONNECT")??;
    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.uri().path(), "/events");
    assert_eq!(
        request
            .extensions()
            .get::<::http2::ext::Protocol>()
            .map(|p| p.as_str()),
        Some("websocket")
    );
    let fields = request
        .extensions()
        .get::<::http2::ext::OrderedHeaders>()
        .ok_or("missing ordered CONNECT fields")?;
    let fields: Vec<_> = fields
        .as_slice()
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_bytes()))
        .collect();
    assert_eq!(
        fields,
        [
            ("x-order", b"first".as_slice()),
            ("sec-websocket-version", b"13".as_slice()),
            ("x-last", b"last".as_slice())
        ]
    );
    if retired {
        connection.abrupt_shutdown(::http2::Reason::NO_ERROR);
        std::future::poll_fn(|context| connection.poll_closed(context)).await?;
        drop(request);
        drop(respond);
        let spare = authenticate(
            spare_tcp.take().ok_or("missing replacement TCP")?,
            &acceptor,
            ech,
        )
        .await?;
        let mut replacement = ::http2::server::handshake(spare).await?;
        assert!(
            timeout(QUIET, replacement.accept()).await.is_err(),
            "backup sent an automatic application stream"
        );
        ready
            .take()
            .ok_or("missing replacement barrier")?
            .send(())
            .map_err(|_| "caller ended before replacement")?;
        for id in [3, 5] {
            let (request, mut respond) = replacement
                .accept()
                .await
                .ok_or("missing replacement GET")??;
            assert_eq!(
                request.method(),
                Method::GET,
                "CONNECT was replayed on the backup"
            );
            assert_eq!(request.uri().path(), "/page");
            assert_eq!(request.body().stream_id().as_u32(), id);
            respond.send_response(Response::new(()), true)?;
        }
        tokio::select! {
            biased;
            result = completed => result?,
            unexpected = replacement.accept() => match unexpected {
                None => {},
                Some(Err(error)) if error.get_io().is_some_and(crate::support::tls::is_peer_gone) => {},
                Some(Err(error)) => return Err(error.into()),
                Some(Ok(_)) => return Err("replacement received a third application stream".into()),
            },
        }
    } else {
        let mut send = respond.send_response(Response::new(()), false)?;
        let handler = async {
            let mut body = request.into_body();
            let frame = super::super::read_client_frame(&mut body).await?;
            assert_eq!(
                frame,
                ClientFrame {
                    rsv1: false,
                    opcode: 2,
                    payload: b"client".to_vec()
                }
            );
            let mut bytes = Vec::new();
            append_server_frame(&mut bytes, true, 2, b"peer");
            send.send_data(Bytes::from(bytes), false)?;
            completed.await?;
            TestResult::Ok(())
        };
        tokio::pin!(handler);
        tokio::select! {
            biased;
            result = &mut handler => result?,
            accepted = connection.accept() => match accepted {
                Some(Ok(_)) => return Err("winner received duplicate CONNECT/application stream".into()),
                Some(Err(error)) => return Err(error.into()),
                None => handler.await?,
            },
        }
    }
    assert!(
        timeout(QUIET, listener.accept()).await.is_err(),
        "a third TCP was opened"
    );
    Ok(())
}
