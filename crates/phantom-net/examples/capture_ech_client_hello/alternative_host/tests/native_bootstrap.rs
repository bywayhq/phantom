use std::{pin::Pin, sync::Arc, time::Duration};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tokio_btls::SslStream;

use super::super::{AlternativeHost, HOST_B, SerializedIndexes};
use crate::{
    CaptureResult, Captured, HOSTNAME, capture_errors, spawn_origin_tcp, tests::test_identity,
};

#[tokio::test]
async fn verified_http1_origin_advertises_destination_b_without_completing_capture()
-> CaptureResult<()> {
    let (identity, root) = test_identity()?;
    let acceptor = identity.acceptor(None)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let destination = TcpListener::bind("127.0.0.1:0").await?;
    let alternative = Arc::new(AlternativeHost::new(
        listener.local_addr()?,
        destination.local_addr()?,
    )?);
    let captured = Arc::new(Captured {
        alternative: Some(Arc::clone(&alternative)),
        ..Captured::default()
    });
    let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::PEER);
    connector
        .cert_store_mut()
        .add_cert(X509::from_der(&root)?)?;
    connector.set_alpn_protos(b"\x08http/1.1")?;
    let connector = connector.build();
    let mut tasks = JoinSet::new();
    let result: CaptureResult<()> = timeout(Duration::from_secs(5), async {
        let empty = TcpStream::connect(listener.local_addr()?).await?;
        let (accepted, peer) = listener.accept().await?;
        let (empty_slot, empty_worker) = spawn_origin_tcp(
            &mut tasks,
            accepted,
            peer,
            acceptor.clone(),
            Arc::clone(&captured),
        );
        empty_worker.abort();
        match tasks.join_next().await {
            Some(Err(error)) if error.is_cancelled() => {}
            _ => return Err("empty ClientHello worker was not cancelled and joined".into()),
        }
        if empty_slot != 0
            || captured
                .lock()
                .tcp
                .get(empty_slot)
                .is_none_or(Option::is_some)
        {
            return Err("cancelled empty worker unexpectedly retained a ClientHello".into());
        }
        drop(empty);

        let tcp = TcpStream::connect(listener.local_addr()?).await?;
        let (accepted, peer) = listener.accept().await?;
        spawn_origin_tcp(&mut tasks, accepted, peer, acceptor, Arc::clone(&captured));
        let mut tls = SslStream::new(connector.configure()?.into_ssl(HOSTNAME)?, tcp)?;
        Pin::new(&mut tls).connect().await?;
        if tls.ssl().selected_alpn_protocol() != Some(b"http/1.1") {
            return Err("bootstrap did not negotiate HTTP/1.1".into());
        }
        let request = format!(
            "GET /learn HTTP/1.1\r\nHost: {}\r\n\r\n",
            alternative.authority()
        );
        tls.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        tls.take(4096).read_to_end(&mut response).await?;
        let response = String::from_utf8(response)?;
        if !response.starts_with("HTTP/1.1 200 OK\r\n")
            || !response.contains(&format!(
                "\r\nAlt-Svc: h3=\"{HOST_B}:{}\"; ma=300\r\n",
                destination.local_addr()?.port()
            ))
            || !response.ends_with("\r\n\r\nlearn")
            || captured.page_served()
        {
            return Err("bootstrap advertisement/body or completion state differs".into());
        }
        match tasks.join_next().await {
            Some(Ok(result)) => result?,
            Some(Err(error)) => return Err(error.into()),
            None => return Err("bootstrap owner disappeared".into()),
        }
        let indexes = SerializedIndexes::new(&captured);
        let (tcp, quic) = captured.take();
        if tcp.len() != 1 || !quic.is_empty() || !tcp[0].request_served || tcp[0].ech_accepted {
            return Err("bootstrap peer observations differ".into());
        }
        let mut fixture = Vec::new();
        tcp[0].write(&mut fixture, 0)?;
        alternative.write(&mut fixture, &indexes)?;
        let fixture = String::from_utf8(fixture)?;
        if !fixture.contains("connection_0_handshake=ok\n")
            || !fixture.contains("alternative_tcp_arrival_slot_1_serialized_index=0\n")
            || !fixture.contains("http/1.1 tcp_arrival_slot=1 authority=")
            || fixture.contains("alternative_tcp_arrival_slot_0_serialized_index=")
        {
            return Err("cancelled ClientHello gap lost the serialized connection mapping".into());
        }
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|result| result);
    tasks.abort_all();
    let mut errors = result.err().into_iter().collect::<Vec<_>>();
    loop {
        match timeout(Duration::from_secs(5), tasks.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) => errors.push(error),
            Ok(Some(Err(error))) if error.is_cancelled() => {}
            Ok(Some(Err(error))) => errors.push(error.into()),
            Ok(None) => break,
            Err(error) => {
                errors.push(error.into());
                break;
            }
        }
    }
    capture_errors(errors)
}
