use super::super::*;
use super::admission::{TestResult, key, setup, wait_until};

fn h2_settings() -> phantom_profile::Http2Settings {
    use phantom_profile::Http2PseudoHeader as H;
    let mut settings = phantom_profile::browser::chrome::v154_http2();
    settings.extended_connect_pseudo_header_order = Some(vec![
        H::Method,
        H::Protocol,
        H::Authority,
        H::Scheme,
        H::Path,
    ]);
    settings
}

fn h2_request() -> Result<http::Request<()>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(crate::http2::prepare_connect_udp(
        "localhost:443",
        crate::request::OriginForm::parse("/.well-known/masque/udp/127.0.0.1/443/")?,
        vec![RequestHeader::new("capsule-protocol", "?1")],
    )?)
}

#[tokio::test]
async fn peer_stream_limit_waits_on_the_retained_outer_connection() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (client, server) = tokio::io::duplex(32 * 1024);
        let (observed_tx, mut observed) = tokio::sync::mpsc::channel(2);
        let (release, mut released) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol().max_concurrent_streams(1);
            let mut connection = builder.handshake::<_,bytes::Bytes>(server).await?;
            let (first, mut respond) = connection.accept().await.ok_or("first stream absent")??;
            let first_send = respond.send_response(http::Response::builder().status(200).header("capsule-protocol","?1").body(())?,false)?;
            observed_tx.send(first.body().stream_id().as_u32()).await?;
            let mut held = Some((first,first_send));
            loop {
                tokio::select! {
                    result = &mut released, if held.is_some() => { result?; drop(held.take()); },
                    accepted = connection.accept() => {
                        let (second,mut respond) = accepted.ok_or("second stream absent")??;
                        let second_send = respond.send_response(http::Response::builder().status(200).header("capsule-protocol","?1").body(())?,false)?;
                        observed_tx.send(second.body().stream_id().as_u32()).await?;
                        drop((second,second_send));
                        while let Some(accepted) = connection.accept().await { accepted?; }
                        return Ok::<_,Box<dyn std::error::Error+Send+Sync>>(());
                    }
                }
            }
        });
        let connection = Http2Connection::connect_extended(client,&h2_settings()).await?;
        let first = match connection.send_connect_udp(h2_request()?).await? {
            crate::http2::Http2ExtendedConnectOutcome::Accepted {stream,..} => stream,
            _ => return Err("first tunnel rejected".into()),
        };
        let first_id = observed.recv().await.ok_or("first stream not observed")?;
        assert_eq!(connection.peer_max_concurrent_streams(),Some(1));
        let pool = ConnectUdpProxyPool::new();
        let mut key = key(0)?;
        key.settings = Settings::Http2(ConnectionSettingsId::default());
        let owner = setup(pool.acquire(key.clone()).await?)?;
        let lease = owner.publish(OuterSession::Http2(connection.clone()),false)?;
        let Acquisition::Reuse {session:OuterSession::Http2(retained),lease:second_lease,..} = pool.acquire(key).await? else { return Err("healthy stream-limited connection replaced".into()) };
        assert!(retained.can_wait_for_connect_udp());
        let request = h2_request()?;
        let waiting = tokio::spawn(async move { let result = retained.send_connect_udp(request).await; (result,second_lease) });
        for _ in 0..20 { tokio::task::yield_now().await; }
        assert!(!waiting.is_finished());
        assert!(matches!(observed.try_recv(),Err(tokio::sync::mpsc::error::TryRecvError::Empty)));
        drop(first); release.send(()).map_err(|_| "server release disappeared")?;
        let second_id = observed.recv().await.ok_or("second stream not observed")?;
        assert_eq!(second_id,first_id+2);
        let (result,second_lease) = waiting.await?;
        assert!(matches!(result?,crate::http2::Http2ExtendedConnectOutcome::Accepted {..}));
        drop(second_lease); drop(lease); pool.clear(); drop(pool); drop(connection);
        server.await??;
        Ok(())
    }).await?
}

#[tokio::test]
async fn peer_goaway_retires_the_retained_session_and_preserves_protocol_error() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (client, server) = tokio::io::duplex(32 * 1024);
        let (retire, retired) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut connection = builder.handshake::<_, bytes::Bytes>(server).await?;
            tokio::select! {
                retired = retired => { retired?; },
                accepted = connection.accept() => return match accepted {
                    Some(Err(error)) => Err(error.into()),
                    _ => Err("unexpected stream before GOAWAY control".into()),
                },
            }
            connection.abrupt_shutdown(::http2::Reason::NO_ERROR);
            while let Some(accepted) = connection.accept().await {
                accepted?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let connection = Http2Connection::connect_extended(client, &h2_settings()).await?;
        assert!(connection.extended_connect_enabled().await?);
        let pool = ConnectUdpProxyPool::new();
        let mut key = key(0)?;
        key.settings = Settings::Http2(ConnectionSettingsId::default());
        let lease = setup(pool.acquire(key.clone()).await?)?
            .publish(OuterSession::Http2(connection.clone()), false)?;
        retire.send(()).map_err(|_| "server retire disappeared")?;
        wait_until(|| !connection.can_wait_for_connect_udp()).await?;
        assert!(!connection.is_reusable());
        assert!(matches!(pool.acquire(key).await?, Acquisition::Setup(_)));
        let error = connection
            .send_connect_udp(h2_request()?)
            .await
            .err()
            .ok_or("GOAWAY permitted another tunnel")?;
        assert_eq!(error.kind(), crate::http2::Http2ErrorKind::Protocol);
        server.await??;
        drop(lease);
        pool.clear();
        drop(pool);
        drop(connection);
        Ok(())
    })
    .await?
}
