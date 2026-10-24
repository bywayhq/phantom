use std::{net::SocketAddr, sync::Arc, time::Duration};

use btls::{
    ssl::{SslContextBuilder, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
use bytes::{Buf, Bytes};
use phantom_quic_btls::{EchOffer, EchOutcome, QuicClientConfig};
use tokio::{net::TcpListener, task::JoinSet, time::timeout};

use super::super::{AlternativeHost, HOST_B, PROBE_BODY, SocketSetupError, bind};
use crate::{
    CaptureResult, Captured, HOSTNAME, Scenario, capture_errors, spawn_origin_quic,
    tests::test_identity,
};

const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum Control {
    Plain,
    Ech,
    WrongName,
    Untrusted,
    CancelIdle,
}

async fn request(
    sender: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    authority: &str,
    path: &str,
) -> CaptureResult<Vec<u8>> {
    let request = http::Request::get(format!("https://{authority}{path}")).body(())?;
    let mut stream = sender.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    if response.status() != http::StatusCode::OK {
        return Err("alternative HTTP/3 response was not successful".into());
    }
    let mut body = Vec::new();
    while let Some(mut data) = stream.recv_data().await? {
        while data.has_remaining() {
            if body.len().saturating_add(data.chunk().len()) > 1024 {
                return Err("alternative control body exceeded its bound".into());
            }
            body.extend_from_slice(data.chunk());
            data.advance(data.chunk().len());
        }
    }
    Ok(body)
}

async fn control(case: Control) -> CaptureResult<()> {
    let (identity, root) = test_identity()?;
    let ech = Scenario::AlternativeHost
        .ech_setup()?
        .ok_or("destination ECH keys missing")?;
    let crypto = identity.quic_server(&ech.keys)?;
    let requested: SocketAddr = "127.0.0.1:0".parse()?;
    let origin = TcpListener::bind(requested)
        .await
        .map_err(|error| SocketSetupError::new("bind bootstrap TCP", requested, error))?;
    let origin_address = origin.local_addr().map_err(|error| {
        SocketSetupError::new("inspect bootstrap TCP address", requested, error)
    })?;
    let (server, reservation) = bind(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        origin_address.ip(),
    )
    .await?;
    let alternative = Arc::new(AlternativeHost::new(
        origin_address,
        reservation.local_addr()?,
    )?);
    let captured = Arc::new(Captured {
        alternative: Some(Arc::clone(&alternative)),
        ..Captured::default()
    });
    let trust = if matches!(case, Control::Untrusted) {
        test_identity()?.1
    } else {
        root
    };
    let mut context = SslContextBuilder::new(SslMethod::tls())?;
    context.set_verify(SslVerifyMode::PEER);
    context.cert_store_mut().add_cert(X509::from_der(&trust)?)?;
    context.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    context.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    context.set_alpn_protos(b"\x02h3")?;
    let offer = EchOffer::new(&ech.published);
    let mut crypto = QuicClientConfig::new(context.build());
    if matches!(case, Control::Ech) {
        crypto = crypto.with_ech(&offer);
    }
    let udp = phantom_testkit::udp::bind(requested)
        .map_err(|error| SocketSetupError::new("bind client UDP", requested, error))?;
    let client_address = udp
        .local_addr()
        .map_err(|error| SocketSetupError::new("inspect client UDP address", requested, error))?;
    let mut client = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        udp,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|error| SocketSetupError::new("create client QUIC endpoint", client_address, error))?;
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let mut tasks = JoinSet::<CaptureResult<()>>::new();
    let result: CaptureResult<()> = timeout(DEADLINE, async {
        if server.local_addr()? != reservation.local_addr()? {
            return Err("alternative TCP reservation and QUIC endpoint use different ports".into());
        }
        let name = if matches!(case, Control::WrongName) {
            HOST_B
        } else {
            HOSTNAME
        };
        let connecting = client.connect(server.local_addr()?, name)?;
        let incoming = server
            .accept()
            .await
            .ok_or("alternative listener stopped")?;
        let worker = spawn_origin_quic(&mut tasks, incoming, Arc::clone(&captured));
        let connected = connecting.await;
        if matches!(case, Control::WrongName | Control::Untrusted) {
            let error = connected
                .err()
                .ok_or("alternative accepted an invalid certificate identity")?;
            let code = match error {
                quinn::ConnectionError::TransportError(error) => u64::from(error.code),
                quinn::ConnectionError::ConnectionClosed(error) => u64::from(error.error_code),
                _ => return Err("negative trust control failed without a TLS alert".into()),
            };
            if !(0x100..0x200).contains(&code) {
                return Err("negative trust control failed outside the TLS alert range".into());
            }
            if !alternative
                .requests
                .lock()
                .map_err(|_| "requests poisoned")?
                .is_empty()
                || captured.page_served()
            {
                return Err("HTTP was served before certificate authentication".into());
            }
            return Ok(());
        }
        let connection = connected?;
        if matches!(case, Control::CancelIdle) {
            worker.abort();
            match tasks.join_next().await {
                Some(Err(error)) if error.is_cancelled() => {}
                _ => return Err("cancelled alternative worker was not joined".into()),
            }
            if captured.page_served()
                || !alternative
                    .requests
                    .lock()
                    .map_err(|_| "requests poisoned")?
                    .is_empty()
            {
                return Err("idle worker cancellation synthesized a completed request".into());
            }
            return Ok(());
        }
        let (mut driver, mut sender) = h3::client::builder()
            .build(h3_quinn::Connection::new(connection.clone()))
            .await?;
        tasks.spawn(async move {
            let error = driver.wait_idle().await;
            if error.is_h3_no_error() {
                return Ok(());
            }
            if let h3::error::ConnectionError::Remote(h3::quic::ConnectionErrorIncoming::Undefined(
                cause,
            )) = &error
                && matches!(
                    cause.downcast_ref::<quinn::ConnectionError>(),
                    Some(quinn::ConnectionError::LocallyClosed)
                )
            {
                return Ok(());
            }
            Err(error.into())
        });
        let authority = alternative.authority();
        if request(&mut sender, &authority, "/probe").await? != PROBE_BODY || captured.page_served()
        {
            return Err(
                "probe response did not preserve its full body and incomplete capture state".into(),
            );
        }
        if request(&mut sender, &authority, "/done?ok=1").await? != b"done" {
            return Err("final alternative report body differs".into());
        }
        if !captured.page_served() {
            return Err("final alternative report did not complete capture".into());
        }
        let (_, records) = captured.take();
        let [record] = records.as_slice() else {
            return Err("alternative did not retain one authenticated QUIC peer".into());
        };
        if record.handshake.is_err()
            || record.inner_server_name.as_deref() != Some(HOSTNAME)
            || !record.request_served
        {
            return Err("alternative handshake or served request metadata differs".into());
        }
        if matches!(case, Control::Ech) {
            let outer = record
                .ech
                .as_deref()
                .and_then(crate::EchOuterExtension::parse)
                .ok_or("ECH outer missing")?;
            if !record.ech_accepted
                || outer.config_id != 2
                || offer.outcome() != Some(EchOutcome::Accepted)
            {
                return Err("destination config 2 was not actually accepted".into());
            }
        } else if record.ech_accepted || offer.outcome().is_some() {
            return Err("plain alternative connection synthesized ECH acceptance".into());
        }
        if !alternative
            .dns
            .lock()
            .map_err(|_| "DNS evidence poisoned")?
            .is_empty()
        {
            return Err("alternative connection synthesized a destination DNS query".into());
        }
        connection.close(0_u32.into(), b"alternative control complete");
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|result| result);
    server.close(0_u32.into(), b"alternative control cleanup");
    client.close(0_u32.into(), b"alternative control cleanup");
    tasks.abort_all();
    let mut errors = result.err().into_iter().collect::<Vec<_>>();
    loop {
        match timeout(DEADLINE, tasks.join_next()).await {
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
    for endpoint in [&server, &client] {
        if let Err(error) = timeout(DEADLINE, endpoint.wait_idle()).await {
            errors.push(error.into());
        }
    }
    capture_errors(errors)
}

#[tokio::test]
async fn alternative_quic_authenticates_origin_a_without_an_ech_offer_or_b_query()
-> CaptureResult<()> {
    control(Control::Plain).await
}

#[tokio::test]
async fn alternative_quic_accepts_config_two_for_logical_origin_a() -> CaptureResult<()> {
    control(Control::Ech).await
}

#[tokio::test]
async fn alternative_quic_rejects_a_certificate_for_the_physical_name() -> CaptureResult<()> {
    control(Control::WrongName).await
}

#[tokio::test]
async fn alternative_quic_rejects_an_untrusted_origin_certificate() -> CaptureResult<()> {
    control(Control::Untrusted).await
}

#[tokio::test]
async fn cancelling_an_idle_alternative_worker_joins_without_publishing_a_page() -> CaptureResult<()>
{
    control(Control::CancelIdle).await
}
