use std::{net::Ipv4Addr, num::NonZeroUsize, panic::AssertUnwindSafe};

use bytes::{Buf, Bytes};
use futures_util::FutureExt;
use h3::ext::OrderedHeaders;
use http::{Response, StatusCode};
use http_body_util::Full;
#[cfg(feature = "cookies")]
use phantom::RetryPolicy;
use phantom::{
    AltSvcPolicy, Client, HttpAttemptBudget, HttpProtocol, RequestErrorKind, RequestHeader,
    ResponseInfo, profile::browser::firefox,
};
#[cfg(feature = "cookies")]
use tokio::sync::oneshot;
use tokio::{io::AsyncWriteExt, sync::watch, time::timeout};

use crate::support::{
    tls::{TestIdentity, TestResult},
    tunnel_proxy::finish_with_cleanup,
};

#[cfg(feature = "cookies")]
use super::FIELDS;
use super::{
    CLEANUP, DEADLINE, DONOR, OTHER,
    peer::{Observation, Peer},
};

type H3Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[cfg(feature = "cookies")]
#[tokio::test]
async fn rejected_donor_continues_with_checked_fields_and_the_shared_attempt_budget()
-> TestResult<()> {
    let identity = TestIdentity::generate_for_dns_names(&[DONOR, OTHER])?;
    let peer = Peer::bind(&identity, &identity).await?;
    let client = builder(
        &identity,
        phantom::profile::Http3MisdirectedRequest::RetryFirst,
    )?
    .cookies()
    .build()?;
    let other_url = url(&peer, OTHER, "/rejected");
    client
        .cookie_jar()
        .ok_or("cookie jar disabled")?
        .set_cookie(&other_url, "sid=original; Path=/")?;
    let allowance = HttpAttemptBudget::new(2);
    let (rejected, rejection_seen) = oneshot::channel();
    let (release, reject_now) = oneshot::channel();
    let (stop, stopped) = watch::channel(false);

    let caller = async {
        settle(&client, &peer).await?;
        let send = async {
            let response = client
                .get_negotiated(&other_url)?
                .headers(caller_fields())
                .retry_policy(RetryPolicy::none().with_unprocessed_replay(Some(NonZeroUsize::MIN)))
                .attempt_budget(allowance.clone())
                .send()
                .await?;
            assert_protocol(&response, HttpProtocol::Http1)?;
            assert_eq!(response.into_body().collect_with_limit(2).await?, "ok");
            TestResult::Ok(())
        };
        let change_cookie = async {
            rejection_seen.await?;
            client
                .cookie_jar()
                .ok_or("cookie jar disabled")?
                .set_cookie(&other_url, "sid=changed; Path=/")?;
            release
                .send(())
                .map_err(|_| "rejection peer stopped before cookie mutation")?;
            TestResult::Ok(())
        };
        tokio::try_join!(send, change_cookie)?;
        assert_eq!(
            allowance.remaining(),
            0,
            "initial and resumed attempts must each spend once"
        );
        stop.send(true)
            .map_err(|_| "replay peers stopped before caller completion")?;
        TestResult::Ok(())
    };
    let tcp = async {
        answer_learn(&peer).await?;
        let (mut stream, fallback) = peer.accept_tcp_request().await?;
        assert_target(&fallback, OTHER, "/rejected", peer.address.port())?;
        assert_frozen_fields(&fallback)?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        stream.shutdown().await?;
        no_more_tcp(&peer, stopped.clone()).await?;
        Ok(fallback)
    };
    let h3 = async {
        let (identity, mut connection) = accept_connection(&peer).await?;
        let (settled, mut stream) = accept_h3(&mut connection, identity).await?;
        assert_target(&settled, DONOR, "/settled", peer.address.port())?;
        answer_ok(&mut stream).await?;
        let (record, mut stream) = accept_h3(&mut connection, identity).await?;
        assert_target(&record, OTHER, "/rejected", peer.address.port())?;
        assert_frozen_fields(&record)?;
        rejected
            .send(())
            .map_err(|_| "caller stopped before rejection observation")?;
        reject_now.await?;
        stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
        stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
        // No replacement B QUIC connection is advertised. Its replay must use TCP.
        let mut stopped = stopped.clone();
        let mut closed = false;
        loop {
            tokio::select! {
                biased;
                incoming = peer.endpoint.accept() => {
                    drop(incoming);
                    return Err("unprocessed replay opened an unadvertised B QUIC connection".into());
                }
                request = connection.accept(), if !closed => {
                    match request {
                        Ok(Some(_)) => return Err("unprocessed replay reused the rejected physical donor".into()),
                        Ok(None) => closed = true,
                        Err(h3::error::ConnectionError::Remote(h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code }, ..))
                            if error_code == h3::error::Code::H3_NO_ERROR.value() => closed = true,
                        Err(error) => return Err(error.into()),
                    }
                }
                result = stopped.wait_for(|done| *done) => {
                    result.map_err(|_| "caller stopped without finishing replay")?;
                    return Ok(record);
                }
            }
        }
    };
    let result = match AssertUnwindSafe(timeout(DEADLINE, async {
        tokio::try_join!(caller, tcp, h3)
    }))
    .catch_unwind()
    .await
    {
        Ok(Ok(result)) => result.map(|_| ()),
        Ok(Err(error)) => Err(error.into()),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("coalesced rejection assertion panicked");
            Err(std::io::Error::other(message.to_owned()).into())
        }
    };
    finish(peer, client, result).await
}

#[tokio::test]
async fn coalesced_421_retires_the_donor_without_replaying_or_interrupting_active_streams()
-> TestResult<()> {
    let identity = TestIdentity::generate_for_dns_names(&[DONOR, OTHER])?;
    let peer = Peer::bind(&identity, &identity).await?;
    let client = builder(
        &identity,
        phantom::profile::Http3MisdirectedRequest::ReturnResponse,
    )?
    .build()?;
    let allowance = HttpAttemptBudget::new(1);
    let (stop, stopped) = watch::channel(false);
    let caller = async {
        settle(&client, &peer).await?;
        let first = client
            .get_negotiated(&url(&peer, DONOR, "/held"))?
            .send()
            .await?;
        let second = client
            .get_negotiated(&url(&peer, OTHER, "/held"))?
            .send()
            .await?;
        assert_protocol(&first, HttpProtocol::Http3)?;
        assert_protocol(&second, HttpProtocol::Http3)?;
        let response = client
            .get_negotiated(&url(&peer, OTHER, "/misdirected"))?
            .attempt_budget(allowance.clone())
            .send()
            .await?;
        assert_protocol(&response, HttpProtocol::Http3)?;
        assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(response.into_body().collect_with_limit(2).await?, "no");
        assert_eq!(allowance.remaining(), 0);
        let snapshot = client.export_alt_svc().ok_or("Alt-Svc store disabled")?;
        assert_eq!(
            snapshot.entries().len(),
            1,
            "421 learned an alternative for B"
        );
        assert_eq!(
            snapshot.entries()[0].origin(),
            format!("https://{DONOR}:{}", peer.address.port())
        );
        for host in [DONOR, OTHER] {
            let response = client
                .get_negotiated(&url(&peer, host, "/after"))?
                .send()
                .await?;
            assert_protocol(&response, HttpProtocol::Http3)?;
            assert_eq!(response.into_body().collect_with_limit(2).await?, "ok");
        }
        let (first, second) = tokio::try_join!(
            first.into_body().collect_with_limit(8),
            second.into_body().collect_with_limit(8)
        )?;
        assert_eq!(first, "old-done");
        assert_eq!(second, "old-done");
        stop.send(true)
            .map_err(|_| "421 peers stopped before caller completion")?;
        TestResult::Ok(())
    };
    let tcp = async {
        answer_learn(&peer).await?;
        no_more_tcp(&peer, stopped.clone()).await
    };
    let h3 = async {
        let (old_id, mut old) = accept_connection(&peer).await?;
        let (settled, mut stream) = accept_h3(&mut old, old_id).await?;
        assert_target(&settled, DONOR, "/settled", peer.address.port())?;
        answer_ok(&mut stream).await?;
        let mut held = Vec::new();
        for host in [DONOR, OTHER] {
            let (record, mut stream) = accept_h3(&mut old, old_id).await?;
            assert_target(&record, host, "/held", peer.address.port())?;
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-length", "8")
                        .body(())?,
                )
                .await?;
            stream.send_data(Bytes::from_static(b"old-")).await?;
            held.push(stream);
        }
        let (record, mut stream) = accept_h3(&mut old, old_id).await?;
        assert_target(&record, OTHER, "/misdirected", peer.address.port())?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::MISDIRECTED_REQUEST)
                    .header("alt-svc", format!("h3=\":{}\"; ma=60", peer.address.port()))
                    .header("content-length", "2")
                    .body(())?,
            )
            .await?;
        stream.send_data(Bytes::from_static(b"no")).await?;
        stream.finish().await?;

        let (new_id, mut new) = tokio::select! {
            connection = accept_connection(&peer) => connection?,
            request = old.accept() => {
                if request?.is_some() {
                    return Err("a request reused the retired physical donor".into());
                }
                accept_connection(&peer).await?
            }
        };
        assert_ne!(
            old_id, new_id,
            "A did not open a replacement QUIC connection"
        );
        for host in [DONOR, OTHER] {
            let accepted = tokio::select! {
                request = accept_h3(&mut new, new_id) => request?,
                request = old.accept() => {
                    if request?.is_some() {
                        return Err("a request joined the retired physical donor".into());
                    }
                    accept_h3(&mut new, new_id).await?
                }
            };
            let (record, mut stream) = accepted;
            assert_target(&record, host, "/after", peer.address.port())?;
            answer_ok(&mut stream).await?;
        }
        for mut stream in held {
            stream.send_data(Bytes::from_static(b"done")).await?;
            stream.finish().await?;
        }
        let mut stopped = stopped.clone();
        tokio::select! {
            request = new.accept() => {
                drop(request?);
                Err("421 fixture observed an unexpected additional request".into())
            }
            result = stopped.wait_for(|done| *done) => {
                result.map_err(|_| "caller stopped without completing held streams")?;
                TestResult::Ok(())
            }
        }
    };
    let result = match AssertUnwindSafe(timeout(DEADLINE, async {
        tokio::try_join!(caller, tcp, h3)
    }))
    .catch_unwind()
    .await
    {
        Ok(Ok(result)) => result.map(|_| ()),
        Ok(Err(error)) => Err(error.into()),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("coalesced 421 assertion panicked");
            Err(std::io::Error::other(message.to_owned()).into())
        }
    };
    finish(peer, client, result).await
}

#[derive(Clone, Copy)]
enum MisdirectedReply {
    Success,
    Repeated,
    Exhausted,
    OneShot,
}

#[tokio::test]
async fn coalesced_421_restarts_once_on_the_origin_with_checked_credentials() -> TestResult<()> {
    misdirected_exchange(MisdirectedReply::Success).await
}

#[tokio::test]
async fn a_second_421_returns_without_a_third_http_attempt() -> TestResult<()> {
    misdirected_exchange(MisdirectedReply::Repeated).await
}

#[tokio::test]
async fn exhausted_shared_allowance_prevents_the_421_restart_send() -> TestResult<()> {
    misdirected_exchange(MisdirectedReply::Exhausted).await
}

#[tokio::test]
async fn a_one_shot_upload_keeps_its_original_421_response_and_body() -> TestResult<()> {
    misdirected_exchange(MisdirectedReply::OneShot).await
}

async fn misdirected_exchange(reply: MisdirectedReply) -> TestResult<()> {
    let identity = TestIdentity::generate_for_dns_names(&[DONOR, OTHER])?;
    let peer = Peer::bind(&identity, &identity).await?;
    let client = builder(
        &identity,
        phantom::profile::Http3MisdirectedRequest::RetryFirst,
    )?
    .build()?;
    let maximum = match reply {
        MisdirectedReply::Success | MisdirectedReply::Repeated => 2,
        MisdirectedReply::Exhausted | MisdirectedReply::OneShot => 1,
    };
    let allowance = HttpAttemptBudget::new(maximum);
    let (stop, stopped) = watch::channel(false);
    let caller = async {
        settle(&client, &peer).await?;
        let request = client
            .get_negotiated(&url(&peer, OTHER, "/misdirected"))?
            .headers(vec![
                RequestHeader::new("x-first", "one"),
                RequestHeader::new("authorization", "Basic dGVzdDp0ZXN0"),
                RequestHeader::new("cookie", "sid=caller"),
            ])
            .attempt_budget(allowance.clone());
        let request = if matches!(reply, MisdirectedReply::OneShot) {
            request.streaming_body(Full::new(Bytes::from_static(b"one-shot")))
        } else {
            request
        };
        let sent = request.send().await;
        if matches!(reply, MisdirectedReply::Exhausted) {
            let error = sent
                .err()
                .ok_or("exhausted 421 restart unexpectedly succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
        } else {
            let response = sent?;
            let (protocol, status, payload) = match reply {
                MisdirectedReply::Success => (HttpProtocol::Http1, StatusCode::OK, "ok"),
                MisdirectedReply::Repeated => {
                    (HttpProtocol::Http1, StatusCode::MISDIRECTED_REQUEST, "no")
                }
                MisdirectedReply::OneShot => {
                    (HttpProtocol::Http3, StatusCode::MISDIRECTED_REQUEST, "no")
                }
                MisdirectedReply::Exhausted => {
                    return Err("exhausted branch reached response handling".into());
                }
            };
            assert_protocol(&response, protocol)?;
            assert_eq!(response.status(), status);
            assert_eq!(response.into_body().collect_with_limit(2).await?, payload);
        }
        assert_eq!(allowance.remaining(), 0);
        let alternatives = client.export_alt_svc().ok_or("Alt-Svc store disabled")?;
        assert!(
            alternatives.entries().iter().all(|entry| {
                entry.origin() != format!("https://{OTHER}:{}", peer.address.port())
            }),
            "421 taught B's Alt-Svc mapping"
        );
        stop.send(true)
            .map_err(|_| "421 peers stopped before caller completion")?;
        TestResult::Ok(())
    };
    let tcp = async {
        answer_learn(&peer).await?;
        if matches!(
            reply,
            MisdirectedReply::Success | MisdirectedReply::Repeated
        ) {
            let (mut stream, record) = peer.accept_tcp_request().await?;
            assert_target(&record, OTHER, "/misdirected", peer.address.port())?;
            assert_421_credentials(&record)?;
            let response = if matches!(reply, MisdirectedReply::Success) {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".as_slice()
            } else {
                b"HTTP/1.1 421 Misdirected Request\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno".as_slice()
            };
            stream.write_all(response).await?;
            stream.shutdown().await?;
        }
        no_more_tcp(&peer, stopped.clone()).await
    };
    let h3 = async {
        let (identity, mut connection) = accept_connection(&peer).await?;
        let (record, mut stream) = accept_h3(&mut connection, identity).await?;
        assert_target(&record, DONOR, "/settled", peer.address.port())?;
        answer_ok(&mut stream).await?;
        let resolver = connection
            .accept()
            .await?
            .ok_or("421 peer closed before B request")?;
        let (request, mut stream) = resolver.resolve_request().await?;
        assert_eq!(request.method(), "GET");
        assert_eq!(
            request
                .uri()
                .authority()
                .ok_or("B omitted authority")?
                .as_str(),
            format!("{OTHER}:{}", peer.address.port())
        );
        assert_eq!(request.uri().path(), "/misdirected");
        assert_421_credentials(&Observation {
            connection: Some(identity),
            stream: Some(stream.id().into_inner()),
            method: request.method().to_string(),
            authority: request
                .uri()
                .authority()
                .ok_or("B omitted authority")?
                .to_string(),
            path: request.uri().path().to_owned(),
            fields: request
                .extensions()
                .get::<OrderedHeaders>()
                .ok_or("B omitted ordered fields")?
                .as_slice()
                .iter()
                .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
                .collect(),
        })?;
        let mut received = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            if received.len() + chunk.remaining() > b"one-shot".len() {
                return Err("421 fixture upload exceeded eight bytes".into());
            }
            received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        if matches!(reply, MisdirectedReply::OneShot) {
            assert_eq!(received, b"one-shot");
        } else {
            assert!(received.is_empty(), "bodyless 421 request carried data");
        }
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::MISDIRECTED_REQUEST)
                    .header("alt-svc", format!("h3=\":{}\"; ma=60", peer.address.port()))
                    .header("content-length", "2")
                    .body(())?,
            )
            .await?;
        stream.send_data(Bytes::from_static(b"no")).await?;
        stream.finish().await?;
        let mut stopped = stopped.clone();
        let mut closed = false;
        loop {
            tokio::select! {
                biased;
                incoming = peer.endpoint.accept() => {
                    drop(incoming);
                    return Err("421 restart opened an unadvertised B QUIC connection".into());
                }
                request = connection.accept(), if !closed => {
                    match request {
                        Ok(Some(_)) => return Err("421 request replayed on its rejected donor".into()),
                        Ok(None) => closed = true,
                        Err(h3::error::ConnectionError::Remote(h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code }, ..))
                            if error_code == h3::error::Code::H3_NO_ERROR.value() => closed = true,
                        Err(error) => return Err(error.into()),
                    }
                }
                result = stopped.wait_for(|done| *done) => {
                    result.map_err(|_| "caller stopped before 421 completion")?;
                    return TestResult::Ok(());
                }
            }
        }
    };
    let result = match AssertUnwindSafe(timeout(DEADLINE, async {
        tokio::try_join!(caller, tcp, h3)
    }))
    .catch_unwind()
    .await
    {
        Ok(Ok(result)) => result.map(|_| ()),
        Ok(Err(error)) => Err(error.into()),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("misdirected request assertion panicked");
            Err(std::io::Error::other(message.to_owned()).into())
        }
    };
    finish(peer, client, result).await
}

fn assert_421_credentials(record: &Observation) -> TestResult<()> {
    let credentials = record
        .fields
        .iter()
        .filter(|(name, _)| matches!(name.as_str(), "x-first" | "authorization" | "cookie"))
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect::<Vec<_>>();
    assert_eq!(
        credentials,
        [
            ("x-first", b"one".as_slice()),
            ("authorization", b"Basic dGVzdDp0ZXN0".as_slice()),
            ("cookie", b"sid=caller".as_slice()),
        ]
    );
    assert!(record.fields.iter().all(|(name, _)| name != "alt-used"));
    Ok(())
}

fn builder(
    identity: &TestIdentity,
    policy: phantom::profile::Http3MisdirectedRequest,
) -> TestResult<phantom::ClientBuilder> {
    let mut http3 = firefox::v157_http3();
    http3.misdirected_request = policy;
    let profile = firefox::v157_windows().with_http3(phantom::profile::Http3ClientSettings::new(
        firefox::v157_http3_tls(),
        firefox::v157_quic(),
        http3,
        firefox::v157_http3_request(),
    ));
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .resolve(DONOR, [Ipv4Addr::LOCALHOST.into()])
        .resolve(OTHER, [Ipv4Addr::LOCALHOST.into()])
        .alt_svc(NonZeroUsize::new(8).ok_or("invalid Alt-Svc fixture capacity")?)
        .alt_svc_policy(AltSvcPolicy::sequential()))
}

fn url(peer: &Peer, host: &str, path: &str) -> String {
    format!("https://{host}:{}{path}", peer.address.port())
}

#[cfg(feature = "cookies")]
fn caller_fields() -> Vec<RequestHeader> {
    FIELDS
        .iter()
        .map(|(name, value)| RequestHeader::new(*name, *value))
        .collect()
}

async fn settle(client: &Client, peer: &Peer) -> TestResult<()> {
    for (path, protocol) in [
        ("/learn", HttpProtocol::Http1),
        ("/settled", HttpProtocol::Http3),
    ] {
        let response = client
            .get_negotiated(&url(peer, DONOR, path))?
            .send()
            .await?;
        assert_protocol(&response, protocol)?;
        assert_eq!(response.into_body().collect_with_limit(2).await?, "ok");
    }
    Ok(())
}

fn assert_protocol<B>(response: &Response<B>, protocol: HttpProtocol) -> TestResult<()> {
    assert_eq!(
        response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted protocol")?
            .protocol(),
        protocol
    );
    Ok(())
}

fn assert_target(record: &Observation, host: &str, path: &str, port: u16) -> TestResult<()> {
    assert_eq!(record.method, "GET");
    assert_eq!(record.authority, format!("{host}:{port}"));
    assert_eq!(record.path, path);
    Ok(())
}

#[cfg(feature = "cookies")]
fn assert_frozen_fields(record: &Observation) -> TestResult<()> {
    let fields = record
        .fields
        .iter()
        .filter(|(name, _)| name.starts_with("x-") || name == "cookie")
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        [
            ("x-first", b"one".as_slice()),
            ("x-last", b"two".as_slice()),
            ("cookie", b"sid=original".as_slice())
        ]
    );
    assert!(record.fields.iter().all(|(name, _)| name != "alt-used"));
    Ok(())
}

async fn answer_learn(peer: &Peer) -> TestResult<()> {
    let (mut stream, record) = peer.accept_tcp_request().await?;
    assert_target(&record, DONOR, "/learn", peer.address.port())?;
    let response = format!(
        "HTTP/1.1 200 OK\r\nAlt-Svc: h3=\":{}\"; ma=60\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        peer.address.port()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn no_more_tcp(peer: &Peer, mut stopped: watch::Receiver<bool>) -> TestResult<()> {
    tokio::select! {
        biased;
        request = peer.accept_tcp_request() => {
            drop(request?);
            Err("coalescing fixture observed an unexpected TCP request".into())
        }
        result = stopped.wait_for(|done| *done) => {
            result.map_err(|_| "caller stopped without completing requests")?;
            Ok(())
        }
    }
}

async fn accept_connection(peer: &Peer) -> TestResult<(usize, H3Connection)> {
    let connection = peer
        .endpoint
        .accept()
        .await
        .ok_or("QUIC endpoint closed early")?
        .await?;
    let identity = connection.stable_id();
    Ok((
        identity,
        h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?,
    ))
}

async fn accept_h3(
    connection: &mut H3Connection,
    identity: usize,
) -> TestResult<(Observation, H3Stream)> {
    let resolver = connection
        .accept()
        .await?
        .ok_or("HTTP/3 peer closed before request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    if stream.recv_data().await?.is_some() {
        return Err("coalescing GET unexpectedly carried a body".into());
    }
    let record = Observation {
        connection: Some(identity),
        stream: Some(stream.id().into_inner()),
        method: request.method().to_string(),
        authority: request
            .uri()
            .authority()
            .ok_or("HTTP/3 request omitted authority")?
            .to_string(),
        path: request.uri().path().to_owned(),
        fields: request
            .extensions()
            .get::<OrderedHeaders>()
            .ok_or("HTTP/3 request omitted ordered fields")?
            .as_slice()
            .iter()
            .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
            .collect(),
    };
    Ok((record, stream))
}

async fn answer_ok(stream: &mut H3Stream) -> TestResult<()> {
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header("content-length", "2")
                .body(())?,
        )
        .await?;
    stream.send_data(Bytes::from_static(b"ok")).await?;
    stream.finish().await?;
    Ok(())
}

async fn finish(peer: Peer, client: Client, result: TestResult<()>) -> TestResult<()> {
    drop(client);
    peer.endpoint
        .close(0_u32.into(), b"coalescing replay fixture complete");
    let cleanup = async {
        timeout(CLEANUP, peer.endpoint.wait_idle()).await?;
        Ok(())
    }
    .await;
    finish_with_cleanup(result, cleanup)
}
