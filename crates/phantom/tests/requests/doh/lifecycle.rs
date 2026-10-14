use std::{io, time::Duration};

use phantom::dns::DohAddressFamilies;
use tokio::time::timeout;

use super::{
    failures::error_kind,
    peer::{
        application::{Fixture, drive, equal, get},
        scripted::{Reply, Request},
    },
};
use crate::support::tls::TestResult;

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test]
async fn dropping_an_uncached_lookup_resets_the_stream_and_releases_shared_admission()
-> TestResult<()> {
    let mut fixture = Fixture::start(
        DohAddressFamilies::Ipv4Only,
        Duration::from_secs(8),
        false,
        false,
    )
    .await?;
    let primary = async {
        let mut operation = Box::pin(get(&fixture.application.client, &fixture.application.url));
        let held = next(&mut fixture.peer.requests, &mut operation).await?;
        let https = fixture.application.doh.https_record_resolver();
        let error = timeout(DEADLINE, https.lookup("application.test", 443)).await?.err().ok_or("shared HTTPS admission unexpectedly succeeded")?;
        equal(error_kind(&error), Some(io::ErrorKind::WouldBlock))?;
        match fixture.peer.requests.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            _ => return Err("rejected admission performed DNS I/O".into()),
        }
        drop(operation);
        equal(timeout(DEADLINE, fixture.peer.resets.recv()).await?.ok_or("missing cancellation reset")?, ::http2::Reason::CANCEL)?;
        drop(held);
        // A different protocol factory uses the released endpoint permit.
        let mut operation = Box::pin(https.lookup("application.test", 443));
        let request = timeout(DEADLINE, async {
            tokio::select! {
                request = fixture.peer.requests.recv() => request.ok_or("DNS worker disappeared"),
                result = &mut operation => Err(if result.is_ok() { "HTTPS returned before response" } else { "released permit failed" }),
            }
        }).await??;
        equal(request.question.kind, 65)?;
        let reply = Reply::dns(request.question.https(60, b"\x00\x01\x00\x00\x01\x00\x03\x02h3")?);
        request.reply(reply)?;
        let answer = timeout(DEADLINE, operation).await??;
        equal(answer.answers().len(), 1)?;
        equal(answer.answers()[0].owner(), "application.test")
    }.await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn a_server_reset_releases_admission_without_caching_a_failure() -> TestResult<()> {
    let mut fixture = Fixture::start(
        DohAddressFamilies::Ipv4Only,
        Duration::from_secs(8),
        true,
        false,
    )
    .await?;
    let primary = async {
        let error = drive(&mut fixture.peer, &fixture.application, 1, |q| {
            let mut reply = Reply::dns(q.server_failure());
            reply.reset = true;
            Ok(reply)
        })
        .await?
        .err()
        .ok_or("server reset succeeded")?;
        equal(error_kind(error.as_ref()), Some(io::ErrorKind::Other))?;
        drive(&mut fixture.peer, &fixture.application, 1, |q| {
            Ok(Reply::dns(
                q.addresses(&[std::net::Ipv4Addr::LOCALHOST.into()], 60)?,
            ))
        })
        .await??;
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn a_single_deadline_covers_the_whole_cname_chain() -> TestResult<()> {
    let mut fixture = Fixture::start(
        DohAddressFamilies::Ipv4Only,
        Duration::from_secs(1),
        false,
        false,
    )
    .await?;
    let primary = async {
        let error = drive(&mut fixture.peer, &fixture.application, 2, |q| {
            let bytes = if q.name == "application.test" {
                q.cname("target.test", 60)?
            } else {
                equal(q.name.as_str(), "target.test")?;
                q.addresses(&[std::net::Ipv4Addr::LOCALHOST.into()], 60)?
            };
            let mut reply = Reply::dns(bytes);
            reply.delay = Duration::from_millis(600);
            Ok(reply)
        })
        .await?
        .err()
        .ok_or("each CNAME hop restarted the deadline")?;
        equal(error_kind(error.as_ref()), Some(io::ErrorKind::TimedOut))?;
        equal(
            timeout(DEADLINE, fixture.peer.resets.recv())
                .await?
                .ok_or("deadline did not cancel terminal request")?,
            ::http2::Reason::CANCEL,
        )?;
        drive(&mut fixture.peer, &fixture.application, 1, |q| {
            Ok(Reply::dns(
                q.addresses(&[std::net::Ipv4Addr::LOCALHOST.into()], 60)?,
            ))
        })
        .await??;
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn the_lookup_deadline_covers_an_unfinished_response_body() -> TestResult<()> {
    let mut fixture = Fixture::start(
        DohAddressFamilies::Ipv4Only,
        Duration::from_secs(1),
        false,
        false,
    )
    .await?;
    let primary = async {
        let error = drive(&mut fixture.peer, &fixture.application, 1, |q| {
            let mut reply = Reply::dns(q.addresses(&[std::net::Ipv4Addr::LOCALHOST.into()], 60)?);
            reply.unfinished = true;
            Ok(reply)
        })
        .await?
        .err()
        .ok_or("unfinished response body completed")?;
        equal(error_kind(error.as_ref()), Some(io::ErrorKind::TimedOut))?;
        equal(
            timeout(DEADLINE, fixture.peer.resets.recv())
                .await?
                .ok_or("body deadline did not reset stream")?,
            ::http2::Reason::CANCEL,
        )?;
        drive(&mut fixture.peer, &fixture.application, 1, |q| {
            Ok(Reply::dns(
                q.addresses(&[std::net::Ipv4Addr::LOCALHOST.into()], 60)?,
            ))
        })
        .await??;
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn a_dual_family_deadline_returns_a_completed_positive_without_cache_reuse() -> TestResult<()>
{
    let mut fixture = Fixture::start(
        DohAddressFamilies::DualIpv6First,
        Duration::from_secs(1),
        true,
        false,
    )
    .await?;
    let primary = async {
        for _ in 0..2 {
            drive(&mut fixture.peer, &fixture.application, 2, |q| {
                let mut reply = match q.kind {
                    1 => Reply::dns(q.addresses(&[std::net::Ipv4Addr::LOCALHOST.into()], 60)?),
                    28 => Reply::dns(q.negative(false, Some((60, 60)))?),
                    _ => return Err("unexpected dual question type".into()),
                };
                reply.unfinished = q.kind == 28;
                Ok(reply)
            })
            .await??;
            equal(
                timeout(DEADLINE, fixture.peer.resets.recv())
                    .await?
                    .ok_or("incomplete family was not cancelled")?,
                ::http2::Reason::CANCEL,
            )?;
        }
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn an_incomplete_dual_negative_is_a_retryable_error() -> TestResult<()> {
    let mut fixture = Fixture::start(
        DohAddressFamilies::DualIpv6First,
        Duration::from_secs(1),
        true,
        false,
    )
    .await?;
    let primary = async {
        for _ in 0..2 {
            let error = drive(&mut fixture.peer, &fixture.application, 2, |q| {
                let mut reply = Reply::dns(q.negative(true, Some((60, 60)))?);
                reply.unfinished = q.kind == 28;
                Ok(reply)
            })
            .await?
            .err()
            .ok_or("partial NXDOMAIN became an authoritative negative")?;
            equal(error_kind(error.as_ref()), Some(io::ErrorKind::TimedOut))?;
            equal(
                timeout(DEADLINE, fixture.peer.resets.recv())
                    .await?
                    .ok_or("incomplete family was not cancelled")?,
                ::http2::Reason::CANCEL,
            )?;
        }
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

async fn next(
    requests: &mut tokio::sync::mpsc::Receiver<Request>,
    operation: &mut std::pin::Pin<Box<impl std::future::Future<Output = TestResult<bytes::Bytes>>>>,
) -> TestResult<Request> {
    Ok(timeout(DEADLINE, async {
        tokio::select! {
            request = requests.recv() => request.ok_or("DNS fixture disappeared"),
            result = operation => Err(if result.is_ok() { "lookup returned before reply" } else { "lookup failed before question" }),
        }
    }).await??)
}
