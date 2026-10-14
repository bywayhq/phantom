use std::{error::Error, io, time::Duration};

use http::HeaderValue;
use phantom::{RequestError, RequestErrorKind, dns::DohAddressFamilies};
use tokio::time::timeout;

use super::peer::{
    application::{Application, Fixture, drive, equal},
    scripted::{Peer, Reply},
    wire::Question,
};
use crate::support::tls::{TestIdentity, TestResult};

#[derive(Clone, Copy, Debug)]
enum InvalidReply {
    Status,
    MissingMedia,
    DuplicateMedia,
    WrongMedia,
    Encoded,
    AgeSyntax,
    AgeConflict,
    Id,
    Truncated,
    Malformed,
    TooLarge,
}

impl InvalidReply {
    fn reply(self, question: &Question) -> TestResult<Reply> {
        let mut reply =
            Reply::dns(question.addresses(&[std::net::Ipv4Addr::LOCALHOST.into()], 60)?);
        match self {
            Self::Status => reply.status = 503,
            Self::MissingMedia => {
                reply.headers.remove("content-type");
            }
            Self::DuplicateMedia => {
                reply.headers.append(
                    "content-type",
                    HeaderValue::from_static("application/dns-message"),
                );
            }
            Self::WrongMedia => {
                reply
                    .headers
                    .insert("content-type", HeaderValue::from_static("application/json"));
            }
            Self::Encoded => {
                reply
                    .headers
                    .insert("content-encoding", HeaderValue::from_static("gzip"));
            }
            Self::AgeSyntax => {
                reply.headers.insert("age", HeaderValue::from_static("1.5"));
            }
            Self::AgeConflict => {
                reply.headers.append("age", HeaderValue::from_static("1"));
                reply.headers.append("age", HeaderValue::from_static("2"));
            }
            Self::Id => {
                reply.bytes[0] ^= 1;
            }
            Self::Truncated => {
                reply.bytes[2] |= 2;
            }
            Self::Malformed => {
                reply.bytes.truncate(13);
            }
            Self::TooLarge => {
                reply.bytes.resize(65_536, 0);
            }
        }
        Ok(reply)
    }

    const fn kind(self) -> io::ErrorKind {
        match self {
            Self::Status | Self::TooLarge => io::ErrorKind::Other,
            _ => io::ErrorKind::InvalidData,
        }
    }
}

#[tokio::test]
async fn invalid_http_and_dns_replies_never_become_cached_addresses() -> TestResult<()> {
    let mut fixture = Fixture::start(
        DohAddressFamilies::Ipv4Only,
        Duration::from_secs(8),
        true,
        false,
    )
    .await?;
    let primary = async {
        for case in [
            InvalidReply::Status,
            InvalidReply::MissingMedia,
            InvalidReply::DuplicateMedia,
            InvalidReply::WrongMedia,
            InvalidReply::Encoded,
            InvalidReply::AgeSyntax,
            InvalidReply::AgeConflict,
            InvalidReply::Id,
            InvalidReply::Truncated,
            InvalidReply::Malformed,
            InvalidReply::TooLarge,
        ] {
            // Retry the same host, with negative caching configured. An
            // operational error must send another real DNS exchange.
            for _ in 0..2 {
                let error = drive(&mut fixture.peer, &fixture.application, 1, |q| {
                    case.reply(q)
                })
                .await?
                .err()
                .ok_or("invalid DNS reply succeeded")?;
                equal(error_kind(error.as_ref()), Some(case.kind()))?;
            }
        }
        drive(&mut fixture.peer, &fixture.application, 1, |q| {
            Ok(Reply::dns(q.maximum_address_response()?))
        })
        .await??;
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn an_untrusted_resolver_certificate_is_rejected_before_a_dns_exchange() -> TestResult<()> {
    verification(false).await
}

#[tokio::test]
async fn a_trusted_certificate_for_another_resolver_name_is_rejected() -> TestResult<()> {
    verification(true).await
}

async fn verification(wrong_name: bool) -> TestResult<()> {
    let identity = TestIdentity::generate_for_dns(if wrong_name {
        "other-resolver.test"
    } else {
        "resolver.test"
    })?;
    let untrusted = TestIdentity::generate_for_dns("resolver.test")?;
    let mut peer = Peer::start_with_verification_failure(&identity, true).await?;
    let trust = if wrong_name { &identity } else { &untrusted };
    let mut application = match Application::start(
        trust,
        peer.port,
        DohAddressFamilies::Ipv4Only,
        Duration::from_secs(8),
        false,
        false,
    )
    .await
    {
        Ok(application) => application,
        Err(error) => {
            peer.finish(Err(error)).await?;
            return Err("fixture lost setup failure".into());
        }
    };
    let primary = timeout(Duration::from_secs(10), async {
        let error = super::peer::application::get(&application.client, &application.url)
            .await
            .err()
            .ok_or("resolver certificate verification succeeded")?;
        let mut cause: &(dyn Error + 'static) = error.as_ref();
        loop {
            if cause
                .downcast_ref::<RequestError>()
                .is_some_and(|error| error.kind() == RequestErrorKind::Tls)
            {
                break;
            }
            cause =
                next_cause(cause).ok_or("resolver failure lost its TLS error classification")?;
        }
        match peer.requests.try_recv() {
            Ok(_) => Err("unverified resolver received a DNS question".into()),
            Err(_) => Ok(()),
        }
    })
    .await
    .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
    .and_then(|result| result);
    let primary = application.finish(primary).await;
    peer.finish(primary).await
}

pub(super) fn error_kind(mut error: &(dyn Error + 'static)) -> Option<io::ErrorKind> {
    loop {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return Some(error.kind());
        }
        error = error.source()?;
    }
}

pub(super) fn next_cause<'a>(
    error: &'a (dyn Error + 'static),
) -> Option<&'a (dyn Error + 'static)> {
    // io::Error::source skips its custom payload and returns that payload's
    // source. Inspect the payload itself to keep its typed classification.
    if let Some(inner) = error
        .downcast_ref::<io::Error>()
        .and_then(io::Error::get_ref)
    {
        Some(inner)
    } else {
        error.source()
    }
}
