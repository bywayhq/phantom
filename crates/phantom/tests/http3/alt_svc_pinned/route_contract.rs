use std::{
    io,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{AddressResolver, HttpProtocol, RedirectPolicy, RequestErrorKind, ResponseInfo};
use tokio::sync::oneshot;

use super::{ORIGIN, alternative, bounded, direct_client, serve_alternative};
use crate::support::{
    h3::server_endpoint,
    tls::{TestIdentity, TestResult},
};

fn refusing_resolver(lookups: Arc<Mutex<Vec<String>>>) -> AddressResolver {
    AddressResolver::from_fn(move |host| {
        let lookups = Arc::clone(&lookups);
        async move {
            lookups
                .lock()
                .map_err(|_| io::Error::other("resolver observation lock poisoned"))?
                .push(host);
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "test resolver refused the host",
            ))
        }
    })
}

#[tokio::test]
async fn a_foreign_redirect_queries_the_selected_resolver_after_the_literal_first_hop()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, wait_for_done) = oneshot::channel();
        let server = serve_alternative(
            endpoint,
            vec![(
                StatusCode::TEMPORARY_REDIRECT,
                Some("https://other.test/next"),
            )],
            wait_for_done,
        );
        let (host, port) = alternative(address);
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let client = direct_client(&identity)
            .dns_resolver(refusing_resolver(Arc::clone(&lookups)))
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;

        let error = client
            .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/first"))?
            .alt_svc_alternative(&host, port)
            .send()
            .await
            .err()
            .ok_or("foreign redirect bypassed the refusing resolver")?;
        assert_eq!(error.kind(), RequestErrorKind::Resolve);
        done.send(())
            .map_err(|_| "alternative ended before completion signal")?;
        let received = server.finish().await?;

        assert_eq!(received.len(), 1);
        assert_eq!(received[0].authority, ORIGIN);
        assert_eq!(received[0].path, "/first");
        assert_eq!(received[0].alt_used, None);

        assert_eq!(
            lookups
                .lock()
                .map_err(|_| "resolver observation lock poisoned")?
                .as_slice(),
            ["other.test"]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_same_origin_redirect_keeps_the_pin_without_querying_a_refusing_resolver()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, wait_for_done) = oneshot::channel();
        let server = serve_alternative(
            endpoint,
            vec![
                (StatusCode::TEMPORARY_REDIRECT, Some("/next")),
                (StatusCode::OK, None),
            ],
            wait_for_done,
        );
        let (host, port) = alternative(address);
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let client = direct_client(&identity)
            .dns_resolver(refusing_resolver(Arc::clone(&lookups)))
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;

        let response = client
            .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/first"))?
            .alt_svc_alternative(&host, port)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http3)
        );
        response.into_body().collect().await?;
        done.send(())
            .map_err(|_| "alternative ended before completion signal")?;
        let received = server.finish().await?;

        assert_eq!(received.len(), 2);
        assert_eq!(received[0].authority, ORIGIN);
        assert_eq!(received[0].path, "/first");
        assert_eq!(received[1].authority, ORIGIN);
        assert_eq!(received[1].path, "/next");

        assert!(
            lookups
                .lock()
                .map_err(|_| "resolver observation lock poisoned")?
                .is_empty()
        );
        Ok(())
    })
    .await
}
