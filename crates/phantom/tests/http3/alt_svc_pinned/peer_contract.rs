use std::{error::Error, fmt, time::Duration};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, ResponseInfo};
use tokio::{sync::oneshot, time::timeout};

use super::{AlternativePeer, ORIGIN, alternative, direct_client, serve_alternative};
use crate::support::{
    h3::{accept_request, server_endpoint},
    tls::{TestIdentity, TestResult},
};

#[tokio::test]
async fn cancelling_a_driven_alternative_closes_its_connection_with_client_retained()
-> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, wait_for_done) = oneshot::channel();
        let server = serve_alternative(endpoint, vec![(StatusCode::OK, None)], wait_for_done);
        let observer = server.endpoint.clone();
        let abort = server.task.abort_handle();
        let (host, port) = alternative(address);
        let client = direct_client(&identity).build()?;
        let response = client
            .get(
                HttpProtocol::Http3,
                &format!("https://{ORIGIN}/owner-cancellation"),
            )?
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
        assert_eq!(observer.open_connections(), 1);

        drop(server);
        let idle = timeout(Duration::from_secs(2), observer.wait_idle()).await;
        let finished = if idle.is_ok() {
            timeout(Duration::from_secs(2), async {
                while !abort.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok()
        } else {
            abort.is_finished()
        };

        if idle.is_err() || !finished {
            // Close this control's endpoint and observe its aborted task finish.
            abort.abort();
            observer.close(0_u32.into(), b"baseline control cleanup");
            timeout(Duration::from_secs(2), observer.wait_idle()).await?;
            timeout(Duration::from_secs(2), async {
                while !abort.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
        }

        drop(done);
        assert!(idle.is_ok(), "alternative outlived its cancelled owner");
        assert!(
            finished,
            "alternative task did not finish before baseline cleanup"
        );
        drop(client);
        Ok(())
    })
    .await?
}

#[derive(Debug)]
struct AlternativeFailure;

impl fmt::Display for AlternativeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("driven pinned alternative failed")
    }
}

impl Error for AlternativeFailure {}

#[tokio::test]
async fn a_completed_driven_alternative_failure_retains_its_original_type() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let retained_endpoint = endpoint.clone();
        let (done, wait_for_done) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (request, mut stream, _connection) = accept_request(&endpoint).await?;
            assert_eq!(
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str()),
                Some(ORIGIN)
            );
            assert_eq!(request.uri().path(), "/typed-peer-failure");

            stream
                .send_response(http::Response::builder().status(StatusCode::OK).body(())?)
                .await?;
            stream.finish().await?;
            wait_for_done.await?;
            Err(Box::new(AlternativeFailure) as Box<dyn Error + Send + Sync>)
        });
        let server = AlternativePeer {
            endpoint: retained_endpoint,
            task,
        };
        let (host, port) = alternative(address);
        let client = direct_client(&identity).build()?;
        let response = client
            .get(
                HttpProtocol::Http3,
                &format!("https://{ORIGIN}/typed-peer-failure"),
            )?
            .alt_svc_alternative(&host, port)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        done.send(())
            .map_err(|_| "alternative ended before the response observation")?;

        let error = server
            .finish()
            .await
            .err()
            .ok_or("failed alternative was accepted")?;
        assert!(error.downcast_ref::<AlternativeFailure>().is_some());
        drop(client);
        Ok(())
    })
    .await?
}
