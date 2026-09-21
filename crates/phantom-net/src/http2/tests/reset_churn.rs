use std::time::Duration;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::chromium::v152_http2;
use tokio::{io::duplex, time::timeout};

use super::{TestResult, target};
use crate::http2::{Http2Body, Http2Connection, Http2Error, Http2ProtocolErrorKind};

const RESET_STREAMS: usize = 2_048;
const TEST_DEADLINE: Duration = Duration::from_secs(15);

#[tokio::test]
async fn response_reset_churn_preserves_sibling_and_connection() -> TestResult<()> {
    timeout(TEST_DEADLINE, async {
        let (client, server) = duplex(256 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = ::http2::server::handshake(server).await?;
            let (_, mut healthy_response) = connection
                .accept()
                .await
                .ok_or("connection closed before healthy sibling")??;
            let mut healthy_body =
                healthy_response.send_response(Response::builder().status(200).body(())?, false)?;

            for _ in 0..RESET_STREAMS {
                let (_, mut reset_response) = connection
                    .accept()
                    .await
                    .ok_or("connection closed during reset churn")??;
                let mut reset_body = reset_response
                    .send_response(Response::builder().status(200).body(())?, false)?;
                reset_body.send_reset(::http2::Reason::CANCEL);
            }

            healthy_body.send_data(Bytes::from_static(b"healthy"), true)?;
            let (_, mut final_response) = connection
                .accept()
                .await
                .ok_or("connection closed before final request")??;
            final_response.send_response(Response::builder().status(204).body(())?, true)?;

            if connection.accept().await.is_some() {
                return Err("client opened an unexpected request".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let connection = Http2Connection::connect(client, &v152_http2()).await?;
        let healthy = connection
            .send_get("example.test", target()?, vec![])
            .await?;
        assert_eq!(healthy.status(), 200);

        for _ in 0..RESET_STREAMS {
            let response = connection.send_get("example.test", target()?, vec![]).await;
            assert_cancelled_response(response).await?;
        }

        let body = healthy.into_body().collect().await?.to_bytes();
        assert_eq!(body, Bytes::from_static(b"healthy"));

        let final_response = connection
            .send_get("example.test", target()?, vec![])
            .await?;
        assert_eq!(final_response.status(), 204);
        final_response.into_body().collect().await?;
        assert!(!connection.is_closed());

        drop(connection);
        server_task.await??;
        Ok(())
    })
    .await
    .map_err(|_| "HTTP/2 reset-churn test exceeded its absolute deadline")?
}

async fn assert_cancelled_response(
    response: Result<Response<Http2Body>, Http2Error>,
) -> TestResult<()> {
    let error = match response {
        Ok(response) => {
            assert_eq!(response.status(), StatusCode::OK);
            match response.into_body().collect().await {
                Ok(_) => return Err("reset response body completed normally".into()),
                Err(error) => error,
            }
        }
        Err(error) => error,
    };
    assert_cancel_reset(error)
}

fn assert_cancel_reset(error: Http2Error) -> TestResult<()> {
    let Http2Error::Protocol(protocol) = error else {
        return Err(format!("reset used an unexpected error variant: {error}").into());
    };
    assert_eq!(protocol.kind(), Http2ProtocolErrorKind::StreamReset);
    assert_eq!(
        protocol.reason_code(),
        Some(u32::from(::http2::Reason::CANCEL))
    );
    Ok(())
}
