use std::error::Error;

use http::{Request, StatusCode};
use tokio::{sync::oneshot, time::timeout};

use super::{
    Http3ErrorKind, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, client_config,
    join_server, send_test_request, server_endpoint,
};

const CONTROL_STREAM: u8 = 0x00;
const DATA_FRAME: u8 = 0x00;
const SETTINGS_FRAME: u8 = 0x04;
const RESERVED_TYPE: u8 = 0x21;

#[tokio::test(flavor = "current_thread")]
async fn frame_before_settings_closes_with_missing_settings() -> TestResult<()> {
    assert_control_stream_error(
        &[CONTROL_STREAM, DATA_FRAME, 0x00],
        h3::error::Code::H3_MISSING_SETTINGS,
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_settings_frame_closes_with_frame_unexpected() -> TestResult<()> {
    assert_control_stream_error(
        &[CONTROL_STREAM, SETTINGS_FRAME, 0x00, SETTINGS_FRAME, 0x00],
        h3::error::Code::H3_FRAME_UNEXPECTED,
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_setting_identifier_closes_with_settings_error() -> TestResult<()> {
    assert_control_stream_error(
        &[CONTROL_STREAM, SETTINGS_FRAME, 0x04, 0x01, 0x00, 0x01, 0x00],
        h3::error::Code::H3_SETTINGS_ERROR,
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn data_on_control_stream_closes_with_frame_unexpected() -> TestResult<()> {
    assert_control_stream_error(
        &[CONTROL_STREAM, SETTINGS_FRAME, 0x00, DATA_FRAME, 0x00],
        h3::error::Code::H3_FRAME_UNEXPECTED,
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_stream_and_frame_do_not_interrupt_response() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let connection = incoming.await?;

        let mut control = connection.open_uni().await?;
        control
            .write_all(&[
                CONTROL_STREAM,
                SETTINGS_FRAME,
                0x00,
                RESERVED_TYPE,
                0x03,
                b'e',
                b'x',
                b't',
            ])
            .await?;

        let mut extension = connection.open_uni().await?;
        extension
            .write_all(&[RESERVED_TYPE, b'o', b'p', b'a', b'q', b'u', b'e'])
            .await?;
        let stop_code = timeout(TEST_TIMEOUT, extension.stopped())
            .await
            .map_err(|_| "client did not stop the unknown unidirectional stream")??
            .ok_or("client accepted the unknown unidirectional stream")?;
        assert_eq!(
            stop_code.into_inner(),
            h3::error::Code::H3_STREAM_CREATION_ERROR.value()
        );

        let (mut response, mut request) = connection.accept_bi().await?;
        let _ = request.read_to_end(64 * 1024).await?;
        response.write_all(&[0x01, 0x03, 0x00, 0x00, 0xd9]).await?;
        response.finish()?;

        let _ = done_received.await;
        connection.close(quinn::VarInt::from_u32(0), b"");
        drop(control);
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });

    let request = request(address, "/unknown-extension")?;
    let response = timeout(
        TEST_TIMEOUT,
        send_test_request(address, TEST_SERVER_NAME, client, request),
    )
    .await
    .map_err(|_| "HTTP/3 request timed out after unknown extension")??;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);

    let _ = client_done.send(());
    join_server(server).await
}

async fn assert_control_stream_error(
    control_bytes: &'static [u8],
    expected: h3::error::Code,
) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;

    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let connection = incoming.await?;
        let mut control = connection.open_uni().await?;
        control.write_all(control_bytes).await?;

        let closed = timeout(TEST_TIMEOUT, connection.closed())
            .await
            .map_err(|_| "client did not close the invalid HTTP/3 connection")?;
        match closed {
            quinn::ConnectionError::ApplicationClosed(close)
                if close.error_code.into_inner() == expected.value() =>
            {
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            }
            error => Err(format!(
                "client closed with {error:?}, expected application code {expected}"
            )
            .into()),
        }
    });

    let result = timeout(
        TEST_TIMEOUT,
        send_test_request(
            address,
            TEST_SERVER_NAME,
            client,
            request(address, "/invalid-control-stream")?,
        ),
    )
    .await
    .map_err(|_| "HTTP/3 client did not reject the invalid control stream")?;
    let error = match result {
        Ok(_) => return Err("invalid control stream unexpectedly produced a response".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Http3ErrorKind::Protocol);

    join_server(server).await
}

fn request(address: std::net::SocketAddr, path: &str) -> TestResult<Request<()>> {
    Ok(Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}{path}",
        address.port()
    ))
    .body(())?)
}
