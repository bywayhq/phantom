// identity_op: we write out how test values are computed
#![allow(clippy::identity_op)]

use std::{borrow::BorrowMut, time::Duration};

use assert_matches::assert_matches;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::future;
use http::{Request, Response, StatusCode};
use tokio::sync::oneshot::{self};

use crate::client::SendRequest;
use crate::error::{Code, ConnectionError, LocalError, StreamError};
use crate::quic::ConnectionErrorIncoming;
use crate::tests::get_stream_blocking;
use crate::{client, server, ConnectionState};
use crate::{
    proto::{
        coding::Encode as _,
        frame::{Frame, Settings},
        push::PushId,
        stream::StreamType,
        varint::VarInt,
    },
    quic::{self, SendStream},
};

use super::h3_quinn;
use super::{init_tracing, Pair};

#[tokio::test]
async fn connect() {
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut drive, _client) = client::new(pair.client().await).await.expect("client init");
        assert_matches!(
            future::poll_fn(|cx| drive.poll_close(cx)).await,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let _server = server::Connection::new(conn).await.unwrap();
    };

    tokio::select!(() = server_fut => (), () = client_fut => panic!("client resolved first"));
}

#[tokio::test]
async fn accept_request_end_on_client_close() {
    let mut pair = Pair::default();
    let mut server = pair.server();
    let client = pair.client();
    let (tx, rx) = oneshot::channel::<()>();
    let client_fut = async move {
        let client = client.await;
        let (mut driver, client) = client::new(client).await.expect("client init");
        let driver = async move {
            let _ = future::poll_fn(|cx: &mut std::task::Context<'_>| driver.poll_close(cx)).await;
        };

        let client_fut = async move {
            // wait for the server to accept the connection
            rx.await.unwrap();
            // client is dropped, it will send H3_NO_ERROR
            drop(client);
        };
        tokio::join!(driver, client_fut);
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        tx.send(()).unwrap();
        assert_matches!(
            incoming.accept().await.err().unwrap(),
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{error_code: code, ..})
            if code == Code::H3_NO_ERROR.value()
        );
    };
    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn server_drop_close() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let server_fut = async {
        let conn = server.next().await;
        let _ = server::Connection::new(conn).await.unwrap();
    };

    let client_fut = async {
        let (mut conn, mut send) = client::new(pair.client().await).await.expect("client init");
        let request_fut = async move {
            let mut request_stream = send
                .send_request(Request::get("http://no.way").body(()).unwrap())
                .await
                .unwrap();
            let response = request_stream.recv_response().await;

            assert_matches!(
                response.unwrap_err(),
                StreamError::ConnectionError(ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                    error_code: code,
                    ..
                }))
                if code == Code::H3_NO_ERROR.value()
            );
        };

        let drive_fut = async {
            let drive = future::poll_fn(|cx| conn.poll_close(cx)).await;
            assert_matches!(drive, ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value());
        };
        tokio::join! {request_fut,drive_fut}
    };
    tokio::join!(server_fut, client_fut);
}

// In this test the client calls send_data() without doing a finish(),
// i.e client keeps the body stream open. And client expects server to
// read_data() and send a response
#[tokio::test]
async fn server_send_data_without_finish() {
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (_driver, mut send_request) = client::new(pair.client().await).await.unwrap();

        let mut req = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        let data = vec![0; 100];
        req.send_data(bytes::Bytes::copy_from_slice(&data))
            .await
            .unwrap();
        let _ = req.recv_response().await.unwrap();
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        let request_resolver = incoming.accept().await.unwrap().unwrap();
        let (_, mut stream) = request_resolver.resolve_request().await.unwrap();
        let mut data = stream.recv_data().await.unwrap().unwrap();
        let data = data.copy_to_bytes(data.remaining());
        assert_eq!(data.len(), 100);
        response(stream).await;
        server.endpoint.wait_idle().await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn client_close_only_on_last_sender_drop() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();

        let (_, mut stream) = incoming
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);

        let (_, mut stream) = incoming
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);

        assert_matches!(
            incoming.accept().await.err().unwrap(),
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value()
        );
    };

    let client_fut = async {
        let (mut conn, mut send1) = client::new(pair.client().await).await.expect("client init");
        let mut send2 = send1.clone();
        let mut request_stream_1 = send1
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();

        assert_matches!(
            request_stream_1.recv_response().await,
            Err(StreamError::RemoteTerminate{
                code
            }) if code == Code::H3_REQUEST_CANCELLED.value()
        );

        request_stream_1.finish().await.unwrap();

        let mut request_stream_2 = send2
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();

        assert_matches!(
            request_stream_2.recv_response().await,
            Err(StreamError::RemoteTerminate{
                code
            }) if code == Code::H3_REQUEST_CANCELLED.value()
        );
        request_stream_2.finish().await.unwrap();

        drop(send1);
        drop(send2);

        let drive = future::poll_fn(|cx| conn.poll_close(cx)).await;
        assert_matches!(
            drive,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_NO_ERROR,
                    ..
                }
            }
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn settings_exchange_client() {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-3.2
    //= type=test
    //# After the QUIC connection is
    //# established, a SETTINGS frame MUST be sent by each endpoint as the
    //# initial frame of their respective HTTP control stream.

    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut conn, client) = client::new(pair.client().await).await.expect("client init");
        let settings_change = async {
            for _ in 0..10 {
                if client.settings().max_field_section_size == 12 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            panic!("peer's max_field_section_size didn't change");
        };

        let drive = async move {
            assert_matches!(future::poll_fn(|cx| conn.poll_close(cx)).await,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value());
        };

        tokio::select! { _ = settings_change => (), _ = drive => panic!("driver resolved first") };
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::builder()
            .max_field_section_size(12)
            .build(conn)
            .await
            .unwrap();
        incoming.accept().await.unwrap()
    };

    tokio::select! { _ = server_fut => panic!("server resolved first"), _ = client_fut => () };
}

#[tokio::test]
async fn settings_exchange_server() {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-3.2
    //= type=test
    //# After the QUIC connection is
    //# established, a SETTINGS frame MUST be sent by each endpoint as the
    //# initial frame of their respective HTTP control stream.

    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut conn, _client) = client::builder()
            .max_field_section_size(12)
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");
        let drive = async move {
            assert_matches!(
                future::poll_fn(|cx| conn.poll_close(cx)).await,
                ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                    error_code: code,
                    ..
                }) if code == Code::H3_NO_ERROR.value()
            );
        };

        drive.await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();

        let state = incoming.inner.shared.clone();
        let accept = async { incoming.accept().await.unwrap() };

        let settings_change = async {
            for _ in 0..10 {
                if state.settings().max_field_section_size == 12 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            panic!("peer's max_field_section_size didn't change");
        };
        tokio::select! { _ = accept => panic!("server resolved first"), _ = settings_change => () };
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn client_error_on_bidi_recv() {
    let mut pair = Pair::default();
    let server = pair.server();

    let client_fut = async {
        let (mut conn, mut send) = client::new(pair.client().await).await.expect("client init");

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
        //= type=test
        //# Clients MUST treat
        //# receipt of a server-initiated bidirectional stream as a connection
        //# error of type H3_STREAM_CREATION_ERROR unless such an extension has
        //# been negotiated.
        let driver = future::poll_fn(|cx| conn.poll_close(cx));
        assert_matches!(
            driver.await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_STREAM_CREATION_ERROR,
                    reason: reason_string
                }
            } if reason_string.starts_with("client received a server-initiated bidirectional stream")
        );
        assert_matches!(send.send_request(Request::get("http://no.way").body(()).unwrap())
            .await.map(|_| ()).unwrap_err(),
            StreamError::ConnectionError(
                ConnectionError::Local { error: LocalError::Application { code: Code::H3_STREAM_CREATION_ERROR, reason: reason_string } }
            )
            if reason_string.starts_with("client received a server-initiated bidirectional stream")
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        for _ in 0..100 {
            match send.write(b"I'm not really a server").await {
                Err(quinn::WriteError::ConnectionLost(
                    quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                        error_code,
                        ..
                    }),
                )) if Code::H3_STREAM_CREATION_ERROR == error_code.into_inner() => return,
                Err(e) => panic!("got err: {}", e),
                Ok(_) => (),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("did not get the expected error");
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn two_control_streams() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //= type=test
        //# Only one control stream per peer is permitted;
        //# receipt of a second stream claiming to be a control stream MUST be
        //# treated as a connection error of type H3_STREAM_CREATION_ERROR.
        for _ in 0..=1 {
            let mut control_stream = connection.open_uni().await.unwrap();
            let mut buf = BytesMut::new();
            StreamType::CONTROL.encode(&mut buf);
            control_stream.write_all(&buf[..]).await.unwrap();
        }

        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_STREAM_CREATION_ERROR,
                    ..
                }
            }
        );
    };

    tokio::select! { _ = server_fut => (), _ = client_fut => panic!("client resolved first") };
}

#[tokio::test]
async fn malformed_qpack_encoder_instruction_has_specific_error() {
    let mut pair = Pair::default();
    let server = pair.server();

    let client_fut = async {
        let (mut driver, _client) = client::new(pair.client().await).await.unwrap();
        let error = future::poll_fn(|cx| driver.poll_close(cx)).await;

        assert_matches!(
            error,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::QPACK_ENCODER_STREAM_ERROR,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut encoder = connection.open_uni().await.unwrap();

        // A capacity update to one exceeds the client's default advertised capacity of zero.
        encoder.write_all(&[0x02, 0x21]).await.unwrap();
        let _ = connection.closed().await;
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn qpack_encoder_insert_emits_decoder_feedback() {
    let mut pair = Pair::default();
    let server = pair.server();

    let client_fut = async {
        let mut builder = client::builder();
        builder.ordered_settings(&[(0x01, 64)]).unwrap();
        let (mut driver, _client) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut client_streams = Vec::new();
        let mut decoder_index = None;

        for _ in 0..3 {
            let mut stream = connection.accept_uni().await.unwrap();
            let mut stream_type = [0];
            stream.read_exact(&mut stream_type).await.unwrap();
            if stream_type[0] == 0x03 {
                decoder_index = Some(client_streams.len());
            }
            client_streams.push(stream);
        }

        let mut encoder = connection.open_uni().await.unwrap();
        encoder
            .write_all(&[
                0x02, // Encoder stream type.
                0x3f, 0x21, // Dynamic table capacity: 64.
                0x41, b'x', 0x01, b'y', // Insert literal name and value.
            ])
            .await
            .unwrap();

        let mut feedback = [0];
        client_streams[decoder_index.unwrap()]
            .read_exact(&mut feedback)
            .await
            .unwrap();
        assert_eq!(feedback, [0x01]);

        connection.close(0_u32.into(), b"test complete");
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn dynamic_qpack_response_survives_recv_future_cancellation() {
    let mut pair = Pair::default();
    let server = pair.server();
    let (headers_sent, headers_received) = oneshot::channel();
    let (send_insert, insert_requested) = oneshot::channel();
    let (feedback_seen, feedback_received) = oneshot::channel();

    let client_fut = async {
        let mut builder = client::builder();
        builder
            .ordered_settings(&[(0x01, 64), (0x06, 65_536), (0x07, 1)])
            .unwrap();
        let (mut driver, mut client) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let request = async move {
            let mut stream = client
                .send_request(Request::get("https://localhost/").body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();

            headers_received.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), stream.recv_response())
                    .await
                    .is_err(),
                "response completed before its dynamic-table insert arrived"
            );
            send_insert.send(()).unwrap();

            let response = stream.recv_response().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers().get("x").unwrap(), "y");
            feedback_received.await.unwrap();
        };

        let ((), driver_result) = tokio::join!(request, drive);
        assert_matches!(
            driver_result,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code: 0 })
                | ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_NO_ERROR,
                        ..
                    }
                }
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();

        let (mut response, _request) = connection.accept_bi().await.unwrap();
        response
            .write_all(&[
                0x21, 0x00, // Unknown frame before response headers.
                0x01, 0x04, // HEADERS frame, four-byte payload.
                0x02, 0x80, 0xd9, 0x10, // :status 200 and dynamic x: y.
            ])
            .await
            .unwrap();
        headers_sent.send(()).unwrap();
        insert_requested.await.unwrap();

        let mut encoder = connection.open_uni().await.unwrap();
        encoder
            .write_all(&[
                0x02, // Encoder stream type.
                0x3f, 0x21, // Dynamic table capacity: 64.
                0x41, b'x', 0x01, b'y', // Insert literal name and value.
            ])
            .await
            .unwrap();

        let mut client_streams = Vec::new();
        let mut decoder_index = None;
        for _ in 0..3 {
            let mut stream = connection.accept_uni().await.unwrap();
            let mut stream_type = [0];
            stream.read_exact(&mut stream_type).await.unwrap();
            if stream_type[0] == 0x03 {
                decoder_index = Some(client_streams.len());
            }
            client_streams.push(stream);
        }

        let mut feedback = [0; 2];
        client_streams[decoder_index.unwrap()]
            .read_exact(&mut feedback)
            .await
            .unwrap();
        assert_eq!(feedback, [0x01, 0x80]);
        feedback_seen.send(()).unwrap();

        connection.close(0_u32.into(), b"test complete");
        drop((control, encoder));
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn dynamic_qpack_trailers_survive_recv_future_cancellation() {
    let mut pair = Pair::default();
    let server = pair.server();
    let (trailers_sent, trailers_received) = oneshot::channel();
    let (send_insert, insert_requested) = oneshot::channel();
    let (feedback_seen, feedback_received) = oneshot::channel();

    let client_fut = async {
        let mut builder = client::builder();
        builder
            .ordered_settings(&[(0x01, 64), (0x06, 65_536), (0x07, 1)])
            .unwrap();
        let (mut driver, mut client) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let request = async move {
            let mut stream = client
                .send_request(Request::get("https://localhost/").body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();

            let response = stream.recv_response().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(stream.recv_data().await.unwrap().is_none());

            trailers_received.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), stream.recv_trailers())
                    .await
                    .is_err(),
                "trailers completed before their dynamic-table insert arrived"
            );
            send_insert.send(()).unwrap();

            let trailers = stream.recv_trailers().await.unwrap().unwrap();
            assert_eq!(trailers.get("x").unwrap(), "y");
            feedback_received.await.unwrap();
        };

        let ((), driver_result) = tokio::join!(request, drive);
        assert_matches!(
            driver_result,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code: 0 })
                | ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_NO_ERROR,
                        ..
                    }
                }
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();

        let (mut response, _request) = connection.accept_bi().await.unwrap();
        response
            .write_all(&[
                0x01, 0x03, 0x00, 0x00, 0xd9, // Static :status 200 response.
                0x01, 0x03, 0x02, 0x80, 0x10, // Dynamic x: y trailers.
            ])
            .await
            .unwrap();
        response.finish().unwrap();
        trailers_sent.send(()).unwrap();
        insert_requested.await.unwrap();

        let mut encoder = connection.open_uni().await.unwrap();
        encoder
            .write_all(&[
                0x02, // Encoder stream type.
                0x3f, 0x21, // Dynamic table capacity: 64.
                0x41, b'x', 0x01, b'y', // Insert literal name and value.
            ])
            .await
            .unwrap();

        let mut client_streams = Vec::new();
        let mut decoder_index = None;
        for _ in 0..3 {
            let mut stream = connection.accept_uni().await.unwrap();
            let mut stream_type = [0];
            stream.read_exact(&mut stream_type).await.unwrap();
            if stream_type[0] == 0x03 {
                decoder_index = Some(client_streams.len());
            }
            client_streams.push(stream);
        }

        let mut feedback = [0; 2];
        client_streams[decoder_index.unwrap()]
            .read_exact(&mut feedback)
            .await
            .unwrap();
        assert_eq!(feedback, [0x01, 0x80]);
        feedback_seen.send(()).unwrap();

        connection.close(0_u32.into(), b"test complete");
        drop((control, encoder));
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn request_drop_and_stop_before_response_emit_qpack_cancellation() {
    let mut pair = Pair::default();
    let server = pair.server();
    let (feedback_seen, feedback_received) = oneshot::channel();

    let client_fut = async {
        let mut builder = client::builder();
        builder.ordered_settings(&[(0x01, 64)]).unwrap();
        let (mut driver, mut client) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let requests = async move {
            let mut dropped = client
                .send_request(Request::get("https://localhost/drop").body(()).unwrap())
                .await
                .unwrap();
            dropped.finish().await.unwrap();
            drop(dropped);

            let mut stopped = client
                .send_request(Request::get("https://localhost/stop").body(()).unwrap())
                .await
                .unwrap();
            stopped.finish().await.unwrap();
            stopped.stop_sending(Code::H3_REQUEST_CANCELLED);

            feedback_received.await.unwrap();
        };

        let ((), driver_result) = tokio::join!(requests, drive);
        assert_matches!(
            driver_result,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code: 0 })
                | ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_NO_ERROR,
                        ..
                    }
                }
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();

        let (_first_response, _first_request) = connection.accept_bi().await.unwrap();
        let (_second_response, _second_request) = connection.accept_bi().await.unwrap();

        let mut client_streams = Vec::new();
        let mut decoder_index = None;
        for _ in 0..3 {
            let mut stream = connection.accept_uni().await.unwrap();
            let mut stream_type = [0];
            stream.read_exact(&mut stream_type).await.unwrap();
            if stream_type[0] == 0x03 {
                decoder_index = Some(client_streams.len());
            }
            client_streams.push(stream);
        }

        let mut feedback = [0; 2];
        client_streams[decoder_index.unwrap()]
            .read_exact(&mut feedback)
            .await
            .unwrap();
        assert_eq!(feedback, [0x40, 0x44]);
        feedback_seen.send(()).unwrap();

        connection.close(0_u32.into(), b"test complete");
        drop(control);
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn request_drop_after_response_headers_emits_qpack_cancellation() {
    let mut pair = Pair::default();
    let server = pair.server();
    let (headers_sent, headers_received) = oneshot::channel();
    let (feedback_seen, feedback_received) = oneshot::channel();

    let client_fut = async {
        let mut builder = client::builder();
        builder.ordered_settings(&[(0x01, 64)]).unwrap();
        let (mut driver, mut client) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let request = async move {
            let mut stream = client
                .send_request(Request::get("https://localhost/").body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();
            headers_received.await.unwrap();

            let response = stream.recv_response().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            drop(stream);

            feedback_received.await.unwrap();
        };

        let ((), driver_result) = tokio::join!(request, drive);
        assert_matches!(
            driver_result,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code: 0 })
                | ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_NO_ERROR,
                        ..
                    }
                }
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();

        let (mut response, _request) = connection.accept_bi().await.unwrap();
        response
            .write_all(&[0x01, 0x03, 0x00, 0x00, 0xd9])
            .await
            .unwrap();
        headers_sent.send(()).unwrap();

        let mut client_streams = Vec::new();
        let mut decoder_index = None;
        for _ in 0..3 {
            let mut stream = connection.accept_uni().await.unwrap();
            let mut stream_type = [0];
            stream.read_exact(&mut stream_type).await.unwrap();
            if stream_type[0] == 0x03 {
                decoder_index = Some(client_streams.len());
            }
            client_streams.push(stream);
        }

        let mut feedback = [0];
        client_streams[decoder_index.unwrap()]
            .read_exact(&mut feedback)
            .await
            .unwrap();
        assert_eq!(feedback, [0x40]);
        feedback_seen.send(()).unwrap();

        connection.close(0_u32.into(), b"test complete");
        drop((control, response));
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn malformed_response_emits_one_qpack_cancellation() {
    let mut pair = Pair::default();
    let server = pair.server();
    let (feedback_seen, feedback_received) = oneshot::channel();

    let client_fut = async {
        let mut builder = client::builder();
        builder.ordered_settings(&[(0x01, 64)]).unwrap();
        let (mut driver, mut client) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let request = async move {
            let mut stream = client
                .send_request(Request::get("https://localhost/").body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();

            assert_matches!(
                stream.recv_response().await,
                Err(StreamError::StreamError {
                    code: Code::H3_MESSAGE_ERROR,
                    ..
                })
            );
            feedback_received.await.unwrap();
        };

        let ((), driver_result) = tokio::join!(request, drive);
        assert_matches!(
            driver_result,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code: 0 })
                | ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_NO_ERROR,
                        ..
                    }
                }
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();

        let (mut response, _request) = connection.accept_bi().await.unwrap();
        response
            .write_all(&[
                0x01, 0x04, // HEADERS frame, four-byte payload.
                0x00, 0x00, 0xc4, 0xd9, // content-length before :status.
            ])
            .await
            .unwrap();

        let mut client_streams = Vec::new();
        let mut decoder_index = None;
        for _ in 0..3 {
            let mut stream = connection.accept_uni().await.unwrap();
            let mut stream_type = [0];
            stream.read_exact(&mut stream_type).await.unwrap();
            if stream_type[0] == 0x03 {
                decoder_index = Some(client_streams.len());
            }
            client_streams.push(stream);
        }

        let mut feedback = [0];
        client_streams[decoder_index.unwrap()]
            .read_exact(&mut feedback)
            .await
            .unwrap();
        assert_eq!(feedback, [0x40]);
        feedback_seen.send(()).unwrap();

        connection.close(0_u32.into(), b"test complete");
        drop((control, response));
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn qpack_reset_while_trailers_await_eos_cancels_reserved_section() {
    let mut pair = Pair::default();
    let server = pair.server();
    let (headers_sent, headers_received) = oneshot::channel();
    let (reset_response, reset_requested) = oneshot::channel();
    let (cancellation_seen, cancellation_received) = oneshot::channel();

    let client_fut = async {
        let mut builder = client::builder();
        builder
            .ordered_settings(&[(0x01, 64), (0x06, 65_536), (0x07, 1)])
            .unwrap();
        let (mut driver, mut client) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let request = async move {
            let mut stream = client
                .send_request(Request::get("https://localhost/").body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();

            headers_received.await.unwrap();
            let response = stream.recv_response().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(stream.recv_data().await.unwrap().is_none());
            assert!(
                tokio::time::timeout(Duration::from_millis(50), stream.recv_trailers())
                    .await
                    .is_err()
            );
            reset_response.send(()).unwrap();

            let result = tokio::time::timeout(Duration::from_secs(1), stream.recv_trailers())
                .await
                .expect("reset did not wake the pending trailers");
            assert!(result.is_err());
            cancellation_received.await.unwrap();
        };

        let ((), driver_result) = tokio::join!(request, drive);
        assert_matches!(
            driver_result,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code: 0 })
                | ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_NO_ERROR,
                        ..
                    }
                }
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();

        let (mut response, _request) = connection.accept_bi().await.unwrap();
        response
            .write_all(&[
                0x01, 0x03, 0x00, 0x00, 0xd9, // Static :status 200 response.
                0x01, 0x03, 0x02, 0x80, 0x10, // Reserved dynamic trailers.
            ])
            .await
            .unwrap();
        headers_sent.send(()).unwrap();
        reset_requested.await.unwrap();
        response
            .reset(h3_quinn::quinn::VarInt::try_from(Code::H3_REQUEST_CANCELLED.value()).unwrap())
            .unwrap();

        let mut client_streams = Vec::new();
        let mut decoder_index = None;
        for _ in 0..3 {
            let mut stream = connection.accept_uni().await.unwrap();
            let mut stream_type = [0];
            stream.read_exact(&mut stream_type).await.unwrap();
            if stream_type[0] == 0x03 {
                decoder_index = Some(client_streams.len());
            }
            client_streams.push(stream);
        }

        let mut feedback = [0];
        client_streams[decoder_index.unwrap()]
            .read_exact(&mut feedback)
            .await
            .unwrap();
        assert_eq!(feedback, [0x40]);
        cancellation_seen.send(()).unwrap();

        connection.close(0_u32.into(), b"test complete");
        drop(control);
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn invalid_qpack_decoder_ack_has_specific_error() {
    let mut pair = Pair::default();
    let server = pair.server();

    let client_fut = async {
        let (mut driver, _client) = client::new(pair.client().await).await.unwrap();
        let error = future::poll_fn(|cx| driver.poll_close(cx)).await;

        assert_matches!(
            error,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::QPACK_DECODER_STREAM_ERROR,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut decoder = connection.open_uni().await.unwrap();

        // Header acknowledgement for stream zero is invalid without a referenced block.
        decoder.write_all(&[0x03, 0x80]).await.unwrap();
        let _ = connection.closed().await;
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn qpack_cancellation_for_static_stream_is_accepted() {
    let mut pair = Pair::default();
    let server = pair.server();

    let client_fut = async {
        let (mut driver, _client) = client::new(pair.client().await).await.unwrap();
        let error = future::poll_fn(|cx| driver.poll_close(cx)).await;

        assert_matches!(
            error,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code: 0 })
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut decoder = connection.open_uni().await.unwrap();

        decoder.write_all(&[0x03, 0x40]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        connection.close(0_u32.into(), b"test complete");
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn closing_qpack_encoder_stream_is_a_critical_stream_error() {
    let mut pair = Pair::default();
    let server = pair.server();

    let client_fut = async {
        let (mut driver, _client) = client::new(pair.client().await).await.unwrap();
        let error = future::poll_fn(|cx| driver.poll_close(cx)).await;

        assert_matches!(
            error,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_CLOSED_CRITICAL_STREAM,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let mut encoder = connection.open_uni().await.unwrap();
        encoder.write_all(&[0x02]).await.unwrap();
        encoder.finish().unwrap();
        let _ = connection.closed().await;
    };

    tokio::join!(client_fut, server_fut);
}

#[tokio::test]
async fn stopping_local_qpack_streams_is_a_critical_stream_error() {
    for target_type in [0x02, 0x03] {
        let mut pair = Pair::default();
        let server = pair.server();

        let client_fut = async {
            let (mut driver, _client) = client::new(pair.client().await).await.unwrap();
            future::poll_fn(|cx| driver.poll_close(cx)).await
        };

        let server_fut = async {
            let connection = server.endpoint.accept().await.unwrap().await.unwrap();
            let mut streams = Vec::new();

            for _ in 0..3 {
                let mut stream = connection.accept_uni().await.unwrap();
                let mut stream_type = [0];
                stream.read_exact(&mut stream_type).await.unwrap();
                if stream_type[0] == target_type {
                    stream.stop(42_u32.into()).unwrap();
                }
                streams.push(stream);
            }

            let _ = connection.closed().await;
            streams
        };

        let (error, _streams) = tokio::join!(client_fut, server_fut);
        assert_matches!(
            error,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_CLOSED_CRITICAL_STREAM,
                    ..
                }
            }
        );
    }
}

#[tokio::test]
async fn control_close_send_error() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //= type=test
        //# If either control
        //# stream is closed at any point, this MUST be treated as a connection
        //# error of type H3_CLOSED_CRITICAL_STREAM.
        control_stream.finish().unwrap(); // close the client control stream immediately

        // create the Connection manually, so it does not open a second Control stream

        let connection_error = loop {
            let accepted = connection.accept_bi().await;
            match accepted {
                // do nothing with the stream
                Ok(_) => continue,
                Err(err) => break err,
            }
        };

        let err_code = match connection_error {
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code,
                ..
            }) => error_code.into_inner(),
            e => panic!("unexpected error: {:?}", e),
        };
        assert_eq!(err_code, Code::H3_CLOSED_CRITICAL_STREAM.value());
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        // Driver detects that the receiving side of the control stream has been closed
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_CLOSED_CRITICAL_STREAM,
                    reason: reason_string
                }
            }
            if reason_string.starts_with("control stream was closed"));
        // Poll it once again returns the previously stored error
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_CLOSED_CRITICAL_STREAM,
                    reason: reason_string
                }
            }
            if reason_string.starts_with("control stream was closed"));
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn missing_settings() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //= type=test
        //# If the first frame of the control stream is any other frame
        //# type, this MUST be treated as a connection error of type
        //# H3_MISSING_SETTINGS.
        Frame::<Bytes>::CancelPush(PushId(0)).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_MISSING_SETTINGS,
                    ..
                }
            }
        );
    };

    tokio::select! { _ = server_fut => (), _ = client_fut => panic!("client resolved first") };
}

#[tokio::test]
async fn control_stream_frame_unexpected() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        // Send a Settings frame or we get a H3_MISSING_SETTINGS instead of H3_FRAME_UNEXPECTED
        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);
        Frame::Settings::<Bytes>(Settings::default()).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
        //= type=test
        //# If
        //# a DATA frame is received on a control stream, the recipient MUST
        //# respond with a connection error of type H3_FRAME_UNEXPECTED.
        let mut buf = BytesMut::new();
        Frame::Data(Bytes::from("")).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_FRAME_UNEXPECTED,
                    ..
                }
            }
        );
    };

    tokio::select! { _ = server_fut => (), _ = client_fut => panic!("client resolved first") };
}

#[tokio::test]
async fn timeout_on_control_frame_read() {
    init_tracing();
    let mut pair = Pair::default();
    pair.with_timeout(Duration::from_millis(10));

    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, _send_request) = client::new(pair.client().await).await.unwrap();
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Timeout
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn goaway_from_server_not_request_id() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();
        control_stream.finish().unwrap(); // close the client control stream immediately

        let (mut driver, _send) = client::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        assert_matches!(
            future::poll_fn(|cx| driver.poll_close(cx)).await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_ID_ERROR,
                    ..
                }
            }
        )
    };

    let server_fut = async {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut control_stream = conn.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);
        Frame::<Bytes>::Settings(Settings::default()).encode(&mut buf);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
        //= type=test
        //# A client MUST treat receipt of a GOAWAY frame containing a stream ID
        //# of any other type as a connection error of type H3_ID_ERROR.

        // StreamId(index=0 << 2 | dir=Uni << 1 | initiator=Server as u64)
        Frame::<Bytes>::Goaway(VarInt(0u64 << 2 | 0 << 1 | 1)).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    tokio::select! { _ = server_fut => panic!("client resolved first"), _ = client_fut => () };
}

#[tokio::test]
async fn peer_application_settings_allow_reserved_first_control_frame() {
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut builder = client::builder();
        builder.peer_application_settings(&[0x04, 0x00]).unwrap();
        let (mut driver, _send) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        assert_matches!(
            future::poll_fn(|cx| driver.poll_close(cx)).await,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose {
                error_code: code,
                ..
            }) if code == 0
        );
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x21, 0x00]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        connection.close(0_u32.into(), b"test complete");
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn empty_peer_application_settings_still_require_wire_settings() {
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut builder = client::builder();
        builder.peer_application_settings(&[]).unwrap();
        let (mut driver, _send) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        assert_matches!(
            future::poll_fn(|cx| driver.poll_close(cx)).await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_MISSING_SETTINGS,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x07, 0x01, 0x00]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    tokio::select! {
        _ = client_fut => (),
        _ = server_fut => panic!("server resolved first"),
    }
}

#[tokio::test]
async fn compatible_wire_settings_extend_peer_application_settings() {
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut builder = client::builder();
        builder
            .peer_application_settings(&[0x04, 0x04, 0x01, 0x20, 0x07, 0x02])
            .unwrap();
        let (mut driver, _send) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        let result = future::poll_fn(|cx| driver.poll_close(cx)).await;
        assert_matches!(
            result,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose {
                error_code: code,
                ..
            }) if code == 0
        );
        let settings = driver.settings();
        assert_eq!(settings.qpack_max_table_capacity, 32);
        assert_eq!(settings.qpack_blocked_streams, 3);
        assert_eq!(settings.max_field_section_size, 64);
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control
            .write_all(&[
                0x00, 0x04, 0x07, 0x01, 0x20, 0x07, 0x03, 0x06, 0x40, 0x40, 0x21, 0x00,
            ])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        connection.close(0_u32.into(), b"test complete");
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn wire_settings_after_another_control_frame_are_rejected() {
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut builder = client::builder();
        builder.peer_application_settings(&[0x04, 0x00]).unwrap();
        let (mut driver, _send) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        assert_matches!(
            future::poll_fn(|cx| driver.poll_close(cx)).await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_FRAME_UNEXPECTED,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control
            .write_all(&[0x00, 0x21, 0x00, 0x04, 0x00])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    tokio::select! {
        _ = client_fut => (),
        _ = server_fut => panic!("server resolved first"),
    }
}

#[tokio::test]
async fn conflicting_wire_settings_after_peer_application_settings_are_rejected() {
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut builder = client::builder();
        builder
            .peer_application_settings(&[0x04, 0x02, 0x01, 0x20])
            .unwrap();
        let (mut driver, _send) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        assert_matches!(
            future::poll_fn(|cx| driver.poll_close(cx)).await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_SETTINGS_ERROR,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control
            .write_all(&[0x00, 0x04, 0x03, 0x01, 0x40, 0x40])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    tokio::select! {
        _ = client_fut => (),
        _ = server_fut => panic!("server resolved first"),
    }
}

#[tokio::test]
async fn late_peer_application_settings_apply_before_control_settings() {
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let (mut driver, send) = client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        driver
            .apply_peer_application_settings(&[0x04, 0x04, 0x01, 0x20, 0x07, 0x02])
            .unwrap();
        let settings = tokio::time::timeout(Duration::from_secs(1), send.peer_settings().ready())
            .await
            .expect("late application settings are already known")
            .unwrap();
        assert_eq!(settings.qpack_max_table_capacity, 32);
        assert_eq!(settings.qpack_blocked_streams, 2);

        let result = future::poll_fn(|cx| driver.poll_close(cx)).await;
        assert_matches!(
            result,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose {
                error_code: code,
                ..
            }) if code == 0
        );
        let settings = driver.settings();
        assert_eq!(settings.qpack_max_table_capacity, 32);
        assert_eq!(settings.qpack_blocked_streams, 3);
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut control = connection.open_uni().await.unwrap();
        control
            .write_all(&[0x00, 0x04, 0x04, 0x01, 0x20, 0x07, 0x03])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        connection.close(0_u32.into(), b"test complete");
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn late_peer_application_settings_reconcile_with_control_settings() {
    for (payload, accepted) in [
        (&[0x04, 0x04, 0x01, 0x20, 0x07, 0x02][..], true),
        (&[0x04, 0x03, 0x01, 0x40, 0x40][..], false),
    ] {
        let mut pair = Pair::default();
        let server = pair.server_inner();
        let (done, finished) = oneshot::channel::<()>();

        let client_fut = async {
            let connection = pair.client_inner().await;
            let (mut driver, send) = client::builder()
                .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            let mut peer_settings = send.peer_settings();
            tokio::select! {
                ready = peer_settings.ready() => { ready.unwrap(); }
                error = future::poll_fn(|cx| driver.poll_close(cx)) => {
                    panic!("connection closed before settings: {error:?}")
                }
            }

            let result = driver.apply_peer_application_settings(payload);
            if accepted {
                result.unwrap();
                let settings = driver.settings();
                assert_eq!(settings.qpack_max_table_capacity, 32);
                assert_eq!(settings.qpack_blocked_streams, 3);
            } else {
                assert_matches!(
                    result,
                    Err(ConnectionError::Local {
                        error: LocalError::Application {
                            code: Code::H3_SETTINGS_ERROR,
                            ..
                        }
                    })
                );
            }
            done.send(()).unwrap();
        };

        let server_fut = async {
            let connection = server.accept().await.unwrap().await.unwrap();
            let mut control = connection.open_uni().await.unwrap();
            control
                .write_all(&[0x00, 0x04, 0x04, 0x01, 0x20, 0x07, 0x03])
                .await
                .unwrap();
            finished.await.unwrap();
        };

        tokio::join!(server_fut, client_fut);
    }
}

#[tokio::test]
async fn invalid_or_repeated_late_peer_application_settings_close_the_connection() {
    for payloads in [
        &[&[0x04, 0x02, 0x01][..]][..],
        &[&[0x04, 0x02, 0x01, 0x20][..], &[0x04, 0x02, 0x01, 0x20][..]][..],
    ] {
        let mut pair = Pair::default();
        let server = pair.server_inner();
        let (done, finished) = oneshot::channel::<()>();

        let client_fut = async {
            let connection = pair.client_inner().await;
            let (mut driver, _send) = client::builder()
                .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            let (last, earlier) = payloads.split_last().unwrap();
            for payload in earlier {
                driver.apply_peer_application_settings(payload).unwrap();
            }
            assert_matches!(
                driver.apply_peer_application_settings(last),
                Err(ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_SETTINGS_ERROR,
                        ..
                    }
                })
            );
            done.send(()).unwrap();
        };

        let server_fut = async {
            let _connection = server.accept().await.unwrap().await.unwrap();
            finished.await.unwrap();
        };

        tokio::join!(server_fut, client_fut);
    }
}

#[tokio::test]
async fn graceful_shutdown_server_rejects() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (_driver, mut send_request) = client::new(pair.client().await).await.unwrap();

        let mut first = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        let mut rejected = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        let first = first.recv_response().await;
        let rejected = rejected.recv_response().await;

        assert_matches!(first, Ok(_));
        assert_matches!(
            rejected.unwrap_err(),
            StreamError::RemoteTerminate {
                code: Code::H3_REQUEST_REJECTED
            }
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        let request_resolver = incoming.accept().await.unwrap().unwrap();
        let (_, stream) = request_resolver.resolve_request().await.unwrap();
        response(stream).await;
        incoming.shutdown(0).await.unwrap();
        assert_matches!(incoming.accept().await.map(|x| x.map(|_| ())), Ok(None));
        server.endpoint.wait_idle().await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn graceful_shutdown_grace_interval() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut send_request) = client::new(pair.client().await).await.unwrap();

        // Sent as the connection is not shutting down
        let mut first = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        // Sent as the connection is shutting down, but GoAway has not been received yet
        let mut in_flight = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        let first = first.recv_response().await;
        let in_flight = in_flight.recv_response().await;

        // Will not be sent as client's driver already received the GoAway
        let too_late = async move {
            tokio::time::sleep(Duration::from_millis(15)).await;
            request(send_request).await
        };
        let driver = future::poll_fn(|cx| driver.poll_close(cx));

        let (too_late, driver) = tokio::join!(too_late, driver);
        assert_matches!(first, Ok(_));
        assert_matches!(in_flight, Ok(_));
        assert_matches!(too_late.unwrap_err(), StreamError::RemoteClosing);
        assert_matches!(
            driver,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_NO_ERROR,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        let (_, first) = get_stream_blocking(&mut incoming).await.unwrap();
        incoming.shutdown(1).await.unwrap();
        let (_, in_flight) = get_stream_blocking(&mut incoming).await.unwrap();
        response(first).await;
        response(in_flight).await;

        while let Some((_, stream)) = get_stream_blocking(&mut incoming).await {
            response(stream).await;
        }

        // Ensure `too_late` request is executed as the connection is still
        // closing (no QUIC `Close` frame has been fired yet)
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn graceful_shutdown_closes_when_idle() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut send_request) = client::new(pair.client().await).await.unwrap();

        // Make continuous requests, ignoring GoAway because the connection is not driven
        while request(&mut send_request).await.is_ok() {
            tokio::task::yield_now().await;
        }
        assert_matches!(
            future::poll_fn(|cx| { driver.poll_close(cx) }).await,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();

        let mut count = 0;

        while let Some((_, stream)) = get_stream_blocking(&mut incoming).await {
            count += 1;
            if count == 4 {
                incoming.shutdown(2).await.unwrap();
            }

            response(stream).await;
        }
    };

    tokio::select! {
        _ = client_fut => (),
        r = tokio::time::timeout(Duration::from_millis(100), server_fut)
            => assert_matches!(r, Ok(())),
    };
}

#[tokio::test]
async fn graceful_shutdown_client() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut _send_request) = client::new(pair.client().await).await.unwrap();
        driver.shutdown(0).await.unwrap();
        assert_matches!(
            future::poll_fn(|cx| { driver.poll_close(cx) }).await,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert!(incoming.accept().await.unwrap().is_none());
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
// This test is to ensure that the server does still process requests even if a stream is started but has not sent any data
async fn server_not_blocking_on_idle_request() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        // create a Connection
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);

        Frame::<Bytes>::Settings(Settings::default()).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        let mut control_recv = connection.accept_uni().await.unwrap();
        // create a Request stream which is idle
        let mut request_stream = connection.open_bi().await.unwrap();

        let mut buf = BytesMut::new();
        Frame::<Bytes>::headers(Bytes::from("test")).encode(&mut buf);
        request_stream.0.write_all(&buf[..]).await.unwrap();

        let mut buf = BytesMut::new();
        // send a wrong frame to control stream
        Frame::<Bytes>::Data(Bytes::from(
            "this frame should cause the server to respond with an error",
        ))
        .encode(&mut buf);
        tokio::time::sleep(Duration::from_millis(10)).await;

        control_stream.write_all(&buf[..]).await.unwrap();

        let mut buf2 = BytesMut::new();
        control_recv.read(buf2.as_mut()).await.unwrap();

        // no bidirectional stream is started by the server
        // this will fail when server sends the error
        let err = connection
            .accept_bi()
            .await
            .expect_err("connection should error after sending wrong data on control stream");

        assert_matches!(err,
        quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose { error_code, .. })
            if error_code.into_inner() == Code::H3_FRAME_UNEXPECTED.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        let resolver = incoming.accept().await.unwrap().unwrap();
        let req1 = async move {
            let _ = resolver
                .resolve_request()
                .await
                .err()
                .expect("server should close connection");
        };

        let server = async move {
            let err = incoming.accept().await.err().expect("Connection Error");
            assert_matches!(
                err,
                ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_FRAME_UNEXPECTED,
                        ..
                    }
                }
            );
        };

        tokio::join!(req1, server);
    };

    let join = async {
        tokio::join!(server_fut, client_fut);
    };

    tokio::select!(
        _ = join => (),
         _ = tokio::time::sleep(Duration::from_secs(100)) => panic!("timeout")
    );
}
async fn request<T, O, B>(mut send_request: T) -> Result<Response<()>, StreamError>
where
    T: BorrowMut<SendRequest<O, B>>,
    O: quic::OpenStreams<B>,
    B: Buf,
{
    let mut request_stream = send_request
        .borrow_mut()
        .send_request(Request::get("http://no.way").body(()).unwrap())
        .await?;
    request_stream.recv_response().await
}

async fn response<S, B>(mut stream: server::RequestStream<S, B>)
where
    S: quic::RecvStream + SendStream<B>,
    B: Buf,
{
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::IM_A_TEAPOT)
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
    stream.finish().await.unwrap();
}

#[tokio::test]
async fn peer_settings_ready_resolves_for_alps_seed() {
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut builder = client::builder();
        builder
            .peer_application_settings(&[0x04, 0x02, 0x08, 0x01])
            .unwrap();
        let (_driver, send) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        let settings = tokio::time::timeout(Duration::from_secs(1), send.peer_settings().ready())
            .await
            .expect("ALPS settings are already known")
            .unwrap();
        assert!(settings.enable_extended_connect());
    };

    let server_fut = async {
        let _connection = server.accept().await.unwrap().await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    tokio::select! {
        _ = client_fut => (),
        _ = server_fut => panic!("server resolved first"),
    }
}

#[tokio::test]
async fn peer_settings_ready_wakes_all_waiters_on_control_settings() {
    let mut pair = Pair::default();
    let server = pair.server_inner();
    let (release, released) = oneshot::channel::<()>();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let (mut driver, send) = client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let mut first = send.peer_settings();
        let mut second = send.peer_settings();
        let waiters = async {
            let (first, second, ()) = tokio::join!(first.ready(), second.ready(), async {
                release.send(()).unwrap();
            });
            (first, second)
        };
        let (first, second) = tokio::select! {
            waiters = waiters => waiters,
            error = future::poll_fn(|cx| driver.poll_close(cx)) => {
                panic!("connection closed before settings: {error:?}")
            }
        };
        assert!(first.unwrap().enable_extended_connect());
        assert!(second.unwrap().enable_extended_connect());
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        released.await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control
            .write_all(&[0x00, 0x04, 0x02, 0x08, 0x01])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    tokio::select! {
        _ = client_fut => (),
        _ = server_fut => panic!("server resolved first"),
    }
}

#[tokio::test]
async fn peer_settings_ready_fails_on_connection_error() {
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let (mut driver, send) = client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let mut settings = send.peer_settings();
        let (ready, _closed) = tokio::join!(
            settings.ready(),
            future::poll_fn(|cx| driver.poll_close(cx))
        );
        assert_matches!(ready, Err(StreamError::ConnectionError(_)));
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        connection.close(0_u32.into(), b"no settings");
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn control_settings_cannot_disable_alps_extended_connect() {
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut builder = client::builder();
        builder
            .peer_application_settings(&[0x04, 0x02, 0x08, 0x01])
            .unwrap();
        let (mut driver, _send) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        assert_matches!(
            future::poll_fn(|cx| driver.poll_close(cx)).await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_SETTINGS_ERROR,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control
            .write_all(&[0x00, 0x04, 0x02, 0x08, 0x00])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    tokio::select! {
        _ = client_fut => (),
        _ = server_fut => panic!("server resolved first"),
    }
}
