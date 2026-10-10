use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use crate::ssl::{
    NameType, SniError, SslContext, SslFiletype, SslKeyUpdateRequest, SslMessageContentType,
    SslMessageDirection, SslMethod, SslVersion,
};

use super::server::Server;

const REQUESTED_KEY_UPDATE: &[u8] = &[24, 0, 0, 1, 1];
const NOT_REQUESTED_KEY_UPDATE: &[u8] = &[24, 0, 0, 1, 0];

#[test]
fn requested_key_update_is_observable_and_answered() {
    let messages = Arc::new(Mutex::new(Vec::new()));
    let mut server = Server::builder();
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let observed = Arc::clone(&messages);
    server.ctx().set_msg_callback(move |_, message| {
        if message.content_type == SslMessageContentType::HANDSHAKE {
            observed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((message.direction, message.data.to_vec()));
        }
    });
    server.io_cb(|mut stream| {
        stream
            .ssl_mut()
            .key_update(SslKeyUpdateRequest::Requested)
            .unwrap();
        stream.write_all(&[1]).unwrap();
        stream.read_exact(&mut [0]).unwrap();
    });
    let server = server.build();

    let mut client = server.client().connect();
    client.read_exact(&mut [0]).unwrap();
    client.write_all(&[2]).unwrap();
    drop(client);
    drop(server);

    let messages = messages
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let requested = messages
        .iter()
        .filter(|(direction, message)| {
            *direction == SslMessageDirection::Write && message == REQUESTED_KEY_UPDATE
        })
        .count();
    let answered = messages
        .iter()
        .filter(|(direction, message)| {
            *direction == SslMessageDirection::Read && message == NOT_REQUESTED_KEY_UPDATE
        })
        .count();
    assert_eq!(requested, 1);
    assert_eq!(answered, 1);
}

#[test]
fn message_callback_survives_sni_context_switch() {
    let mut replacement = SslContext::builder(SslMethod::tls()).unwrap();
    replacement
        .set_certificate_chain_file("test/cert.pem")
        .unwrap();
    replacement
        .set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    replacement
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    replacement
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let replacement = replacement.build();

    let switched = Arc::new(AtomicBool::new(false));
    let after_switch = Arc::new(AtomicUsize::new(0));
    let mut server = Server::builder();
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();

    let observed_switch = Arc::clone(&switched);
    let observed_messages = Arc::clone(&after_switch);
    server.ctx().set_msg_callback(move |_, message| {
        if observed_switch.load(Ordering::SeqCst)
            && message.content_type == SslMessageContentType::HANDSHAKE
        {
            observed_messages.fetch_add(1, Ordering::SeqCst);
        }
    });

    let completed_switch = Arc::clone(&switched);
    server.ctx().set_servername_callback(move |ssl, _| {
        if ssl.servername(NameType::HOST_NAME) != Some("foobar.com") {
            return Err(SniError::ALERT_FATAL);
        }
        ssl.set_ssl_context(&replacement)
            .map_err(|_| SniError::ALERT_FATAL)?;
        completed_switch.store(true, Ordering::SeqCst);
        Ok(())
    });
    server.io_cb(|mut stream| {
        let mut request = [0; 7];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"request");
        stream.write_all(b"response").unwrap();
    });
    let server = server.build();

    let client = server.client().build();
    let mut connection = client.builder();
    connection.ssl().set_hostname("foobar.com").unwrap();
    let mut connection = connection.connect();
    connection.write_all(b"request").unwrap();
    let mut response = [0; 8];
    connection.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"response");
    drop(connection);
    drop(server);

    assert!(switched.load(Ordering::SeqCst));
    assert!(after_switch.load(Ordering::SeqCst) > 0);
}

#[test]
fn message_debug_hides_runtime_client_hello_bytes() {
    let canary = format!(
        "private-{}-{}.example",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let messages = Arc::new(Mutex::new(Vec::new()));
    let server = Server::builder().build();
    let mut client = server.client();
    let observed_messages = Arc::clone(&messages);
    let observed_canary = canary.clone();
    client.ctx().set_msg_callback(move |_, message| {
        if message.direction == SslMessageDirection::Write
            && message.content_type == SslMessageContentType::HANDSHAKE
            && message
                .data
                .windows(observed_canary.len())
                .any(|bytes| bytes == observed_canary.as_bytes())
        {
            observed_messages
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((
                    message.direction,
                    message.version,
                    message.content_type,
                    message.data.to_vec(),
                    format!("{message:?}"),
                    format!("{message:#?}"),
                ));
        }
    });
    let client = client.build();
    let mut connection = client.builder();
    connection.ssl().set_hostname(&canary).unwrap();
    drop(connection.connect());
    drop(server);

    let messages = messages
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(messages.len(), 1);
    let (direction, version, content_type, data, compact, pretty) = &messages[0];
    assert!(data
        .windows(canary.len())
        .any(|bytes| bytes == canary.as_bytes()));
    let decimal_canary = canary
        .bytes()
        .map(|byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    for debug in [compact, pretty] {
        assert!(!debug.contains(&canary));
        let tokens = debug
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>();
        assert!(!tokens.contains(&decimal_canary.replace(' ', "")));
        assert!(!tokens.contains(&format!("{data:?}").replace(' ', "")));
        assert!(debug.starts_with("SslMessage {"));

        // Pretty Debug adds whitespace and a trailing comma to tuple fields.
        let metadata = tokens.replace(',', "");
        assert!(metadata.contains(&format!("direction:{direction:?}")));
        assert!(metadata.contains(&format!("version:{version}")));
        assert!(metadata.contains(&format!(
            "content_type:SslMessageContentType({})",
            content_type.as_raw()
        )));
        assert!(metadata.contains(&format!("data_len:{}", data.len())));
    }
}
