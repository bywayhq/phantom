use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

use crate::ssl::{SslKeyUpdateRequest, SslMessageContentType, SslMessageDirection, SslVersion};

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
