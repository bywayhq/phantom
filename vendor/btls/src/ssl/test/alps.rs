use std::sync::{Arc, Mutex};

use crate::ssl::{select_next_proto, AlpnError, SslVersion};

use super::server::Server;

const H2: &[u8] = b"h2";
const H2_WIRE: &[u8] = b"\x02h2";

#[test]
fn absent_application_settings_are_distinct_from_empty_settings() {
    let mut server = tls13_h2_server();
    let observed = Arc::new(Mutex::new(None));
    server.io_cb({
        let observed = Arc::clone(&observed);
        move |stream| {
            *observed.lock().unwrap() = Some(
                stream
                    .ssl()
                    .peer_application_settings()
                    .map(ToOwned::to_owned),
            );
        }
    });
    let server = server.build();

    let client = tls13_h2_client(&server);
    let stream = client.connect();
    assert_eq!(stream.ssl().peer_application_settings(), None);
    drop(stream);
    drop(server);

    assert_eq!(*observed.lock().unwrap(), Some(None));
}

#[test]
fn negotiated_empty_application_settings_are_present() {
    assert_round_trip(&[], &[]);
}

#[test]
fn nonempty_application_settings_round_trip_exactly() {
    assert_round_trip(b"client settings", b"server settings");
}

fn assert_round_trip(client_settings: &'static [u8], server_settings: &'static [u8]) {
    let mut server = tls13_h2_server();
    server.ssl_cb(move |ssl| {
        ssl.add_application_settings_with_payload(H2, server_settings)
            .unwrap();
        ssl.set_alps_use_new_codepoint(true);
    });
    let observed = Arc::new(Mutex::new(None));
    server.io_cb({
        let observed = Arc::clone(&observed);
        move |stream| {
            *observed.lock().unwrap() = Some(
                stream
                    .ssl()
                    .peer_application_settings()
                    .map(ToOwned::to_owned),
            );
        }
    });
    let server = server.build();

    let client = tls13_h2_client(&server);
    let mut connection = client.build().builder();
    connection
        .ssl()
        .add_application_settings_with_payload(H2, client_settings)
        .unwrap();
    connection.ssl().set_alps_use_new_codepoint(true);
    let stream = connection.connect();
    assert_eq!(
        stream.ssl().peer_application_settings(),
        Some(server_settings)
    );
    drop(stream);
    drop(server);

    assert_eq!(
        *observed.lock().unwrap(),
        Some(Some(client_settings.to_vec()))
    );
}

fn tls13_h2_server() -> super::server::Builder {
    let mut server = Server::builder();
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server.ctx().set_alpn_select_callback(|_, offered| {
        select_next_proto(H2_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    server
}

fn tls13_h2_client(server: &Server) -> super::server::ClientBuilder {
    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client.ctx().set_alpn_protos(H2_WIRE).unwrap();
    client
}
