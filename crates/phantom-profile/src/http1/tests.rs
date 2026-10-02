use crate::{chromium, firefox};

#[test]
fn chromium_154_opens_six_http1_connections_per_origin() {
    // `g_max_sockets_per_group` for the normal pool,
    // `net/socket/client_socket_pool_manager.cc:54-58` at `154.0.8037.58`.
    assert_eq!(chromium::v154_http1().max_connections_per_origin.get(), 6);
}

#[test]
fn firefox_157_opens_six_http1_connections_per_origin() {
    // `network.http.max-persistent-connections-per-server`,
    // `modules/libpref/init/all.js:1153` at `FIREFOX_157_0_RELEASE`.
    assert_eq!(firefox::v157_http1().max_connections_per_origin.get(), 6);
}
