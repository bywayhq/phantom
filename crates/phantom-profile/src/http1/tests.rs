use crate::{chromium, firefox};

#[test]
fn chromium_154_opens_six_http1_connections_per_origin() {
    // `g_max_sockets_per_group` for the normal pool,
    // `net/socket/client_socket_pool_manager.cc:54-58` at `154.0.8037.58`.
    assert_eq!(chromium::v154_http1().max_connections_per_origin.get(), 6);
}

#[test]
fn firefox_156_opens_six_http1_connections_per_origin() {
    // `network.http.max-persistent-connections-per-server`,
    // `modules/libpref/init/all.js:1161` at `FIREFOX_156_0_RELEASE`.
    assert_eq!(firefox::v156_http1().max_connections_per_origin.get(), 6);
}
