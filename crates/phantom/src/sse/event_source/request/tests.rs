use crate::HttpProtocol;

use super::default_headers;

#[test]
fn default_headers_preserve_protocol_spelling_and_order() {
    for (protocol, expected_names) in [
        (HttpProtocol::Http1, ["Accept", "Cache-Control"]),
        (HttpProtocol::Http2, ["accept", "cache-control"]),
        (HttpProtocol::Http3, ["accept", "cache-control"]),
    ] {
        let headers = default_headers(protocol);
        assert_eq!(
            headers
                .iter()
                .map(|header| header.name())
                .collect::<Vec<_>>(),
            expected_names
        );
        assert_eq!(headers[0].value(), b"text/event-stream");
        assert_eq!(headers[1].value(), b"no-cache");
    }
}
