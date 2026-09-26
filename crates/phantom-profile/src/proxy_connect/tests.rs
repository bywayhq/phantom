use std::collections::{HashMap, HashSet};

use super::{Http2ProxyConnections, Http2RejectedConnect, ProxyConnectField, ProxyConnectTemplate};
use crate::{chromium, firefox};

#[test]
fn every_connect_recipe_is_valid() {
    for template in [
        chromium::v154_proxy_connect(),
        firefox::v156_proxy_connect(),
    ] {
        assert_eq!(template.validate(), Ok(()));
    }
}

// Field names of the CONNECT requests for the page's own origin in
// `fixtures/proxy/<browser>/<version>/windows-11-26200/`: the
// `http-proxy-auth-*` HTTP/1.1 CONNECTs and the `https-proxy-auth-*` HTTP/2
// CONNECTs, three agreeing runs each, from Chrome 154.0.8037.58, Edge
// 154.0.4258.37, and Firefox 156.0. Without credentials the same lists end
// before `Proxy-Authorization`.
#[test]
fn connect_recipes_name_the_captured_fields_in_order() {
    let names = |fields: &[ProxyConnectField]| -> Vec<String> {
        fields.iter().map(|field| field.name().to_owned()).collect()
    };
    let chromium = chromium::v154_proxy_connect();
    assert_eq!(
        names(&chromium.http1_fields),
        [
            "Host",
            "Proxy-Connection",
            "User-Agent",
            "Proxy-Authorization"
        ]
    );
    let firefox = firefox::v156_proxy_connect();
    assert_eq!(
        names(&firefox.http1_fields),
        [
            "User-Agent",
            "Proxy-Connection",
            "Connection",
            "Host",
            "Proxy-Authorization"
        ]
    );
    for template in [&chromium, &firefox] {
        assert_eq!(
            names(&template.http2_fields),
            ["user-agent", "proxy-authorization"]
        );
        assert!(matches!(
            template
                .http1_fields
                .iter()
                .find(|field| field.name() == "User-Agent"),
            Some(ProxyConnectField::FromRequest { .. })
        ));
    }
}

#[test]
fn validation_rejects_missing_or_misplaced_placeholders() {
    let valid = || ProxyConnectTemplate {
        http1_fields: vec![
            ProxyConnectField::authority("Host"),
            ProxyConnectField::proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![ProxyConnectField::proxy_authorization(
            "proxy-authorization",
        )],
        http2_rejected: Http2RejectedConnect::EndStream,
        http2_connections: Http2ProxyConnections::Shared,
    };
    assert_eq!(valid().validate(), Ok(()));

    let cases: [fn(&mut ProxyConnectTemplate); 10] = [
        |template| {
            template.http1_fields.remove(0);
        },
        |template| {
            template.http1_fields.pop();
        },
        |template| {
            template
                .http1_fields
                .push(ProxyConnectField::authority("host"));
        },
        |template| {
            template
                .http2_fields
                .push(ProxyConnectField::authority("host"));
        },
        |template| {
            template
                .http1_fields
                .push(ProxyConnectField::literal("Host", "example.com:443"));
        },
        |template| {
            template
                .http1_fields
                .push(ProxyConnectField::literal("Content-Length", "0"));
        },
        |template| {
            template
                .http1_fields
                .push(ProxyConnectField::literal("X-Probe", "a\r\nb"));
        },
        |template| {
            template
                .http2_fields
                .push(ProxyConnectField::literal("proxy-connection", "keep-alive"));
        },
        |template| {
            template
                .http2_fields
                .push(ProxyConnectField::from_request("User-Agent"));
        },
        |template| {
            template
                .http1_fields
                .push(ProxyConnectField::from_request("proxy-authorization"));
        },
    ];
    for (index, change) in cases.into_iter().enumerate() {
        let mut template = valid();
        change(&mut template);
        assert!(template.validate().is_err(), "case {index}");
    }
}

#[test]
fn validation_refuses_to_copy_origin_credentials_into_connect() {
    let valid = || ProxyConnectTemplate {
        http1_fields: vec![
            ProxyConnectField::authority("Host"),
            ProxyConnectField::proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![ProxyConnectField::proxy_authorization(
            "proxy-authorization",
        )],
        http2_rejected: Http2RejectedConnect::EndStream,
        http2_connections: Http2ProxyConnections::Shared,
    };
    for name in [
        "Authorization",
        "authorization",
        "Cookie",
        "cookie2",
        "Proxy-Authorization",
    ] {
        let mut template = valid();
        template
            .http1_fields
            .push(ProxyConnectField::from_request(name));
        assert_eq!(
            template.validate().map_err(|error| error.field()),
            Err("http1_fields"),
            "{name}"
        );
        let mut template = valid();
        template.http2_fields.insert(
            0,
            ProxyConnectField::from_request(name.to_ascii_lowercase()),
        );
        assert_eq!(
            template.validate().map_err(|error| error.field()),
            Err("http2_fields"),
            "{name}"
        );
    }
    let mut template = valid();
    template
        .http1_fields
        .push(ProxyConnectField::from_request("User-Agent"));
    assert_eq!(template.validate(), Ok(()));
}

/// What one captured page request asked the proxy for.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Purpose {
    /// A forwarded `http://` request: the navigation, a `fetch()`, or a probe.
    Forward,
    /// A CONNECT for an `https://` `fetch()`.
    Tunnel,
    /// A CONNECT for a `ws://` or `wss://` opening.
    WebSocket,
}

/// Returns, for each run of one `https-proxy-*` capture, the proxy
/// connection of every page request with its purpose.
fn captured_connections(capture: &str) -> Vec<Vec<(String, Purpose)>> {
    let fields: HashMap<&str, &str> = capture
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let count = |key: String| {
        fields
            .get(key.as_str())
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
    };
    (0..count("repeat_count".to_owned()))
        .map(|run| {
            (0..count(format!("run_{run}_request_count")))
                .filter_map(|index| {
                    let request = fields.get(format!("run_{run}_request_{index}").as_str())?;
                    let part = |name: &str| {
                        request
                            .split(',')
                            .find_map(|part| part.strip_prefix(name))
                            .unwrap_or_default()
                    };
                    let purpose = match part("kind:") {
                        "page" | "probe" | "ready" | "done" => Purpose::Forward,
                        "https-connect" => Purpose::Tunnel,
                        "connect" | "wss-connect" => Purpose::WebSocket,
                        // Background traffic, and the Upgrade inside a tunnel.
                        _ => return None,
                    };
                    Some((part("connection:").to_owned(), purpose))
                })
                .collect()
        })
        .collect()
}

// In every run of every `https-proxy-*` capture, Chrome 154, Edge 154, Brave
// 154, and Opera 135 send all of a page's requests on one HTTP/2 proxy
// connection, and Firefox 156 gives forwarded requests, `https://` CONNECTs,
// and WebSocket CONNECTs a connection each.
#[test]
fn connection_sharing_follows_the_captured_proxy_connections()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/proxy");
    let mut checked = 0;
    for (browser, recipe) in [
        ("chrome/154.0.8037.58", chromium::v154_proxy_connect()),
        ("edge/154.0.4258.37", chromium::v154_proxy_connect()),
        ("brave/154.1.96.59", chromium::v154_proxy_connect()),
        ("opera/135.0.5973.92", chromium::v154_proxy_connect()),
        ("firefox/156.0", firefox::v156_proxy_connect()),
    ] {
        let directory = root.join(browser).join("windows-11-26200");
        for entry in std::fs::read_dir(&directory)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if !name.starts_with("https-proxy-") {
                continue;
            }
            for run in captured_connections(&std::fs::read_to_string(&path)?) {
                let connections: HashSet<&str> = run
                    .iter()
                    .map(|(connection, _)| connection.as_str())
                    .collect();
                let purposes: HashSet<Purpose> = run.iter().map(|(_, purpose)| *purpose).collect();
                // A page with one kind of request shows nothing about sharing.
                if purposes.len() < 2 {
                    continue;
                }
                let pairs: HashSet<(&str, Purpose)> = run
                    .iter()
                    .map(|(connection, purpose)| (connection.as_str(), *purpose))
                    .collect();
                let captured = if connections.len() == 1 {
                    Http2ProxyConnections::Shared
                } else if pairs.len() == purposes.len() && connections.len() == purposes.len() {
                    Http2ProxyConnections::ByPurpose
                } else {
                    return Err(format!("{browser} {name} mixes purposes: {run:?}").into());
                };
                assert_eq!(recipe.http2_connections, captured, "{browser} {name}");
                checked += 1;
            }
        }
    }
    // Six scenarios with more than one kind of request, three runs each, for
    // five browsers.
    assert_eq!(checked, 90);
    Ok(())
}
