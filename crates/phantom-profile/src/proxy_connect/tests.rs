use super::{Http2RejectedConnect, ProxyConnectField, ProxyConnectTemplate};
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
// 153.0.4234.48, and Firefox 156.0. Without credentials the same lists end
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
