use crate::{
    proxy::{
        HttpBasicCredentials, HttpConnectError, HttpConnectHeader, HttpProxyAuthentication,
        http1_opening::{ProxyBinding, ProxyOpeningError},
    },
    request::RequestHeader,
    route::{Endpoint, HttpConnectRoute, ProxyTransport},
};

#[test]
fn connect_binding_allows_current_fields_but_not_another_endpoint_or_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let first = [HttpConnectHeader::authority("host")];
    let current = [
        HttpConnectHeader::field(RequestHeader::new("x-claim", "current")),
        HttpConnectHeader::authority("host"),
    ];
    let route = HttpConnectRoute {
        speculative_tls: false,
        proxy: ProxyTransport::Tcp(Endpoint {
            host: "PROXY.example",
            port: 8080,
        }),
        authority: "origin.example:443",
        headers: &first,
        credentials: None,
    };
    let binding = match ProxyBinding::new(route, "origin.example") {
        Ok(binding) => binding,
        Err(_) => return Err("valid original binding failed".into()),
    };
    assert!(
        binding
            .validate_connect(HttpConnectRoute {
                speculative_tls: false,
                headers: &current,
                proxy: ProxyTransport::Tcp(Endpoint {
                    host: "proxy.example",
                    port: 8080
                }),
                ..route
            })
            .is_ok()
    );
    assert!(matches!(
        binding.validate_connect(HttpConnectRoute {
            speculative_tls: false,
            authority: "other.example:443",
            ..route
        }),
        Err(ProxyOpeningError::Binding(_))
    ));
    assert!(matches!(
        binding.validate_connect(HttpConnectRoute {
            speculative_tls: false,
            proxy: ProxyTransport::Tcp(Endpoint {
                host: "proxy.example",
                port: 8081
            }),
            ..route
        }),
        Err(ProxyOpeningError::Binding(_))
    ));
    assert!(matches!(
        binding.validate_connect(HttpConnectRoute {
            speculative_tls: false,
            headers: &[],
            ..route
        }),
        Err(ProxyOpeningError::Proxy(
            HttpConnectError::MissingAuthorityHeader
        ))
    ));
    assert_eq!(
        binding.server_name().map_err(|_| "missing original name")?,
        "origin.example"
    );
    Ok(())
}

#[test]
fn connect_binding_retains_credentials_and_validates_their_current_placeholder()
-> Result<(), Box<dyn std::error::Error>> {
    let original = HttpBasicCredentials::new("user", "first")?;
    let changed = HttpBasicCredentials::new("user", "second")?;
    let fields = [
        HttpConnectHeader::authority("host"),
        HttpConnectHeader::proxy_authorization("proxy-authorization"),
    ];
    let route = HttpConnectRoute {
        speculative_tls: false,
        proxy: ProxyTransport::Tcp(Endpoint {
            host: "proxy.example",
            port: 8080,
        }),
        authority: "origin.example:443",
        headers: &fields,
        credentials: Some(HttpProxyAuthentication::Basic(&original)),
    };
    let binding = match ProxyBinding::new(route, "origin.example") {
        Ok(binding) => binding,
        Err(_) => return Err("valid credential binding failed".into()),
    };
    assert!(binding.validate_connect(route).is_ok());
    for credentials in [None, Some(HttpProxyAuthentication::Basic(&changed))] {
        assert!(matches!(
            binding.validate_connect(HttpConnectRoute {
                speculative_tls: false,
                credentials,
                ..route
            }),
            Err(ProxyOpeningError::Binding(_))
        ));
    }
    assert!(binding.validate_forward(route.proxy).is_err());
    Ok(())
}
