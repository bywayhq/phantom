use std::{error::Error, ffi::OsString};

use super::{EnvironmentProxies, EnvironmentProxyErrorKind, MAX_BYPASS_RULES, MAX_VARIABLE_BYTES};
use crate::{
    authority::{Endpoint, parse_absolute_uri},
    route::{HttpProxy, ProxyConfigError, ProxyConfigErrorKind, Route, Socks5DnsMode, Socks5Proxy},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn selected(proxies: &EnvironmentProxies, target: &str) -> TestResult<Route> {
    let uri = parse_absolute_uri(target)?;
    let scheme = uri.scheme_str().ok_or("target has no scheme")?;
    let port = if matches!(scheme, "https" | "wss") {
        443
    } else {
        80
    };
    let endpoint = Endpoint::new(
        uri.authority().cloned().ok_or("target has no authority")?,
        port,
    )?;
    Ok(proxies.route_for(scheme, &endpoint))
}

fn canary() -> TestResult<String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(format!("{timestamp:032x}"))
}

#[test]
fn scheme_specific_routes_precede_all_and_websockets_follow_origin_security() -> TestResult {
    let proxies = EnvironmentProxies::from_values([
        ("HTTP_PROXY", "http://plain.example:8080"),
        ("HTTPS_PROXY", "https://secure.example:8443"),
        ("ALL_PROXY", "socks5h://other.example:1080"),
    ])?;
    let plain = Route::http_proxy(HttpProxy::new("http://plain.example:8080")?);
    let secure = Route::http_proxy(HttpProxy::new("https://secure.example:8443")?);
    for target in ["http://origin.example/", "ws://origin.example/"] {
        assert_eq!(selected(&proxies, target)?, plain);
    }
    for target in ["https://origin.example/", "wss://origin.example/"] {
        assert_eq!(selected(&proxies, target)?, secure);
    }
    assert!(proxies.uses_tls_proxy());
    let all = EnvironmentProxies::from_values([("ALL_PROXY", "socks5h://other.example:1080")])?;
    assert_eq!(
        selected(&all, "https://origin.example/")?,
        Route::socks5(Socks5Proxy::new("socks5h://other.example:1080")?)
    );
    assert!(!all.uses_tls_proxy());
    assert_eq!(
        selected(&EnvironmentProxies::default(), "https://origin.example/")?,
        Route::Direct
    );
    Ok(())
}

#[test]
fn lowercase_presence_wins_even_when_empty_or_shadowing_an_invalid_value() -> TestResult {
    let proxies = EnvironmentProxies::from_values([
        ("HTTP_PROXY", "invalid"),
        ("http_proxy", " "),
        ("HTTPS_PROXY", "invalid"),
        ("https_proxy", "http://lower.example"),
        ("ALL_PROXY", "invalid"),
        ("all_proxy", "http://all.example"),
        ("NO_PROXY", "*"),
        ("no_proxy", ""),
    ])?;
    assert_eq!(
        selected(&proxies, "http://origin.example/")?,
        Route::http_proxy(HttpProxy::new("http://all.example")?)
    );
    assert_eq!(
        selected(&proxies, "https://origin.example/")?,
        Route::http_proxy(HttpProxy::new("http://lower.example")?)
    );
    let empty = EnvironmentProxies::from_values([("ALL_PROXY", "invalid"), ("all_proxy", "")])?;
    assert_eq!(selected(&empty, "https://origin.example/")?, Route::Direct);
    Ok(())
}

#[test]
fn cgi_suppresses_only_uppercase_http_proxy() -> TestResult {
    let proxies = EnvironmentProxies::from_values([
        ("REQUEST_METHOD", ""),
        ("HTTP_PROXY", "invalid"),
        ("HTTPS_PROXY", "https://secure.example"),
        ("ALL_PROXY", "http://all.example"),
    ])?;
    assert_eq!(
        selected(&proxies, "http://origin.example/")?,
        Route::http_proxy(HttpProxy::new("http://all.example")?)
    );
    assert_eq!(
        selected(&proxies, "https://origin.example/")?,
        Route::http_proxy(HttpProxy::new("https://secure.example")?)
    );
    let lower = EnvironmentProxies::from_values([
        ("REQUEST_METHOD", "GET"),
        ("HTTP_PROXY", "invalid"),
        ("http_proxy", "http://lower.example"),
    ])?;
    assert_eq!(
        selected(&lower, "http://origin.example/")?,
        Route::http_proxy(HttpProxy::new("http://lower.example")?)
    );
    assert_eq!(
        EnvironmentProxies::from_values([("HTTP_PROXY", "invalid")])
            .err()
            .ok_or("invalid proxy accepted")?
            .variable(),
        "HTTP_PROXY"
    );
    Ok(())
}

#[test]
fn injected_snapshot_owns_its_values_and_uses_the_last_exact_name() -> TestResult {
    let values = vec![
        ("https_proxy".to_owned(), "http://first.example".to_owned()),
        ("https_proxy".to_owned(), "http://last.example".to_owned()),
        ("HTTPS_proxy".to_owned(), "invalid".to_owned()),
        ("unrelated".to_owned(), "invalid".to_owned()),
    ];
    let proxies =
        EnvironmentProxies::from_values(values.iter().map(|(name, value)| (name, value)))?;
    drop(values);
    assert_eq!(
        selected(&proxies, "https://origin.example/")?,
        Route::http_proxy(HttpProxy::new("http://last.example")?)
    );
    Ok(())
}

#[test]
fn domains_match_only_the_apex_or_dot_boundary_with_idna_and_root_dots() -> TestResult {
    let proxies = EnvironmentProxies::from_values([
        ("all_proxy", "http://proxy.example"),
        (
            "no_proxy",
            " , .EXAMPLE.test., bücher.example, localhost , ",
        ),
    ])?;
    for target in [
        "http://example.test/",
        "https://sub.example.test./",
        "https://BÜCHER.Example/",
        "https://xn--bcher-kva.example/",
        "http://localhost/",
    ] {
        assert_eq!(selected(&proxies, target)?, Route::Direct, "{target}");
    }
    for target in [
        "https://notexample.test/",
        "https://example.test.other/",
        "https://notbücher.example/",
    ] {
        assert_ne!(selected(&proxies, target)?, Route::Direct, "{target}");
    }
    Ok(())
}

#[test]
fn ports_match_effective_origin_ports_and_ipv6_ports_need_brackets() -> TestResult {
    let proxies = EnvironmentProxies::from_values([
        ("all_proxy", "http://proxy.example"),
        (
            "no_proxy",
            "example.test:443,127.0.0.1:80,[::1]:443,2001:db8::1:443",
        ),
    ])?;
    for target in [
        "https://example.test/",
        "https://sub.example.test:443/",
        "http://127.0.0.1/",
        "https://[::1]/",
        "https://[2001:db8::1:443]:8080/",
    ] {
        assert_eq!(selected(&proxies, target)?, Route::Direct, "{target}");
    }
    for target in [
        "http://example.test/",
        "https://127.0.0.1/",
        "http://[::1]/",
        "https://[2001:db8::1]:443/",
    ] {
        assert_ne!(selected(&proxies, target)?, Route::Direct, "{target}");
    }
    Ok(())
}

#[test]
fn cidr_masks_host_bits_and_matches_literals_without_dns_or_cross_family_matching() -> TestResult {
    let proxies = EnvironmentProxies::from_values([
        ("all_proxy", "http://proxy.example"),
        (
            "no_proxy",
            "10.2.3.99/24,2001:db8::123/32,192.0.2.1/32,::1/128",
        ),
    ])?;
    for target in [
        "https://10.2.3.1/",
        "https://[2001:db8:ffff::1]/",
        "https://192.0.2.1/",
        "https://[::1]/",
    ] {
        assert_eq!(selected(&proxies, target)?, Route::Direct, "{target}");
    }
    for target in [
        "https://10.2.4.1/",
        "https://[2001:db9::1]/",
        "https://192.0.2.2/",
        "https://[::2]/",
        "https://[::ffff:10.2.3.1]/",
        "https://10.2.3.example/",
    ] {
        assert_ne!(selected(&proxies, target)?, Route::Direct, "{target}");
    }
    for (network, matching, other) in [
        ("0.0.0.0/0", "https://192.0.2.1/", "https://[::1]/"),
        ("::/0", "https://[2001:db8::1]/", "https://192.0.2.1/"),
    ] {
        let proxies = EnvironmentProxies::from_values([
            ("all_proxy", "http://proxy.example"),
            ("no_proxy", network),
        ])?;
        assert_eq!(selected(&proxies, matching)?, Route::Direct);
        assert_ne!(selected(&proxies, other)?, Route::Direct);
    }
    Ok(())
}

#[test]
fn wildcard_is_intentional_bypass_and_does_not_skip_selected_configuration_validation() -> TestResult
{
    let proxies = EnvironmentProxies::from_values([
        ("all_proxy", "http://proxy.example"),
        ("no_proxy", "example.test,*,::1"),
    ])?;
    assert_eq!(selected(&proxies, "https://other.example/")?, Route::Direct);
    let error = EnvironmentProxies::from_values([("all_proxy", "invalid"), ("no_proxy", "*")])
        .err()
        .ok_or("invalid selected proxy accepted")?;
    assert_eq!(error.variable(), "all_proxy");
    assert_eq!(error.kind(), EnvironmentProxyErrorKind::InvalidProxy);
    Ok(())
}

#[test]
fn invalid_bypass_syntax_is_rejected_without_retaining_the_entry() -> TestResult {
    for value in [
        "http://example.test",
        "example.test/path",
        "*.example.test",
        "example.test?x",
        "example.test#x",
        "user@example.test",
        "[fe80::1%eth0]",
        "fe80::1%25eth0",
        "..example.test",
        "example.test..",
        "a..example.test",
        ".",
        "example.test:",
        "example.test:65536",
        "example.test:+443",
        "[::1]:",
        "[::1]:abc",
        "example.test/24",
        "10.0.0.1/33",
        "::1/129",
        "::1/-1",
        "::1/",
        "[::1]/128",
        "10.0.0.1/24:80",
        "example.test\n",
        "127.01",
    ] {
        let error = EnvironmentProxies::from_values([("no_proxy", value)])
            .err()
            .ok_or("invalid bypass accepted")?;
        assert_eq!(
            error.kind(),
            EnvironmentProxyErrorKind::InvalidBypassRule,
            "{value}"
        );
        assert_eq!(error.variable(), "no_proxy");
        assert!(error.source().is_none());
    }
    Ok(())
}

#[test]
fn credentials_decode_strictly_preserve_plus_and_retain_route_identity() -> TestResult {
    let password = canary()?;
    for scheme in ["http", "https", "socks5", "socks5h"] {
        let url = format!("{scheme}://u%2Bname:p%3A{password}+@proxy.example:8080");
        let proxies = EnvironmentProxies::from_values([("all_proxy", &url)])?;
        let route = selected(&proxies, "https://origin.example/")?;
        let decoded = format!("p:{password}+");
        let expected = if matches!(scheme, "http" | "https") {
            Route::http_proxy(
                HttpProxy::new(&format!("{scheme}://proxy.example:8080"))?
                    .with_basic_auth("u+name", &decoded)?,
            )
        } else {
            let proxy = Socks5Proxy::new(&format!("{scheme}://proxy.example:8080"))?
                .with_username_password("u+name", &decoded)?;
            assert_eq!(
                proxy.dns_mode(),
                if scheme == "socks5" {
                    Socks5DnsMode::Local
                } else {
                    Socks5DnsMode::Remote
                }
            );
            Route::socks5(proxy)
        };
        assert_eq!(route, expected);
        let other = EnvironmentProxies::from_values([(
            "all_proxy",
            format!("{scheme}://u%2Bname:{password}@proxy.example:8080"),
        )])?;
        assert_ne!(route, selected(&other, "https://origin.example/")?);
        let debug = format!("{proxies:?}");
        assert!(!debug.contains(&url));
        assert!(!debug.contains(&password));
        assert!(!debug.contains("proxy.example"));
    }
    Ok(())
}

#[test]
fn unicode_credentials_and_byte_limits_use_the_existing_proxy_validators() -> TestResult {
    let password = canary()?;
    let url = format!("SOCKS5H://%E7%94%A8%E6%88%B7:{password}%40@[::1]:1080");
    let proxies = EnvironmentProxies::from_values([("all_proxy", &url)])?;
    let expected = Route::socks5(
        Socks5Proxy::new("socks5h://[::1]:1080")?
            .with_username_password("用户", format!("{password}@"))?,
    );
    assert_eq!(selected(&proxies, "https://origin.example/")?, expected);
    let http = format!("http://%E7%94%A8%E6%88%B7:{password}@proxy.example");
    let error = EnvironmentProxies::from_values([("all_proxy", http)])
        .err()
        .ok_or("non-ASCII Basic username accepted")?;
    assert_eq!(error.kind(), EnvironmentProxyErrorKind::InvalidCredentials);
    assert!(
        error
            .source()
            .is_some_and(|source| source.is::<ProxyConfigError>())
    );

    let username = format!("{}a", "é".repeat(127));
    let maximum_password = password.repeat(8)[..255].to_owned();
    let url = format!("socks5://{username}:{maximum_password}@proxy.example");
    let proxies = EnvironmentProxies::from_values([("all_proxy", &url)])?;
    assert_eq!(
        selected(&proxies, "https://origin.example/")?,
        Route::socks5(
            Socks5Proxy::new("socks5://proxy.example")?
                .with_username_password(&username, &maximum_password)?,
        )
    );
    for (username, password) in [
        ("é".repeat(128), password.clone()),
        ("user".to_owned(), password.repeat(8)),
    ] {
        let url = format!("socks5://{username}:{password}@proxy.example");
        let error = EnvironmentProxies::from_values([("all_proxy", &url)])
            .err()
            .ok_or("oversized SOCKS credential accepted")?;
        assert_eq!(error.kind(), EnvironmentProxyErrorKind::InvalidCredentials);
    }
    let oversized_basic = format!("http://user:{}@proxy.example", password.repeat(800));
    let error = EnvironmentProxies::from_values([("all_proxy", oversized_basic)])
        .err()
        .ok_or("oversized Basic field accepted")?;
    assert_eq!(error.kind(), EnvironmentProxyErrorKind::InvalidCredentials);
    Ok(())
}

#[test]
fn malformed_or_rejected_credentials_are_recoverable_and_redacted() -> TestResult {
    let password = canary()?;
    for userinfo in [
        format!("user:{password}%"),
        format!("user:{password}%ff"),
        format!("user:{password}%0a"),
        format!("user:{password}%0"),
        format!("user:{password}%GG"),
        format!("user:{password}%c2%85"),
        format!(":{password}"),
        format!("u%3Aser:{password}"),
        format!("user:{password}@other"),
    ] {
        let value = format!("http://{userinfo}@proxy.example");
        let error = EnvironmentProxies::from_values([("HTTPS_PROXY", &value)])
            .err()
            .ok_or("invalid credentials accepted")?;
        assert_eq!(error.variable(), "HTTPS_PROXY");
        assert_eq!(error.kind(), EnvironmentProxyErrorKind::InvalidCredentials);
        let mut output = format!("{error} {error:?}");
        let mut source = error.source();
        while let Some(error) = source {
            output.push_str(&format!(" {error} {error:?}"));
            source = error.source();
        }
        assert!(!output.contains(&value));
        assert!(!output.contains(&password));
    }
    let empty = EnvironmentProxies::from_values([("all_proxy", "http://user@proxy.example")])?;
    assert!(matches!(
        selected(&empty, "https://origin.example/")?,
        Route::HttpProxy(_)
    ));
    assert_eq!(
        EnvironmentProxies::from_values([("all_proxy", "socks5://user@proxy.example")])
            .err()
            .ok_or("empty SOCKS password accepted")?
            .kind(),
        EnvironmentProxyErrorKind::InvalidCredentials
    );
    let long = format!("socks5h://user:{}@proxy.example", password.repeat(9));
    assert_eq!(
        EnvironmentProxies::from_values([("all_proxy", long)])
            .err()
            .ok_or("oversized SOCKS password accepted")?
            .kind(),
        EnvironmentProxyErrorKind::InvalidCredentials
    );
    Ok(())
}

#[test]
fn proxy_schemes_and_paths_use_typed_errors_without_direct_fallback() -> TestResult {
    for value in [
        "socks4://proxy.example",
        "masque://proxy.example",
        "ftp://proxy.example",
    ] {
        assert_eq!(
            EnvironmentProxies::from_values([("all_proxy", value)])
                .err()
                .ok_or("unsupported scheme accepted")?
                .kind(),
            EnvironmentProxyErrorKind::UnsupportedProxyScheme
        );
    }
    let password = canary()?;
    let value = format!("http://user:{password}@proxy.example/secret?value={password}");
    let error = EnvironmentProxies::from_values([("http_proxy", &value)])
        .err()
        .ok_or("invalid proxy path accepted")?;
    assert_eq!(error.kind(), EnvironmentProxyErrorKind::InvalidProxy);
    let source = error
        .source()
        .and_then(|source| source.downcast_ref::<ProxyConfigError>())
        .ok_or("missing typed proxy source")?;
    assert_eq!(source.kind(), ProxyConfigErrorKind::UnexpectedPath);
    assert!(!format!("{error:?} {error} {source:?} {source}").contains(&password));
    Ok(())
}

#[test]
fn selected_size_bounds_are_enforced_but_shadowed_values_are_ignored() -> TestResult {
    let large = "x".repeat(MAX_VARIABLE_BYTES + 1);
    assert_eq!(
        EnvironmentProxies::from_values([("no_proxy", &large)])
            .err()
            .ok_or("oversized variable accepted")?
            .kind(),
        EnvironmentProxyErrorKind::TooLarge
    );
    assert!(
        EnvironmentProxies::from_values([("NO_PROXY", large.as_str()), ("no_proxy", "")]).is_ok()
    );
    let list = vec!["a"; MAX_BYPASS_RULES].join(",");
    assert!(EnvironmentProxies::from_values([("no_proxy", list.as_str())]).is_ok());
    assert_eq!(
        EnvironmentProxies::from_values([("no_proxy", format!("{list},a"))])
            .err()
            .ok_or("oversized list accepted")?
            .kind(),
        EnvironmentProxyErrorKind::TooLarge
    );
    Ok(())
}

#[cfg(unix)]
fn non_unicode() -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(vec![0xff])
}

#[cfg(windows)]
fn non_unicode() -> OsString {
    use std::os::windows::ffi::OsStringExt;
    OsString::from_wide(&[0xd800])
}

#[cfg(any(unix, windows))]
#[test]
fn non_unicode_selected_values_fail_without_exposing_os_bytes() -> TestResult {
    let error = EnvironmentProxies::from_values([("https_proxy", non_unicode())])
        .err()
        .ok_or("non-Unicode value accepted")?;
    assert_eq!(error.kind(), EnvironmentProxyErrorKind::NonUnicodeValue);
    assert!(error.source().is_none());
    assert!(
        EnvironmentProxies::from_values([
            (OsString::from("HTTPS_PROXY"), non_unicode()),
            (OsString::from("https_proxy"), OsString::new()),
        ])
        .is_ok()
    );
    assert!(
        EnvironmentProxies::from_values([
            (OsString::from("HTTP_PROXY"), non_unicode()),
            (OsString::from("REQUEST_METHOD"), OsString::new()),
        ])
        .is_ok()
    );
    Ok(())
}
