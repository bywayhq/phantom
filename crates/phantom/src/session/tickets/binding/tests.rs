use std::{error::Error, num::NonZeroUsize, time::Duration};

use phantom_profile::{
    ClientHintSettings, ClientProfile, CookiePlacement, Http3ClientSettings, SessionTickets,
    TlsVersion, TlsVersionRange, TrustAnchorIds, TrustAnchorOrder, TrustAnchorOrders, UdpSettings,
    browser::{chrome, opera},
};

use super::{
    BindingPlan, PreparationError,
    encoding::{Encoder, MAX_POLICY_BYTES},
    profile,
};

type TestResult = Result<(), Box<dyn Error>>;

fn cache_endpoint(host: &str, port: u16) -> Result<crate::authority::Endpoint, Box<dyn Error>> {
    Ok(crate::authority::Endpoint::new(
        format!("{host}:{port}").parse()?,
        port,
    )?)
}

fn client_context<'a>(source: &'a phantom_net::SourceBinding) -> super::TicketClientContext<'a> {
    super::TicketClientContext {
        origin_authentication: phantom_net::ServerAuthentication::WebPki,
        origin_roots: &[],
        proxy_authentication: phantom_net::ServerAuthentication::WebPki,
        proxy_roots: &[],
        default_certificate: None,
        certificate_origins: &[],
        source_binding: source,
        http3_early_data: None,
    }
}

fn route_bytes(route_value: &crate::Route) -> Result<Vec<u8>, PreparationError> {
    let mut e = Encoder::new();
    super::route::encode(&mut e, route_value)?;
    Ok(e.finish())
}

#[test]
fn descriptor_binds_origin_server_cache_leg_and_exact_protocol() -> TestResult {
    use super::descriptor::{TicketCacheLeg as Leg, TicketCacheProtocol as Protocol};
    let source = phantom_net::SourceBinding::new();
    let profile = chrome::v154_windows();
    let prepared = BindingPlan::capture(&profile)?
        .complete(&profile)?
        .with_client_context(client_context(&source))?;
    let origin = cache_endpoint("origin.example", 443)?;
    let other = cache_endpoint("other.example", 443)?;
    let port = cache_endpoint("origin.example", 8443)?;
    let descriptor = |endpoint: &crate::authority::Endpoint, server, leg, protocol| {
        prepared.prepare_cache_descriptor(endpoint, server, leg, protocol, &crate::Route::Direct)
    };
    let first = descriptor(&origin, "origin.example", Leg::Origin, Protocol::Http1)?;
    for changed in [
        descriptor(&other, "origin.example", Leg::Origin, Protocol::Http1)?,
        descriptor(&port, "origin.example", Leg::Origin, Protocol::Http1)?,
        descriptor(&origin, "other.example", Leg::Origin, Protocol::Http1)?,
        descriptor(&origin, "origin.example", Leg::HttpProxy, Protocol::Http1)?,
        descriptor(&origin, "origin.example", Leg::ConnectUdp, Protocol::Http1)?,
        descriptor(&origin, "origin.example", Leg::Origin, Protocol::Http2)?,
        descriptor(&origin, "origin.example", Leg::Origin, Protocol::Negotiated)?,
        descriptor(&origin, "origin.example", Leg::Origin, Protocol::Http3)?,
    ] {
        assert!(first.policy != changed.policy);
    }
    assert!(
        prepared
            .prepare_cache_descriptor(
                &origin,
                "origin.example",
                Leg::Origin,
                Protocol::Http1,
                &crate::Route::Direct
            )?
            .policy
            == first.policy
    );
    Ok(())
}

#[test]
fn descriptor_equal_policy_keeps_different_allowed_draw_witnesses_separate() -> TestResult {
    use super::descriptor::{TicketCacheLeg, TicketCacheProtocol};
    let configured = drawn_profile(TrustAnchorIds::PerClient(candidates()?));
    let source = phantom_net::SourceBinding::new();
    let prepare = |draw| -> Result<super::PreparedTicketPolicy, Box<dyn Error>> {
        let mut actual = configured.clone();
        let plan = BindingPlan::capture(&actual)?;
        actual.draw_per_client(|| Ok::<_, PreparationError>(draw))?;
        Ok(plan
            .complete(&actual)?
            .with_client_context(client_context(&source))?)
    };
    let first = prepare(0)?;
    let second = prepare(u64::MAX)?;
    let origin = cache_endpoint("origin.example", 443)?;
    let descriptor = |prepared: &super::PreparedTicketPolicy| {
        prepared.prepare_cache_descriptor(
            &origin,
            "origin.example",
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http3,
            &crate::Route::Direct,
        )
    };
    let first = descriptor(&first)?;
    let second = descriptor(&second)?;
    assert!(first.policy == second.policy);
    assert!(first.witness != second.witness);
    Ok(())
}

#[test]
fn descriptor_binds_ordered_root_content_and_origin_proxy_roles() -> TestResult {
    use super::descriptor::{TicketCacheLeg, TicketCacheProtocol};
    let source = phantom_net::SourceBinding::new();
    let profile = chrome::v154_windows();
    let endpoint = cache_endpoint("origin.example", 443)?;
    let roots: Vec<Box<[u8]>> = vec![
        Box::from(&b"synthetic-root-a"[..]),
        Box::from(&b"synthetic-root-b"[..]),
    ];
    let reversed = vec![roots[1].clone(), roots[0].clone()];
    let descriptor = |origin_roots, proxy_roots| -> Result<_, PreparationError> {
        let mut input = client_context(&source);
        input.origin_roots = origin_roots;
        input.proxy_roots = proxy_roots;
        BindingPlan::capture(&profile)?
            .complete(&profile)?
            .with_client_context(input)?
            .prepare_cache_descriptor(
                &endpoint,
                "origin.example",
                TicketCacheLeg::Origin,
                TicketCacheProtocol::Http1,
                &crate::Route::Direct,
            )
    };
    let baseline = descriptor(&roots, &[])?;
    assert!(baseline.policy != descriptor(&reversed, &[])?.policy);
    assert!(baseline.policy != descriptor(&[], &roots)?.policy);
    assert!(baseline.policy != descriptor(&roots[..1], &[])?.policy);
    Ok(())
}

#[test]
fn descriptor_binds_source_configuration_and_effective_early_data() -> TestResult {
    use super::descriptor::{TicketCacheLeg as Leg, TicketCacheProtocol};
    let profile = chrome::v154_windows();
    let endpoint = cache_endpoint("origin.example", 443)?;
    let source = phantom_net::SourceBinding::new();
    let v4 = source.clone().with_address("127.0.0.1".parse()?);
    let v6 = source.clone().with_address("::1".parse()?);
    let interface = source.clone().with_interface("synthetic-interface");
    let descriptor = |source, early_data, leg| -> Result<_, PreparationError> {
        let mut input = client_context(source);
        input.http3_early_data = Some(early_data);
        BindingPlan::capture(&profile)?
            .complete(&profile)?
            .with_client_context(input)?
            .prepare_cache_descriptor(
                &endpoint,
                "origin.example",
                leg,
                TicketCacheProtocol::Http3,
                &crate::Route::Direct,
            )
    };
    let baseline = descriptor(&source, false, Leg::Origin)?;
    for source in [&v4, &v6, &interface] {
        assert!(baseline.policy != descriptor(source, false, Leg::Origin)?.policy);
    }
    assert!(baseline.policy != descriptor(&source, true, Leg::Origin)?.policy);
    assert!(
        descriptor(&source, false, Leg::ConnectUdp)?.policy
            == descriptor(&source, true, Leg::ConnectUdp)?.policy
    );
    Ok(())
}

#[test]
fn descriptor_effective_tcp_early_data_requires_direct_origin() -> TestResult {
    use super::descriptor::{TicketCacheLeg as Leg, TicketCacheProtocol as Protocol};
    let source = phantom_net::SourceBinding::new();
    let profile = chrome::v154_windows();
    let mut prepared = BindingPlan::capture(&profile)?
        .complete(&profile)?
        .with_client_context(client_context(&source))?;
    let origin = cache_endpoint("origin.example", 443)?;
    let routes = [
        crate::Route::Direct,
        crate::Route::http_proxy(crate::HttpProxy::new("https://proxy.example")?),
        crate::Route::socks4(crate::Socks4Proxy::new("socks4a://proxy.example")?),
        crate::Route::socks5(crate::Socks5Proxy::new("socks5h://proxy.example")?),
        crate::Route::connect_udp(crate::ConnectUdpProxy::new(
            "https://proxy.example/udp/{target_host}/{target_port}/",
        )?),
    ];
    for route in &routes {
        for leg in [Leg::Origin, Leg::HttpProxy, Leg::ConnectUdp] {
            for protocol in [Protocol::Http1, Protocol::Http2, Protocol::Negotiated] {
                // Isolate the derived flag: the full configured policy must stay bound.
                prepared.tcp_early_data = false;
                let disabled = prepared.prepare_cache_descriptor(
                    &origin,
                    "origin.example",
                    leg,
                    protocol,
                    route,
                )?;
                prepared.tcp_early_data = true;
                let enabled = prepared.prepare_cache_descriptor(
                    &origin,
                    "origin.example",
                    leg,
                    protocol,
                    route,
                )?;
                assert_eq!(
                    disabled.policy != enabled.policy,
                    matches!(route, crate::Route::Direct) && matches!(leg, Leg::Origin)
                );
                assert!(disabled.witness == enabled.witness);
            }
        }
    }
    Ok(())
}

#[test]
fn descriptor_selects_actual_last_wins_certificate_without_binding_unrelated_map() -> TestResult {
    use super::descriptor::{TicketCacheLeg, TicketCacheProtocol};
    let certificate = || -> Result<phantom_net::ClientCertificate, Box<dyn Error>> {
        let generated = rcgen::generate_simple_self_signed(Vec::<String>::new())?;
        Ok(phantom_net::ClientCertificate::from_pem(
            generated.cert.pem().as_bytes(),
            generated.signing_key.serialize_pem().as_bytes(),
        )?)
    };
    let first = certificate()?;
    let selected = certificate()?;
    let unrelated = certificate()?;
    let profile = chrome::v154_windows();
    let client = crate::Client::builder(profile.clone())
        .client_certificate_for("https://ORIGIN.example", first)
        .client_certificate_for("https://origin.example:443", selected.clone())
        .client_certificate_for("https://unrelated.example", unrelated)
        .build()?;
    let same = crate::Client::builder(profile.clone())
        .client_certificate_for("https://origin.example", selected)
        .build()?;
    let none = crate::Client::builder(profile).build()?;
    let endpoint = cache_endpoint("origin.example", 443)?;
    let descriptor = |client: &crate::Client| -> Result<_, Box<dyn Error>> {
        let prepared = client
            .inner
            .ticket_preparation
            .as_ref()
            .map_err(|error| *error)?;
        Ok(prepared.prepare_cache_descriptor(
            &endpoint,
            "origin.example",
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http1,
            &crate::Route::Direct,
        )?)
    };
    let baseline = descriptor(&client)?;
    assert!(baseline.policy == descriptor(&same)?.policy);
    assert!(baseline.policy != descriptor(&none)?.policy);
    Ok(())
}

#[test]
fn http_route_identity_binds_explicit_order_sensitivity_transport_and_credentials() -> TestResult {
    use phantom_net::{proxy::HttpConnectHeader, request::RequestHeader};
    let base = crate::HttpProxy::new("https://proxy.example:443")?;
    let one = RequestHeader::new("X-One", "synthetic-value");
    let two = RequestHeader::new("X-Two", "other-value");
    let first = route_bytes(&crate::Route::http_proxy(
        base.clone().headers(vec![one.clone(), two.clone()]),
    ))?;
    for changed in [
        base.clone().headers(vec![two, one.clone()]),
        base.clone().headers(vec![
            one.clone().sensitive(),
            RequestHeader::new("X-Two", "other-value"),
        ]),
        base.clone().headers(vec![one.clone(), one]),
        base.clone().with_http2_transport()?,
        base.clone()
            .with_basic_auth("synthetic-user", "synthetic-password")?,
        base.clone()
            .with_digest_auth("synthetic-user", "synthetic-password")?,
    ] {
        assert!(first != route_bytes(&crate::Route::http_proxy(changed))?);
    }
    assert!(
        route_bytes(&crate::Route::http_proxy(base.clone()))?
            != route_bytes(&crate::Route::http_proxy(
                base.connect_headers(vec![HttpConnectHeader::authority("Host")])
            ))?
    );
    Ok(())
}

#[test]
fn http_route_identity_preserves_pool_sharing_across_derived_request_fields() -> TestResult {
    let route = crate::Route::http_proxy(crate::HttpProxy::new("http://proxy.example")?);
    let template = chrome::v154_proxy_connect();
    let derived = route
        .with_profile_connect(Some(&template), |name| {
            name.eq_ignore_ascii_case("user-agent").then(|| {
                phantom_net::request::RequestHeader::new("User-Agent", "synthetic-derived-agent")
                    .sensitive()
            })
        })
        .ok_or("missing derived route")?;
    assert!(route == derived);
    assert!(route_bytes(&route)? == route_bytes(&derived)?);
    Ok(())
}

#[test]
fn socks_route_policy_binds_dns_mechanism_and_protocol() -> TestResult {
    let local4 = crate::Socks4Proxy::new("socks4://proxy.example")?;
    let remote4 = crate::Socks4Proxy::new("socks4a://proxy.example")?;
    let local5 = crate::Socks5Proxy::new("socks5://proxy.example")?;
    let remote5 = crate::Socks5Proxy::new("socks5h://proxy.example")?;
    let first = route_bytes(&crate::Route::socks4(local4.clone()))?;
    for changed in [
        crate::Route::socks4(remote4),
        crate::Route::socks5(local5.clone()),
        crate::Route::Direct,
    ] {
        assert!(first != route_bytes(&changed)?);
    }
    assert!(
        first
            == route_bytes(&crate::Route::socks4(
                local4.with_user_id("synthetic-user")?
            ))?
    );
    let first = route_bytes(&crate::Route::socks5(local5.clone()))?;
    assert!(first != route_bytes(&crate::Route::socks5(remote5))?);
    assert!(
        first
            != route_bytes(&crate::Route::socks5(
                local5.with_username_password("synthetic-user", "synthetic-password")?
            ))?
    );
    Ok(())
}

#[test]
fn connect_udp_route_identity_binds_every_template_operator_and_outer_transport() -> TestResult {
    let base =
        crate::ConnectUdpProxy::new("https://proxy.example/udp/{target_host}/{target_port}/")?;
    let first = route_bytes(&crate::Route::connect_udp(base.clone()))?;
    for changed in [
        base.clone().with_http2_transport(),
        base.clone().with_http1_transport(),
        crate::ConnectUdpProxy::new("https://proxy.example/udp/{target_port}/{target_host}/")?,
        crate::ConnectUdpProxy::new("https://proxy.example/udp/{?target_host,target_port}")?,
        crate::ConnectUdpProxy::new("https://proxy.example/udp/?x=1{&target_host,target_port}")?,
        crate::ConnectUdpProxy::new("https://proxy.example/udp2/{target_host}/{target_port}/")?,
        base.clone()
            .with_basic_auth("synthetic-user", "synthetic-password")?,
        base.header(
            phantom_net::request::RequestHeader::new("X-Field", "synthetic-field").sensitive(),
        ),
    ] {
        assert!(first != route_bytes(&crate::Route::connect_udp(changed))?);
    }
    Ok(())
}

#[test]
fn descriptor_custody_and_debug_keep_route_secrets_out_of_diagnostics() -> TestResult {
    use super::descriptor::{TicketCacheLeg, TicketCacheProtocol};
    let source = phantom_net::SourceBinding::new();
    let profile = chrome::v154_windows();
    let prepared = BindingPlan::capture(&profile)?
        .complete(&profile)?
        .with_client_context(client_context(&source))?;
    let endpoint = cache_endpoint("origin.example", 443)?;
    let route = crate::Route::http_proxy(
        crate::HttpProxy::new("https://proxy.example")?
            .header(
                phantom_net::request::RequestHeader::new("X-Secret", "synthetic-secret")
                    .sensitive(),
            )
            .with_digest_auth("synthetic-user", "synthetic-password")?,
    );
    let first = prepared.prepare_cache_descriptor(
        &endpoint,
        "origin.example",
        TicketCacheLeg::Origin,
        TicketCacheProtocol::Http1,
        &route,
    )?;
    let other_prepared = BindingPlan::capture(&profile)?
        .complete(&profile)?
        .with_client_context(client_context(&source))?;
    let other = other_prepared.prepare_cache_descriptor(
        &endpoint,
        "origin.example",
        TicketCacheLeg::Origin,
        TicketCacheProtocol::Http1,
        &route,
    )?;
    assert!(first.policy == other.policy);
    let diagnostic = format!("{first:?} {prepared:?} {route:?}");
    for secret in ["synthetic-user", "synthetic-password", "synthetic-secret"] {
        assert!(!diagnostic.contains(secret));
    }
    Ok(())
}

#[test]
fn oversized_trust_preparation_is_ineligible_without_partial_descriptor() -> TestResult {
    let source = phantom_net::SourceBinding::new();
    let roots = vec![vec![0; MAX_POLICY_BYTES].into_boxed_slice()];
    let mut input = client_context(&source);
    input.origin_roots = &roots;
    let profile = chrome::v154_windows();
    assert!(matches!(
        BindingPlan::capture(&profile)?
            .complete(&profile)?
            .with_client_context(input),
        Err(PreparationError::TooLarge)
    ));
    Ok(())
}

#[cfg(feature = "danger-disable-verification")]
#[test]
fn unverified_client_stays_locally_constructible_but_transfer_ineligible() -> TestResult {
    let client = crate::Client::builder(chrome::v154_windows())
        .server_authentication(phantom_net::ServerAuthentication::DangerDisabled)
        .build()?;
    assert!(matches!(
        client.inner.ticket_preparation,
        Err(PreparationError::Unsupported(
            "disabled server authentication"
        ))
    ));
    assert_eq!(client.clear_session_tickets()?, 0);
    Ok(())
}

fn candidates() -> Result<TrustAnchorOrders, Box<dyn Error>> {
    Ok(TrustAnchorOrders::new(vec![
        TrustAnchorOrder::new(vec![Box::from(&b"a"[..]), Box::from(&b"b"[..])])?,
        TrustAnchorOrder::new(vec![Box::from(&b"b"[..]), Box::from(&b"a"[..])])?,
    ])?)
}

fn drawn_profile(ids: TrustAnchorIds) -> ClientProfile {
    let mut tcp = chrome::v154_tcp_tls();
    tcp.requested_trust_anchor_ids = Some(ids.clone());
    let mut quic = chrome::v154_quic_tls();
    quic.requested_trust_anchor_ids = Some(ids);
    ClientProfile::new(tcp).with_http3(Http3ClientSettings::new(
        quic,
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    ))
}

#[test]
fn equal_policies_allow_independent_tcp_and_quic_client_draws() -> TestResult {
    let configured = drawn_profile(TrustAnchorIds::PerClient(candidates()?));
    let mut first = configured.clone();
    let mut second = configured;
    let first_plan = BindingPlan::capture(&first)?;
    let second_plan = BindingPlan::capture(&second)?;
    let mut first_calls = 0;
    first.draw_per_client(|| {
        first_calls += 1;
        Ok::<_, PreparationError>(if first_calls == 1 { 0 } else { u64::MAX })
    })?;
    let mut second_calls = 0;
    second.draw_per_client(|| {
        second_calls += 1;
        Ok::<_, PreparationError>(if second_calls == 1 { u64::MAX } else { 0 })
    })?;
    let first = first_plan.complete(&first)?;
    let second = second_plan.complete(&second)?;
    assert_eq!(first_calls, 2);
    assert_eq!(second_calls, 2);
    assert!(first.canonical == second.canonical);
    assert!(first.tcp_draw != second.tcp_draw);
    assert!(first.quic_draw != second.quic_draw);
    Ok(())
}

#[test]
fn fixed_per_client_and_per_connection_are_distinct_policies() -> TestResult {
    let orders = candidates()?;
    let fixed = drawn_profile(TrustAnchorIds::Fixed(orders.as_slice()[0].clone()));
    let client = drawn_profile(TrustAnchorIds::PerClient(orders.clone()));
    let connection = drawn_profile(TrustAnchorIds::PerConnection(orders));
    let fixed = profile::encode(&fixed, None, None)?;
    let client = profile::encode(&client, None, None)?;
    let connection = profile::encode(&connection, None, None)?;
    assert!(fixed != client && fixed != connection && client != connection);
    Ok(())
}

#[test]
fn candidate_weights_and_order_survive_the_policy_encoding() -> TestResult {
    let orders = candidates()?;
    let mut weighted = orders.as_slice().to_vec();
    weighted.push(weighted[0].clone());
    let base = drawn_profile(TrustAnchorIds::PerClient(orders.clone()));
    let changed = drawn_profile(TrustAnchorIds::PerClient(TrustAnchorOrders::new(weighted)?));
    let mut reversed = orders.as_slice().to_vec();
    reversed.reverse();
    let reversed = drawn_profile(TrustAnchorIds::PerClient(TrustAnchorOrders::new(reversed)?));
    let base = profile::encode(&base, None, None)?;
    assert!(base != profile::encode(&changed, None, None)?);
    assert!(base != profile::encode(&reversed, None, None)?);
    Ok(())
}

#[test]
fn unselected_or_changed_post_draw_policy_is_rejected() -> TestResult {
    let configured = drawn_profile(TrustAnchorIds::PerClient(candidates()?));
    assert!(matches!(
        BindingPlan::capture(&configured)?.complete(&configured),
        Err(PreparationError::DrawMismatch)
    ));
    let mut sampled = configured.clone();
    sampled.draw_per_client(|| Ok::<_, PreparationError>(0))?;
    let mut changed_tls = sampled.tls().clone();
    changed_tls.close_notify = !changed_tls.close_notify;
    let changed =
        ClientProfile::new(changed_tls).with_http3(sampled.http3().ok_or("missing H3")?.clone());
    assert!(matches!(
        BindingPlan::capture(&configured)?.complete(&changed),
        Err(PreparationError::DrawMismatch)
    ));
    let mut foreign = sampled.tls().clone();
    foreign.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(TrustAnchorOrder::new(vec![
        Box::from(&b"other"[..]),
    ])?));
    let foreign =
        ClientProfile::new(foreign).with_http3(sampled.http3().ok_or("missing H3")?.clone());
    assert!(matches!(
        BindingPlan::capture(&configured)?.complete(&foreign),
        Err(PreparationError::DrawMismatch)
    ));
    Ok(())
}

#[test]
fn per_connection_and_absent_anchor_policies_do_not_add_draws() -> TestResult {
    for configured in [
        drawn_profile(TrustAnchorIds::PerConnection(candidates()?)),
        chrome::v154_windows(),
    ] {
        let plan = BindingPlan::capture(&configured)?;
        let mut sampled = configured;
        let mut calls = 0;
        sampled.draw_per_client(|| {
            calls += 1;
            Ok::<_, PreparationError>(0)
        })?;
        let prepared = plan.complete(&sampled)?;
        assert_eq!(calls, 0);
        assert!(prepared.tcp_draw.is_none() && prepared.quic_draw.is_none());
    }
    Ok(())
}

#[test]
fn all_twelve_profile_members_participate_in_policy_identity() -> TestResult {
    let base = ClientProfile::new(chrome::v154_tcp_tls());
    let changed = [
        base.clone().with_tcp(chrome::v154_tcp()),
        base.clone().with_udp(UdpSettings::default()),
        base.clone().with_dns_cache(chrome::v154_dns_cache()),
        ClientProfile::new(opera::v136_tcp_tls()),
        base.clone().with_http1(chrome::v154_http1()),
        base.clone().with_http2(chrome::v154_http2()),
        base.clone().with_http3(Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        )),
        base.clone()
            .with_client_hints(ClientHintSettings::new(Vec::new())),
        base.clone().with_websocket(chrome::v154_websocket()),
        base.clone()
            .with_proxy_connect(chrome::v154_proxy_connect()),
        base.clone()
            .with_cookie_placement(CookiePlacement::before_fields(["x-placement"])),
        base.clone()
            .with_request_template(chrome::v154_windows_navigation_template()),
    ];
    let base = profile::encode(&base, None, None)?;
    for policy in changed {
        assert!(base != profile::encode(&policy, None, None)?);
    }
    Ok(())
}

#[test]
fn none_and_explicit_empty_trust_anchor_lists_are_distinct() -> TestResult {
    let mut tls = chrome::v154_tcp_tls();
    tls.requested_trust_anchor_ids = None;
    let absent = profile::encode(&ClientProfile::new(tls.clone()), None, None)?;
    tls.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(TrustAnchorOrder::empty()));
    assert!(absent != profile::encode(&ClientProfile::new(tls), None, None)?);
    Ok(())
}

#[test]
fn framing_preserves_boundaries_presence_integer_width_and_fractional_time() -> TestResult {
    let mut e = Encoder::new();
    e.bytes(b"a")?;
    e.bytes(b"bc")?;
    e.option(None::<&u8>, |e, value| e.u8(*value))?;
    e.option(Some(&0_u8), |e, value| e.u8(*value))?;
    e.u16(0x0102)?;
    e.duration(Duration::new(1, 2))?;
    assert!(
        e.finish()
            == vec![
                0, 0, 0, 1, b'a', 0, 0, 0, 2, b'b', b'c', 0, 1, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0,
                0, 0, 2
            ]
    );
    let mut first = Encoder::new();
    first.list(&[b"a".as_slice(), b"bc".as_slice()], |e, value| {
        e.bytes(value)
    })?;
    let mut second = Encoder::new();
    second.list(&[b"ab".as_slice(), b"c".as_slice()], |e, value| {
        e.bytes(value)
    })?;
    assert!(first.finish() != second.finish());
    Ok(())
}

#[test]
fn preparation_bound_rejects_growth_before_changing_the_encoded_buffer() -> TestResult {
    let mut e = Encoder::new();
    e.bytes(&vec![0; MAX_POLICY_BYTES - 4])?;
    assert!(matches!(e.u8(1), Err(PreparationError::TooLarge)));
    assert!(matches!(e.bytes(b""), Err(PreparationError::TooLarge)));
    assert_eq!(e.finish().len(), MAX_POLICY_BYTES);
    let mut oversized = chrome::v154_tcp_tls();
    oversized.alpn_protocols = vec![vec![0; MAX_POLICY_BYTES].into_boxed_slice()];
    assert!(matches!(
        BindingPlan::capture(&ClientProfile::new(oversized)),
        Err(PreparationError::TooLarge)
    ));
    Ok(())
}

#[test]
fn all_twenty_four_tls_fields_change_the_canonical_policy() -> TestResult {
    let base = chrome::v154_tcp_tls();
    let mut changed = Vec::new();
    macro_rules! field {
        ($field:ident, $value:expr) => {{
            let mut value = base.clone();
            value.$field = $value;
            changed.push(value);
        }};
    }
    field!(versions, TlsVersionRange::only(TlsVersion::Tls13));
    field!(
        cipher_suites,
        base.cipher_suites.iter().copied().rev().collect()
    );
    field!(groups, base.groups.iter().copied().rev().collect());
    field!(key_shares, Vec::new());
    field!(
        signature_schemes,
        base.signature_schemes.iter().copied().rev().collect()
    );
    field!(
        delegated_credential_schemes,
        vec![phantom_profile::SignatureScheme::MlDsa44]
    );
    field!(
        alpn_protocols,
        base.alpn_protocols.iter().cloned().rev().collect()
    );
    field!(alps, None);
    field!(certificate_compression, Vec::new());
    field!(session_tickets, SessionTickets::disabled());
    field!(
        session_ticket_order,
        phantom_profile::SessionTicketOrder::OldestFirst
    );
    field!(
        session_ticket_extension_when_resuming,
        !base.session_ticket_extension_when_resuming
    );
    field!(tcp_early_data, !base.tcp_early_data);
    field!(record_size_limit, Some(100));
    field!(
        tls12_extensions_in_tls13_client_hello,
        !base.tls12_extensions_in_tls13_client_hello
    );
    field!(
        requested_trust_anchor_ids,
        Some(TrustAnchorIds::Fixed(TrustAnchorOrder::empty()))
    );
    field!(grease, !base.grease);
    field!(
        grease_signature_algorithms,
        !base.grease_signature_algorithms
    );
    field!(
        extension_order,
        phantom_profile::ClientHelloExtensionOrder::BackendDefault
    );
    field!(ech, phantom_profile::EchSettings::Disabled);
    field!(request_ocsp_staple, !base.request_ocsp_staple);
    field!(
        request_signed_certificate_timestamps,
        !base.request_signed_certificate_timestamps
    );
    field!(aes_hardware, !base.aes_hardware);
    field!(close_notify, !base.close_notify);
    assert_eq!(changed.len(), 24);
    let base = profile::encode(&ClientProfile::new(base), None, None)?;
    for tls in changed {
        assert!(base != profile::encode(&ClientProfile::new(tls), None, None)?);
    }
    Ok(())
}

#[test]
fn preparations_and_errors_keep_profile_field_values_out_of_debug() -> TestResult {
    let mut tls = chrome::v154_tcp_tls();
    tls.alpn_protocols = vec![Box::from(&b"synthetic-profile-value"[..])];
    let profile = ClientProfile::new(tls);
    let prepared = BindingPlan::capture(&profile)?.complete(&profile)?;
    assert!(!format!("{prepared:?}").contains("synthetic-profile-value"));
    assert!(!format!("{}", PreparationError::TooLarge).contains("synthetic-profile-value"));
    Ok(())
}

#[test]
fn all_eighteen_quic_fields_change_policy_identity() -> TestResult {
    let base = chrome::v154_quic();
    let mut changed = Vec::new();
    macro_rules! field {
        ($field:ident, $value:expr) => {{
            let mut value = base.clone();
            value.$field = $value;
            changed.push(value);
        }};
    }
    field!(max_idle_timeout_ms, base.max_idle_timeout_ms + 1);
    field!(max_udp_payload_size, base.max_udp_payload_size + 1);
    field!(initial_max_data, base.initial_max_data + 1);
    field!(
        initial_max_stream_data_bidi_local,
        base.initial_max_stream_data_bidi_local + 1
    );
    field!(
        initial_max_stream_data_bidi_remote,
        base.initial_max_stream_data_bidi_remote + 1
    );
    field!(
        initial_max_stream_data_uni,
        base.initial_max_stream_data_uni + 1
    );
    field!(initial_max_streams_bidi, base.initial_max_streams_bidi + 1);
    field!(initial_max_streams_uni, base.initial_max_streams_uni + 1);
    field!(max_datagram_frame_size, Some(1));
    field!(max_ack_delay_ms, base.max_ack_delay_ms + 1);
    field!(
        active_connection_id_limit,
        base.active_connection_id_limit + 1
    );
    field!(min_ack_delay_us, Some(1));
    field!(reset_stream_at, !base.reset_stream_at);
    field!(initial_path_mtu, Some(1400));
    field!(
        initial_destination_connection_id,
        Some(phantom_profile::QuicConnectionIdLength::Fixed(8))
    );
    field!(
        wire_parameters,
        base.wire_parameters.iter().cloned().rev().collect()
    );
    field!(
        parameter_order,
        phantom_profile::QuicTransportParameterOrder::Fixed
    );
    field!(early_data, !base.early_data);
    assert_eq!(changed.len(), 18);
    let encode = |settings| {
        profile::encode(
            &ClientProfile::new(chrome::v154_tcp_tls()).with_http3(Http3ClientSettings::new(
                chrome::v154_quic_tls(),
                settings,
                chrome::v154_http3(),
                chrome::v154_http3_request(),
            )),
            None,
            None,
        )
    };
    let base = encode(base)?;
    for value in changed {
        assert!(base != encode(value)?);
    }
    Ok(())
}

#[test]
fn all_fifteen_http2_fields_change_policy_identity() -> TestResult {
    let base = chrome::v154_http2();
    let mut changed = Vec::new();
    let priority = phantom_profile::Http2Priority {
        dependency_stream_id: 0,
        weight: 7,
        exclusive: false,
    };
    macro_rules! field {
        ($field:ident, $value:expr) => {{
            let mut value = base.clone();
            value.$field = $value;
            changed.push(value);
        }};
    }
    field!(
        initial_settings,
        base.initial_settings.iter().copied().rev().collect()
    );
    field!(
        initial_connection_window_size,
        base.initial_connection_window_size + 1
    );
    field!(initial_stream_window_target, Some(12_582_912));
    field!(
        pseudo_header_order,
        base.pseudo_header_order.iter().copied().rev().collect()
    );
    field!(extended_connect_pseudo_header_order, None);
    field!(headers_priority, Some(priority));
    field!(extended_connect_priority, Some(priority));
    let mut hpack = base.hpack.clone();
    hpack.huffman_coding = phantom_profile::Http2HuffmanCoding::AlwaysIncludingEmpty;
    field!(hpack, hpack);
    let mut streams = base.streams;
    streams.first_stream_id += 2;
    field!(streams, streams);
    field!(preface_ping_after, Some(Duration::from_secs(9999)));
    field!(ping_timeout, Some(Duration::from_secs(9999)));
    field!(ping_failure_retries, base.ping_failure_retries + 1);
    field!(idle_ping_after, Some(Duration::from_secs(9999)));
    field!(idle_ping_timeout, Some(Duration::from_secs(9999)));
    field!(
        idle_timeout,
        phantom_profile::Http2IdleTimeout::ClosedOnTimer(Duration::from_secs(9999))
    );
    assert_eq!(changed.len(), 15);
    let encode = |settings| {
        profile::encode(
            &ClientProfile::new(chrome::v154_tcp_tls()).with_http2(settings),
            None,
            None,
        )
    };
    let base = encode(base)?;
    for value in changed {
        assert!(base != encode(value)?);
    }
    Ok(())
}

#[test]
fn request_and_websocket_nested_values_are_not_catalog_labels() -> TestResult {
    let base =
        chrome::v154_windows().with_request_template(chrome::v154_windows_navigation_template());
    let bytes = profile::encode(&base, None, None)?;
    let mut request = base.request_template().ok_or("missing template")?.clone();
    request
        .http1_fields
        .push(phantom_profile::RequestField::literal("x-synthetic", "one"));
    assert!(
        bytes
            != profile::encode(
                &base.clone().with_request_template(request.clone()),
                None,
                None
            )?
    );
    request.http1_fields.pop();
    request.requested_client_hint_placement = !request.requested_client_hint_placement;
    assert!(bytes != profile::encode(&base.clone().with_request_template(request), None, None)?);
    let mut ws = base.websocket().ok_or("missing websocket")?.clone();
    ws.permessage_deflate_offer
        .push(phantom_profile::WebSocketDeflateParameter::ClientMaxWindowBits(Some(10)));
    assert!(bytes != profile::encode(&base.clone().with_websocket(ws.clone()), None, None)?);
    ws.permessage_deflate_offer.pop();
    ws.http1_fields.reverse();
    assert!(bytes != profile::encode(&base.clone().with_websocket(ws), None, None)?);
    let mut proxy = base
        .proxy_connect()
        .ok_or("missing proxy template")?
        .clone();
    proxy.http2_rejected = phantom_profile::Http2RejectedConnect::LeaveOpen;
    assert!(bytes != profile::encode(&base.clone().with_proxy_connect(proxy), None, None)?);
    let mut h1 = base.http1().ok_or("missing H1")?.to_owned();
    h1.max_connections_per_origin = NonZeroUsize::new(9).ok_or("zero limit")?;
    assert!(bytes != profile::encode(&base.with_http1(h1), None, None)?);
    Ok(())
}

#[test]
fn absent_http3_template_fields_differ_from_present_empty_fields() -> TestResult {
    let base =
        chrome::v154_windows().with_request_template(chrome::v154_windows_navigation_template());
    let mut template = base.request_template().ok_or("missing template")?.clone();
    template.http3_fields = None;
    let absent = profile::encode(
        &base.clone().with_request_template(template.clone()),
        None,
        None,
    )?;
    template.http3_fields = Some(Vec::new());
    assert!(absent != profile::encode(&base.with_request_template(template), None, None)?);
    Ok(())
}

#[test]
fn draw_failure_keeps_existing_partial_draw_semantics() -> TestResult {
    let mut profile = drawn_profile(TrustAnchorIds::PerClient(candidates()?));
    let _plan = BindingPlan::capture(&profile)?;
    let mut calls = 0;
    let result = profile.draw_per_client(|| {
        calls += 1;
        if calls == 1 {
            Ok(0)
        } else {
            Err(PreparationError::Allocation)
        }
    });
    assert_eq!(calls, 2);
    assert!(matches!(result, Err(PreparationError::Allocation)));
    assert!(matches!(
        profile.tls().requested_trust_anchor_ids.as_ref(),
        Some(TrustAnchorIds::Fixed(_))
    ));
    assert!(matches!(
        profile
            .http3()
            .ok_or("missing H3")?
            .tls()
            .requested_trust_anchor_ids
            .as_ref(),
        Some(TrustAnchorIds::PerClient(_))
    ));
    Ok(())
}

#[test]
fn real_client_construction_retains_ineligible_preparation_without_failing() -> TestResult {
    use phantom_profile::{ClientHint, ClientHintDelivery};

    let profile =
        chrome::v154_windows().with_client_hints(ClientHintSettings::new(vec![ClientHint::new(
            "sec-ch-ua",
            vec![b'a'; MAX_POLICY_BYTES],
            ClientHintDelivery::Default,
        )]));
    profile.client_hints().ok_or("missing hints")?.validate()?;
    let client = crate::Client::builder(profile).build()?;
    assert!(matches!(
        client.inner.ticket_preparation,
        Err(PreparationError::TooLarge)
    ));
    assert_eq!(client.clear_session_tickets()?, 0);
    let owner =
        super::super::TicketOwner::with_preparation(client.inner.ticket_preparation.clone());
    assert!(matches!(
        owner.preparation,
        Some(Err(PreparationError::TooLarge))
    ));
    assert_eq!(owner.clear()?, 0);
    Ok(())
}

#[test]
fn successful_preparation_is_retained_by_the_ticket_owner() -> TestResult {
    let configured = chrome::v154_windows();
    let prepared = std::sync::Arc::new(BindingPlan::capture(&configured)?.complete(&configured)?);
    let expected = prepared.canonical.clone();
    let owner = super::super::TicketOwner::with_preparation(Ok(prepared));
    let actual = owner
        .preparation
        .as_ref()
        .ok_or("missing preparation")?
        .as_ref()
        .map_err(|error| *error)?;
    assert!(actual.canonical == expected);
    assert_eq!(owner.clear()?, 0);
    Ok(())
}

#[test]
fn all_hpack_and_stream_policy_fields_change_identity() -> TestResult {
    use phantom_profile::{
        Http2CookieCrumbs, Http2FieldIndexing, Http2IndexingLimit, Http2NameReference,
        Http2SensitiveProxyAuthorization, Http2StaticNameIndex, Http2TableSizeUpdates,
        Http2UnindexedMatch,
    };

    let base = chrome::v154_http2();
    let encode = |settings| {
        profile::encode(
            &ClientProfile::new(chrome::v154_tcp_tls()).with_http2(settings),
            None,
            None,
        )
    };
    let mut changed = Vec::new();
    macro_rules! hpack {
        ($field:ident, $value:expr) => {{
            let mut value = base.clone();
            value.hpack.$field = $value;
            changed.push((stringify!($field), value));
        }};
    }
    hpack!(literal_pseudo_headers, Vec::new());
    hpack!(static_name_index, Http2StaticNameIndex::Highest);
    hpack!(huffman_coding, phantom_profile::Http2HuffmanCoding::Always);
    hpack!(cookie_crumbs, Http2CookieCrumbs::Whole);
    hpack!(field_indexing, Http2FieldIndexing::Nghttp2);
    hpack!(name_reference, Http2NameReference::OldestDynamic);
    hpack!(unindexed_match, Http2UnindexedMatch::Literal);
    hpack!(indexing_limit, Http2IndexingLimit::Half);
    hpack!(table_size_updates, Http2TableSizeUpdates::EverySetting);
    hpack!(
        sensitive_proxy_authorization,
        Http2SensitiveProxyAuthorization::NeverIndexed
    );
    macro_rules! streams {
        ($field:ident, $value:expr) => {{
            let mut value = base.clone();
            value.streams.$field = $value;
            changed.push((stringify!($field), value));
        }};
    }
    streams!(first_stream_id, 3);
    streams!(assumed_max_concurrent_streams, None);
    streams!(max_concurrent_streams_cap, None);
    assert_eq!(changed.len(), 13);
    let original = encode(base)?;
    for (field, value) in changed {
        assert!(original != encode(value)?, "missing {field}");
    }
    Ok(())
}

#[test]
fn socket_dns_and_quic_parameter_payloads_preserve_values() -> TestResult {
    use phantom_profile::{
        QuicTransportParameter, QuicTransportParameterKind, QuicVarIntWidth, TcpAddressSelection,
        TcpBackupConnection, TcpKeepalive, TcpKeepalivePolicy,
    };

    let encode_tcp = |settings| {
        profile::encode(
            &ClientProfile::new(chrome::v154_tcp_tls()).with_tcp(settings),
            None,
            None,
        )
    };
    let mut tcp = chrome::v154_tcp();
    tcp.keepalive = TcpKeepalivePolicy::Fixed(TcpKeepalive {
        idle: Duration::from_secs(1),
        interval: None,
    });
    let first = encode_tcp(tcp)?;
    tcp.keepalive = TcpKeepalivePolicy::Fixed(TcpKeepalive {
        idle: Duration::from_secs(1),
        interval: Some(Duration::from_secs(1)),
    });
    assert!(first != encode_tcp(tcp)?);
    tcp.address_selection = TcpAddressSelection::Backup(TcpBackupConnection {
        delay: Duration::from_millis(250),
        known_family_backup_timeout: None,
    });
    let first = encode_tcp(tcp)?;
    tcp.address_selection = TcpAddressSelection::Backup(TcpBackupConnection {
        delay: Duration::from_millis(250),
        known_family_backup_timeout: Some(Duration::from_secs(1)),
    });
    assert!(first != encode_tcp(tcp)?);
    let mut dns = chrome::v154_dns_cache();
    let first = profile::encode(
        &ClientProfile::new(chrome::v154_tcp_tls()).with_dns_cache(dns),
        None,
        None,
    )?;
    dns.negative_ttl = Some(Duration::new(1, 2));
    assert!(
        first
            != profile::encode(
                &ClientProfile::new(chrome::v154_tcp_tls()).with_dns_cache(dns),
                None,
                None
            )?
    );
    let mut quic = chrome::v154_quic();
    quic.wire_parameters = vec![QuicTransportParameter {
        kind: QuicTransportParameterKind::MaxIdleTimeout {
            value_width: QuicVarIntWidth::Two,
        },
        id_width: QuicVarIntWidth::One,
        length_width: QuicVarIntWidth::One,
    }];
    let encode_quic = |settings| {
        profile::encode(
            &ClientProfile::new(chrome::v154_tcp_tls()).with_http3(Http3ClientSettings::new(
                chrome::v154_quic_tls(),
                settings,
                chrome::v154_http3(),
                chrome::v154_http3_request(),
            )),
            None,
            None,
        )
    };
    let first = encode_quic(quic.clone())?;
    quic.wire_parameters[0].length_width = QuicVarIntWidth::Two;
    assert!(first != encode_quic(quic.clone())?);
    quic.wire_parameters[0].length_width = QuicVarIntWidth::One;
    quic.wire_parameters[0].kind = QuicTransportParameterKind::MaxIdleTimeout {
        value_width: QuicVarIntWidth::Four,
    };
    assert!(first != encode_quic(quic)?);
    Ok(())
}

mod source_witness;

mod credential_transfer;

#[test]
fn http_route_policy_binds_digest_algorithm_policy_separately_from_values() -> TestResult {
    let sha2 = phantom_net::proxy::HttpDigestCredentials::new("user", "password")?;
    let legacy = sha2
        .clone()
        .with_policy(phantom_net::proxy::DigestPolicy::AllowLegacyMd5);
    let proxy = crate::HttpProxy::new("https://proxy.example")?;
    assert_ne!(
        route_bytes(&crate::Route::http_proxy(
            proxy.clone().with_digest_credentials(sha2)
        ))?,
        route_bytes(&crate::Route::http_proxy(
            proxy.with_digest_credentials(legacy)
        ))?
    );
    Ok(())
}

#[test]
fn opaque_socks_framing_rejects_oversized_input_without_secret_diagnostics() -> TestResult {
    let oversized = vec![b'x'; 64 * 1024];
    let error = Encoder::transfer_credential(b"phantom-ticket-socks4-user-id", &[&oversized])
        .err()
        .ok_or("accepted oversized credential input")?;
    assert_eq!(error, PreparationError::TooLarge);
    assert!(!format!("{error:?} {error}").contains("xxxx"));
    Ok(())
}

mod dns_ttl;
mod tcp_schedule;

#[test]
fn opening_stream_target_values_change_ticket_policy_identity() -> TestResult {
    let base = chrome::v154_http2();
    let advertised = base
        .initial_settings
        .iter()
        .find_map(|setting| match setting {
            phantom_profile::Http2Setting::InitialWindowSize(value) => Some(*value),
            _ => None,
        })
        .ok_or("advertised stream window absent")?;
    let encode = |target| {
        let mut settings = base.clone();
        settings.initial_stream_window_target = target;
        profile::encode(
            &ClientProfile::new(chrome::v154_tcp_tls()).with_http2(settings),
            None,
            None,
        )
    };
    let absent = encode(None)?;
    let equal = encode(Some(advertised))?;
    let higher = encode(Some(advertised + 1))?;
    assert_ne!(absent, equal);
    assert_ne!(absent, higher);
    assert_ne!(equal, higher);
    Ok(())
}

#[test]
fn ticket_policy_distinguishes_each_websocket_refusal_rule() -> TestResult {
    use phantom_profile::WebSocketRefusedStreamRetry;
    let mut encoded = Vec::new();
    for rule in [
        WebSocketRefusedStreamRetry::None,
        WebSocketRefusedStreamRetry::SameSessionOnce,
        WebSocketRefusedStreamRetry::ReacquireTwice,
    ] {
        let mut settings = chrome::v154_websocket();
        settings.connection.refused_stream_retry = rule;
        let profile = chrome::v154_windows().with_websocket(settings);
        encoded.push(profile::encode(&profile, None, None)?);
    }
    assert_ne!(encoded[0], encoded[1]);
    assert_ne!(encoded[0], encoded[2]);
    assert_ne!(encoded[1], encoded[2]);
    Ok(())
}
