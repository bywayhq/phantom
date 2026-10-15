use super::*;
use std::net::{Ipv6Addr, SocketAddrV6};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn adapter(servers: &[&str], suffix: &str, if_type: u32, up: bool) -> AdapterDns {
    AdapterDns {
        if_index: 7,
        ipv6_if_index: 11,
        if_type,
        oper_status: if up { 1 } else { 2 },
        servers: servers
            .iter()
            .map(|value| {
                value
                    .parse()
                    .unwrap_or_else(|error| panic!("fixture server: {error}"))
            })
            .collect(),
        suffix: suffix.to_owned(),
    }
}

fn settings(adapters: Vec<AdapterDns>) -> WindowsDnsSettings {
    WindowsDnsSettings {
        adapters,
        registry: RegistryDnsSettings::default(),
    }
}

fn configuration(eligibility: WindowsDnsEligibility) -> WindowsDnsConfiguration {
    match eligibility {
        WindowsDnsEligibility::BuiltIn(config) => config,
        WindowsDnsEligibility::SystemOnly { .. } => {
            panic!("fixture unexpectedly requires system DNS")
        }
    }
}

#[test]
fn preserves_first_usable_adapter_order_ports_and_ipv6_scope() -> TestResult {
    let mut selected = adapter(
        &["192.0.2.2:0", "192.0.2.1:5353"],
        "connection.example",
        6,
        true,
    );
    selected
        .servers
        .push(SocketAddrV6::new("fe80::1".parse()?, 53, 123, 9).into());
    let expected = vec![
        "192.0.2.2:53".parse()?,
        "192.0.2.1:5353".parse()?,
        SocketAddrV6::new("fe80::1".parse()?, 53, 123, 9).into(),
    ];
    let input = settings(vec![
        adapter(&["192.0.2.9:53"], "down", 6, false),
        adapter(&[], "before.example", 6, true),
        selected,
    ]);
    let config = configuration(chromium_windows(&input)?);
    assert_eq!(config.servers, expected);
    assert_eq!(config.search, ["before.example", "connection.example"]);
    assert_eq!(config.adapter_indices, (7, 11));
    assert_eq!(config.ndots, 1);
    Ok(())
}

#[test]
fn ignores_loopback_for_selection_but_compares_its_up_servers() -> TestResult {
    let input = settings(vec![
        adapter(&["127.0.0.1:53"], "loop", 24, true),
        adapter(&["192.0.2.1:53"], "selected", 6, true),
    ]);
    let WindowsDnsEligibility::SystemOnly {
        configuration,
        reasons,
    } = chromium_windows(&input)?
    else {
        return Err("differing loopback servers accepted".into());
    };
    assert_eq!(configuration.servers, ["192.0.2.1:53".parse()?]);
    assert_eq!(configuration.search, ["selected"]);
    assert!(reasons.differing_nameservers);
    Ok(())
}

#[test]
fn server_set_comparison_ignores_order_and_duplicates_without_reordering_selection() -> TestResult {
    let input = settings(vec![
        adapter(
            &["192.0.2.2:53", "192.0.2.1:53", "192.0.2.2:53"],
            "",
            6,
            true,
        ),
        adapter(&["192.0.2.1:53", "192.0.2.2:53"], "", 6, true),
    ]);
    let config = configuration(chromium_windows(&input)?);
    assert_eq!(
        config.servers,
        [
            "192.0.2.2:53".parse()?,
            "192.0.2.1:53".parse()?,
            "192.0.2.2:53".parse()?
        ]
    );
    Ok(())
}

#[test]
fn records_all_ineligibility_reasons_including_disconnected_ppp() -> TestResult {
    let mut input = settings(vec![
        adapter(&["192.0.2.1:53"], "", 6, true),
        adapter(&["192.0.2.2:53"], "", 6, true),
        adapter(&[], "", 23, false),
    ]);
    input.registry.nrpt_present = true;
    input.registry.proxy_present = true;
    let WindowsDnsEligibility::SystemOnly {
        configuration,
        reasons,
    } = chromium_windows(&input)?
    else {
        return Err("policy accepted".into());
    };
    assert_eq!(
        reasons,
        WindowsDnsIneligibility {
            nrpt: true,
            proxy: true,
            ppp: true,
            differing_nameservers: true
        }
    );
    assert!(configuration.use_local_ipv6);
    Ok(())
}

#[test]
fn filters_only_the_four_pinned_stateless_discovery_addresses() -> TestResult {
    let mut selected = adapter(&[], "", 6, true);
    for last in 0..5 {
        let mut bytes = [0xfe, 0xc0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes[15] = last;
        selected
            .servers
            .push(SocketAddrV6::new(Ipv6Addr::from(bytes), 53, 0, 0).into());
    }
    let expected = selected.servers[4];
    let config = configuration(chromium_windows(&settings(vec![selected]))?);
    assert_eq!(config.servers, [expected]);
    Ok(())
}

#[test]
fn missing_usable_servers_is_an_error_even_with_policy_markers() {
    let mut input = settings(vec![adapter(&[], "suffix", 23, false)]);
    input.registry.nrpt_present = true;
    assert!(matches!(
        chromium_windows(&input),
        Err(ConfigurationError::NoNameserver)
    ));
}

#[test]
fn explicit_search_uses_policy_precedence_and_stops_at_empty_component() -> TestResult {
    let mut input = settings(vec![adapter(&["192.0.2.1:53"], "connection", 6, true)]);
    input.registry.tcpip_search = Some("user.example".into());
    input.registry.policy_search =
        Some("\u{3000}Policy.EXAMPLE\u{85},second.example, ,ignored.example".into());
    let config = configuration(chromium_windows(&input)?);
    assert_eq!(config.search, ["Policy.EXAMPLE", "second.example"]);
    Ok(())
}

#[test]
fn empty_policy_search_suppresses_user_list_but_keeps_primary_and_connection() -> TestResult {
    let mut input = settings(vec![adapter(&["192.0.2.1:53"], "connection", 6, true)]);
    input.registry.policy_search = Some(String::new());
    input.registry.tcpip_search = Some("must-not-appear".into());
    input.registry.primary_suffix = Some(String::new());
    input.registry.tcpip_domain = Some("a.b.example".into());
    let config = configuration(chromium_windows(&input)?);
    assert_eq!(config.search, ["a.b.example", "connection"]);
    Ok(())
}

#[test]
fn devolution_enabled_and_level_precedence_are_independent() -> TestResult {
    let mut input = settings(vec![adapter(&["192.0.2.1:53"], "connection", 6, true)]);
    input.registry.primary_suffix = Some("a.b.c.example".into());
    input.registry.policy_devolution.enabled = Some(1);
    input.registry.cache_devolution.enabled = Some(0);
    input.registry.cache_devolution.level = Some(2);
    input.registry.tcpip_devolution.level = Some(3);
    let config = configuration(chromium_windows(&input)?);
    assert_eq!(
        config.search,
        ["a.b.c.example", "connection", "b.c.example", "c.example"]
    );
    input.registry.policy_devolution.level = Some(3);
    let config = configuration(chromium_windows(&input)?);
    assert_eq!(
        config.search,
        ["a.b.c.example", "connection", "b.c.example"]
    );
    input.registry.policy_devolution.enabled = Some(0);
    let config = configuration(chromium_windows(&input)?);
    assert_eq!(config.search, ["a.b.c.example", "connection"]);
    Ok(())
}

#[test]
fn absent_or_low_devolution_level_never_invents_a_default() -> TestResult {
    for level in [None, Some(0), Some(1)] {
        let mut search = vec!["connection".to_owned()];
        let registry = RegistryDnsSettings {
            tcpip_domain: Some("a.b.c.example".into()),
            policy_devolution: Devolution {
                enabled: None,
                level,
            },
            ..RegistryDnsSettings::default()
        };
        suffix_search(&registry, &mut search)?;
        assert_eq!(search, ["a.b.c.example", "connection"]);
    }
    Ok(())
}

#[test]
fn append_to_multi_label_is_explicit_and_never_implied_by_search() -> TestResult {
    for (flag, expected) in [(None, false), (Some(0), false), (Some(2), true)] {
        let mut input = settings(vec![adapter(&["192.0.2.1:53"], "connection", 6, true)]);
        input.registry.append_to_multi_label = flag;
        assert_eq!(
            configuration(chromium_windows(&input)?).append_to_multi_label,
            expected
        );
    }
    Ok(())
}

#[test]
fn matches_pinned_idna_fixture_preserves_ascii_and_checks_context_j() -> TestResult {
    assert_eq!(
        search_list("\u{017c}\u{f3}\u{0142}ta.pi\u{0119}\u{015b}\u{0107}.pl,pl")?,
        ["xn--ta-4ja03asj.xn--pi-wla5e0q.pl", "pl"]
    );
    assert_eq!(
        domain_ascii("Upper_CASE..example-")?,
        Some("Upper_CASE..example-".into())
    );
    assert_eq!(domain_ascii("fa\u{df}.de")?, Some("xn--fa-hia.de".into()));
    assert_eq!(domain_ascii("a\u{200d}b.example")?, None);
    assert_eq!(search_list("ok,a\u{200d}b.example,never")?, ["ok"]);
    // FEFF is not in pinned base::kWhitespaceWide.
    assert_eq!(search_list("\u{feff}EXAMPLE")?, ["example"]);
    Ok(())
}

#[test]
fn bounds_are_explicit_and_debug_never_formats_configuration_values() -> TestResult {
    let canary = format!("private-{}-suffix", std::process::id());
    let input = settings(vec![adapter(&["192.0.2.17:5301"], &canary, 6, true)]);
    let output = chromium_windows(&input)?;
    for debug in [
        format!("{input:?}"),
        format!("{:#?}", input.adapters[0]),
        format!("{output:#?}"),
    ] {
        assert!(!debug.contains(&canary));
        assert!(!debug.contains("192.0.2.17"));
    }
    assert!(format!("{output:?}").contains("server_count"));
    assert!(matches!(
        domain_ascii(&"a".repeat(MAX_SUFFIX_UNITS)),
        Err(ConfigurationError::Limit(_))
    ));
    let oversized = settings(
        (0..=MAX_ADAPTER_NODES)
            .map(|_| adapter(&[], "", 6, false))
            .collect(),
    );
    assert!(matches!(
        chromium_windows(&oversized),
        Err(ConfigurationError::Limit(_))
    ));
    Ok(())
}

#[test]
fn compatibility_uses_chromium_endpoint_keys_without_changing_output_metadata() -> TestResult {
    let mut first = adapter(&[], "", 6, true);
    first.servers = vec![
        SocketAddrV6::new("2001:db8::1".parse()?, 53, 1, 7).into(),
        SocketAddrV6::new("fe80::1".parse()?, 53, 2, 8).into(),
    ];
    let mut second = adapter(&[], "", 6, true);
    second.servers = vec![
        SocketAddrV6::new("2001:db8::1".parse()?, 53, 3, 9).into(),
        SocketAddrV6::new("fe80::1".parse()?, 53, 4, 8).into(),
    ];
    let expected = first.servers.clone();
    let mut input = settings(vec![first, second]);
    assert_eq!(configuration(chromium_windows(&input)?).servers, expected);
    let SocketAddr::V6(link) = &mut input.adapters[1].servers[1] else {
        return Err("expected IPv6 fixture".into());
    };
    link.set_scope_id(10);
    assert!(matches!(
        chromium_windows(&input)?,
        WindowsDnsEligibility::SystemOnly {
            reasons: WindowsDnsIneligibility {
                differing_nameservers: true,
                ..
            },
            ..
        }
    ));
    Ok(())
}

#[test]
fn each_policy_marker_independently_prevents_builtin_eligibility() -> TestResult {
    for marker in 0..3 {
        let mut input = settings(vec![adapter(&["192.0.2.1:53"], "", 6, true)]);
        match marker {
            0 => input.registry.nrpt_present = true,
            1 => input.registry.proxy_present = true,
            _ => input.adapters.push(adapter(&[], "", 23, false)),
        }
        let WindowsDnsEligibility::SystemOnly { reasons, .. } = chromium_windows(&input)? else {
            return Err("policy marker ignored".into());
        };
        assert_eq!(reasons.nrpt, marker == 0);
        assert_eq!(reasons.proxy, marker == 1);
        assert_eq!(reasons.ppp, marker == 2);
        assert!(!reasons.differing_nameservers);
    }
    Ok(())
}

#[test]
fn ascii_leading_dot_devolution_keeps_the_pinned_delimiter_offset() -> TestResult {
    let registry = RegistryDnsSettings {
        tcpip_domain: Some(".a.b.example".into()),
        policy_devolution: Devolution {
            enabled: None,
            level: Some(2),
        },
        ..RegistryDnsSettings::default()
    };
    let mut search = Vec::new();
    suffix_search(&registry, &mut search)?;
    assert_eq!(search, [".a.b.example", "b.example", "example"]);
    Ok(())
}
