use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn builtin(resolv: &str, nss: &str) -> Result<LinuxDnsConfiguration, LinuxConfigurationError> {
    match chromium_linux(resolv.as_bytes(), nss.as_bytes())? {
        LinuxDnsEligibility::BuiltIn(configuration) => Ok(configuration),
        LinuxDnsEligibility::SystemOnly { .. } => {
            Err(LinuxConfigurationError::Invalid("expected built-in"))
        }
    }
}

fn system_only(resolv: &str, nss: &str) -> Result<LinuxDnsIneligibility, LinuxConfigurationError> {
    match chromium_linux(resolv.as_bytes(), nss.as_bytes())? {
        LinuxDnsEligibility::SystemOnly { reasons, .. } => Ok(reasons),
        LinuxDnsEligibility::BuiltIn(_) => {
            Err(LinuxConfigurationError::Invalid("expected system-only"))
        }
    }
}

#[test]
fn preserves_server_order_duplicates_scope_and_libc_effective_limit() -> TestResult {
    let configuration = builtin(
        "nameserver 192.0.2.2\nnameserver fe80::1%7\nnameserver 192.0.2.2\nnameserver 192.0.2.3\n",
        "hosts: files dns",
    )?;
    assert_eq!(
        configuration.servers,
        [
            SocketAddr::from(([192, 0, 2, 2], 53)),
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse()?, 53, 0, 7)),
            SocketAddr::from(([192, 0, 2, 2], 53)),
        ]
    );
    Ok(())
}

#[test]
fn defaults_and_upper_clamps_are_distinct_from_intake_bounds() -> TestResult {
    let configuration = builtin("", "")?;
    assert_eq!(
        configuration.servers,
        [SocketAddr::from((Ipv4Addr::LOCALHOST, 53))]
    );
    assert_eq!(
        (
            configuration.ndots,
            configuration.attempts,
            configuration.rotate
        ),
        (1, 2, false)
    );
    assert!(configuration.search.is_empty());
    let configuration = builtin("options ndots:99 attempts:99 timeout:99 rotate\n", "")?;
    assert_eq!(
        (
            configuration.ndots,
            configuration.attempts,
            configuration.rotate
        ),
        (15, 5, true)
    );
    let configuration = builtin("options ndots:0 attempts:0\n", "")?;
    assert_eq!((configuration.ndots, configuration.attempts), (0, 0));
    Ok(())
}

#[test]
fn last_domain_or_search_wins_without_case_unicode_or_duplicate_rewriting() -> TestResult {
    let configuration = builtin(
        "search old.example\ndomain chosen.example ignored.example\nsearch A.example büro.example A.example\n",
        "",
    )?;
    assert_eq!(
        configuration.search,
        ["A.example", "büro.example", "A.example"]
    );
    let configuration = builtin(
        "search discarded.example\ndomain chosen.example ignored.example\n",
        "",
    )?;
    assert_eq!(configuration.search, ["chosen.example"]);
    Ok(())
}

#[test]
fn effective_search_prefix_obeys_both_native_slots_and_byte_storage() -> TestResult {
    let configuration = builtin("search a b c d e f g\n", "")?;
    assert_eq!(configuration.search, ["a", "b", "c", "d", "e", "f"]);
    let first = "a".repeat(253);
    let configuration = builtin(&format!("search {first} b c\n"), "")?;
    assert_eq!(configuration.search, [first, "b".to_owned()]);
    let configuration = builtin(&format!("search {} later.example\n", "a".repeat(256)), "")?;
    assert!(
        configuration.search.is_empty(),
        "an oversized native prefix must not skip to later suffixes"
    );
    Ok(())
}

#[test]
fn environment_precedence_and_hostname_fallback_are_explicit_inputs() -> TestResult {
    let overrides = LinuxDnsOverrides {
        local_domain: Some("ENV.example second.example\nignored"),
        res_options: Some("ndots:4 attempts:3 -rotate -use-vc"),
        hostname: Some("host.fallback.example"),
        option_syntax: LibcOptionSyntax::Negation,
        ..LinuxDnsOverrides::default()
    };
    let LinuxDnsEligibility::BuiltIn(configuration) = chromium_linux_with_overrides(
        b"search file.example\noptions ndots:2 rotate use-vc\n",
        b"",
        &overrides,
    )?
    else {
        return Err("environment did not clear use-vc".into());
    };
    assert_eq!(configuration.search, ["ENV.example", "second.example"]);
    assert_eq!(
        (
            configuration.ndots,
            configuration.attempts,
            configuration.rotate
        ),
        (4, 3, false)
    );
    let overrides = LinuxDnsOverrides {
        local_domain: Some(""),
        hostname: Some("host.fallback.example"),
        ..LinuxDnsOverrides::default()
    };
    let LinuxDnsEligibility::BuiltIn(configuration) =
        chromium_linux_with_overrides(b"search ignored.example\n", b"", &overrides)?
    else {
        return Err("unexpected system-only".into());
    };
    assert_eq!(configuration.search, [""]);
    let overrides = LinuxDnsOverrides {
        hostname: Some("host.fallback.example"),
        ..LinuxDnsOverrides::default()
    };
    let LinuxDnsEligibility::BuiltIn(configuration) =
        chromium_linux_with_overrides(b"", b"", &overrides)?
    else {
        return Err("unexpected system-only".into());
    };
    assert_eq!(configuration.search, ["fallback.example"]);
    Ok(())
}

#[test]
fn legacy_ipv4_syntax_is_not_misclassified_as_an_invalid_nameserver() -> TestResult {
    let configuration = builtin(
        "nameserver 127.1\nnameserver 0x7f000002\nnameserver 0177.0.0.3\n",
        "",
    )?;
    assert_eq!(
        configuration.servers,
        [
            SocketAddr::from(([127, 0, 0, 1], 53)),
            SocketAddr::from(([127, 0, 0, 2], 53)),
            SocketAddr::from(([127, 0, 0, 3], 53))
        ]
    );
    for value in [
        "256.0.0.1",
        "127.0.65536",
        "0x100000000",
        "08.0.0.1",
        "1..2",
        "1.2.3.4.5",
        "0.0.0.0",
        "::",
    ] {
        assert!(
            chromium_linux(format!("nameserver {value}\n").as_bytes(), b"").is_err(),
            "accepted {value}"
        );
    }
    Ok(())
}

#[test]
fn named_scope_requires_a_matching_owned_index_witness() -> TestResult {
    assert!(matches!(
        chromium_linux(b"nameserver fe80::1%eth0\n", b""),
        Err(LinuxConfigurationError::MissingInterfaceIndex)
    ));
    let overrides = LinuxDnsOverrides {
        interface_indices: &[("eth0", 42), ("eth0", 42)],
        ..LinuxDnsOverrides::default()
    };
    let LinuxDnsEligibility::BuiltIn(configuration) =
        chromium_linux_with_overrides(b"nameserver fe80::1%eth0\n", b"", &overrides)?
    else {
        return Err("unexpected system-only".into());
    };
    assert_eq!(
        configuration.servers,
        [SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse()?,
            53,
            0,
            42
        ))]
    );
    assert!(matches!(
        chromium_linux_with_overrides(b"nameserver 2001:db8::1%eth0\n", b"", &overrides),
        Err(LinuxConfigurationError::Invalid("IPv6 scope"))
    ));
    let configuration = builtin("nameserver 2001:db8::1%42\n", "")?;
    assert_eq!(
        configuration.servers,
        [SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::1".parse()?,
            53,
            0,
            42
        ))]
    );
    let overrides = LinuxDnsOverrides {
        interface_indices: &[("eth0", 2), ("eth0", 3)],
        ..LinuxDnsOverrides::default()
    };
    assert!(matches!(
        chromium_linux_with_overrides(b"", b"", &overrides),
        Err(LinuxConfigurationError::Invalid(
            "conflicting interface witnesses"
        ))
    ));
    Ok(())
}

#[test]
fn only_operative_conversion_flags_disable_builtin_dns() -> TestResult {
    let reasons = system_only("options use-vc\n", "hosts: files dns")?;
    assert!(reasons.use_vc);
    assert!(!reasons.nsswitch);
    let configuration = builtin(
        "# harmless comment\n; another comment\nsortlist 192.0.2.0/24\nunknown-directive ignored\noptions edns0 single-request single-request-reopen no-aaaa trust-ad no-reload no-tld-query strict-error unknown-option\n",
        "hosts: files dns # comment",
    )?;
    assert_eq!(configuration.attempts, 2);
    // glibc uses prefix matches for boolean options, including their negation.
    assert!(system_only("options use-vc-extra\n", "")?.use_vc);
    assert!(builtin("options rotate-extra\n", "")?.rotate);
    assert!(system_only("options use-vc -use-vc\n", "")?.use_vc);
    Ok(())
}

#[test]
fn first_hosts_database_and_default_missing_database_match_chromium() -> TestResult {
    for text in [
        "",
        "passwd: files\n",
        "hosts:\nhosts: bad\n",
        "  HoStS: files dns\nhosts: bad\n",
    ] {
        builtin("", text)?;
    }
    assert!(system_only("", "hosts: bad\nhosts: files dns\n")?.nsswitch);
    // Chrome stops checking after compatible DNS; later services are irrelevant.
    builtin("", "hosts: files dns unknown files dns")?;
    Ok(())
}

#[test]
fn nss_service_and_action_compatibility_preserves_source_rules() -> TestResult {
    for text in [
        "files dns",
        "files [SUCCESS=return] dns",
        "files [!SUCCESS=continue] dns",
        "files mdns4_minimal [NOTFOUND=return] dns",
        "myhostname files dns",
        "files dns [UNAVAIL=merge]",
        "files [SUCCESS=return SUCCESS=return] dns",
    ] {
        builtin("", &format!("hosts: {text}"))?;
    }
    for text in [
        "dns",
        "files files dns",
        "files",
        "mdns files dns",
        "files nis dns",
        "files bad dns",
        "files [SUCCESS=continue] dns",
        "files [NOTFOUND=return] dns",
        "files [SUCCESS=return SUCCESS=continue] dns",
        "files [!SUCCESS=return] dns",
        "files mdns_minimal [UNAVAIL=return] dns",
        "myhostname [NOTFOUND=return] files dns",
        "files dns [SUCCESS=continue]",
        "files [MISSING=return] dns",
        "files [SUCCESS=bad] dns",
    ] {
        assert!(
            system_only("", &format!("hosts: {text}"))?.nsswitch,
            "accepted {text}"
        );
    }
    Ok(())
}

#[test]
fn resolve_service_requires_exact_single_systemd_stub_and_correct_actions() -> TestResult {
    builtin("nameserver 127.0.0.53\n", "hosts: resolve")?;
    builtin(
        "nameserver 127.0.0.53\n",
        "hosts: files resolve [!UNAVAIL=return] dns",
    )?;
    for resolv in [
        "",
        "nameserver 127.0.0.54\n",
        "nameserver 127.0.0.53\nnameserver 127.0.0.53\n",
        "nameserver ::ffff:127.0.0.53\n",
    ] {
        assert!(system_only(resolv, "hosts: resolve dns")?.nsswitch);
    }
    assert!(
        system_only(
            "nameserver 127.0.0.53\n",
            "hosts: resolve [SUCCESS=continue]"
        )?
        .nsswitch
    );
    Ok(())
}

#[test]
fn malformed_input_returns_errors_without_exposing_values() {
    for (resolv, nss) in [
        (b"options ndots:-1\n".as_slice(), b"".as_slice()),
        (b"options attempts:no\n", b""),
        (b"nameserver invalid\n", b""),
        (b"", b"hosts: files [SUCCESS=return dns"),
        (b"", b"hosts: [SUCCESS=return] files dns"),
        (b"", b"hosts: files [[SUCCESS=return]] dns"),
        (b"\xff", b""),
        (b"nameserver 127.0.0.1\0", b""),
    ] {
        assert!(chromium_linux(resolv, nss).is_err());
    }
}

#[test]
fn explicit_intake_limits_do_not_silently_truncate_resource_overflow() {
    assert!(matches!(
        chromium_linux(&vec![b' '; MAX_INPUT_BYTES + 1], b""),
        Err(LinuxConfigurationError::Limit("input bytes"))
    ));
    assert!(matches!(
        chromium_linux(
            format!("search {}\n", "a".repeat(MAX_TOKEN_BYTES + 1)).as_bytes(),
            b""
        ),
        Err(LinuxConfigurationError::Limit("token bytes"))
    ));
    assert!(matches!(
        chromium_linux(
            b"",
            format!("hosts: {}", "files ".repeat(MAX_SERVICES + 1)).as_bytes()
        ),
        Err(LinuxConfigurationError::Limit("NSS service count"))
    ));
    assert!(matches!(
        chromium_linux(
            b"",
            format!(
                "hosts: files [{}] dns",
                "SUCCESS=return ".repeat(MAX_ACTIONS + 1)
            )
            .as_bytes()
        ),
        Err(LinuxConfigurationError::Limit("NSS action count"))
    ));
    assert!(matches!(
        chromium_linux("ignored value\n".repeat(MAX_TOKENS).as_bytes(), b""),
        Err(LinuxConfigurationError::Limit("tokens"))
    ));
}

#[test]
fn debug_reports_shape_without_host_configuration_or_override_values() -> TestResult {
    let marker = format!("private-{}", MAX_INPUT_BYTES);
    let overrides = LinuxDnsOverrides {
        local_domain: Some(&marker),
        res_options: Some("rotate"),
        hostname: Some(&marker),
        interface_indices: &[("eth0", 7)],
        option_syntax: LibcOptionSyntax::Legacy,
    };
    let result =
        chromium_linux_with_overrides(b"nameserver 192.0.2.77\noptions use-vc\n", b"", &overrides)?;
    let eligible = chromium_linux_with_overrides(b"nameserver 192.0.2.77\n", b"", &overrides)?;
    let debug = format!("{overrides:?} {result:?} {eligible:?}");
    assert!(!debug.contains(&marker));
    assert!(!debug.contains("192.0.2.77"));
    assert!(!debug.contains("eth0"));
    assert!(debug.contains("server_count: 1"));
    assert!(debug.contains("use_vc: true"));
    Ok(())
}

#[test]
fn boolean_negation_depends_on_the_supplied_actual_libc_syntax() -> TestResult {
    for syntax in [LibcOptionSyntax::Legacy, LibcOptionSyntax::Negation] {
        let overrides = LinuxDnsOverrides {
            option_syntax: syntax,
            ..LinuxDnsOverrides::default()
        };
        let result = chromium_linux_with_overrides(
            b"options use-vc -use-vc rotate -rotate\n",
            b"",
            &overrides,
        )?;
        match (syntax, result) {
            (LibcOptionSyntax::Legacy, LinuxDnsEligibility::SystemOnly { reasons }) => {
                assert!(reasons.use_vc);
            }
            (LibcOptionSyntax::Negation, LinuxDnsEligibility::BuiltIn(configuration)) => {
                assert!(!configuration.rotate)
            }
            _ => return Err("libc option syntax was ignored".into()),
        }
        // Rotation is observable only for built-in configurations. Check its
        // legacy/negated forms separately from the TCP-only eligibility rule.
        let rotation = chromium_linux_with_overrides(b"options rotate -rotate\n", b"", &overrides)?;
        let LinuxDnsEligibility::BuiltIn(configuration) = rotation else {
            return Err("rotation selected OS-only resolution".into());
        };
        assert_eq!(
            configuration.rotate,
            matches!(syntax, LibcOptionSyntax::Legacy)
        );
    }
    Ok(())
}
