use phantom_profile::{
    ClientProfile, CookiePlacement, Http3ClientSettings, TlsVersion,
    browser::{brave, chrome, edge, firefox, opera},
};

#[test]
fn windows_factories_keep_tcp_and_quic_tls_in_their_own_layers() {
    for (name, profile, tcp_tls, quic_tls) in [
        (
            "chrome",
            chrome::v154_windows(),
            chrome::v154_tcp_tls(),
            chrome::v154_quic_tls(),
        ),
        (
            "edge",
            edge::v154_windows(),
            edge::v154_tcp_tls(),
            edge::v154_quic_tls(),
        ),
        (
            "brave",
            brave::v154_windows(),
            brave::v154_tcp_tls(),
            brave::v154_quic_tls(),
        ),
        (
            "opera",
            opera::v136_windows(),
            opera::v136_tcp_tls(),
            opera::v136_quic_tls(),
        ),
        (
            "firefox",
            firefox::v157_windows(),
            firefox::v157_tcp_tls(),
            firefox::v157_quic_tls(),
        ),
    ] {
        assert_eq!(profile.tls(), &tcp_tls, "{name}");
        assert!(
            tcp_tls
                .alpn_protocols
                .iter()
                .any(|value| value.as_ref() == b"http/1.1")
        );
        assert!(
            tcp_tls
                .alpn_protocols
                .iter()
                .any(|value| value.as_ref() == b"h2")
        );
        let http3 = profile.http3().expect("Windows recipe must include HTTP/3");
        assert_eq!(http3.tls(), &quic_tls, "{name}");
        assert_eq!(quic_tls.min_version, TlsVersion::Tls13, "{name}");
        assert_eq!(quic_tls.max_version, TlsVersion::Tls13, "{name}");
        assert_eq!(
            quic_tls.alpn_protocols,
            vec![Box::<[u8]>::from(*b"h3")],
            "{name}"
        );
        assert!(profile.tcp().is_some(), "{name}");
        assert!(profile.http1().is_some(), "{name}");
        assert!(profile.http2().is_some(), "{name}");
        assert!(profile.dns_cache().is_some(), "{name}");
        assert!(profile.websocket().is_some(), "{name}");
        assert!(profile.proxy_connect().is_some(), "{name}");
        assert_eq!(profile.request_template(), None, "{name}");
        if name == "firefox" {
            assert_eq!(profile.client_hints(), None);
            assert_eq!(profile.udp(), None);
            assert_eq!(
                profile.cookie_placement(),
                &firefox::v157_cookie_placement()
            );
        } else {
            assert!(profile.client_hints().is_some(), "{name}");
            assert_eq!(profile.udp(), Some(&chrome::v154_udp()), "{name}");
            assert_eq!(profile.tcp(), Some(&chrome::v154_tcp()), "{name}");
            assert_eq!(
                profile.cookie_placement(),
                &chrome::v154_cookie_placement(),
                "{name}"
            );
        }
    }
}

#[test]
fn android_factories_leave_uncaptured_policies_absent() {
    for (name, profile, tls, has_http2, has_http3, has_hints, has_websocket) in [
        (
            "chrome",
            chrome::v154_android(),
            chrome::v154_android_tcp_tls(),
            true,
            true,
            true,
            true,
        ),
        (
            "edge",
            edge::v153_android(),
            edge::v153_android_tcp_tls(),
            true,
            true,
            true,
            false,
        ),
        (
            "brave",
            brave::v153_android(),
            brave::v153_android_tcp_tls(),
            true,
            true,
            true,
            true,
        ),
        (
            "opera",
            opera::v102_android(),
            opera::v102_android_tcp_tls(),
            false,
            false,
            true,
            false,
        ),
        (
            "firefox",
            firefox::v156_android(),
            firefox::v156_android_tcp_tls(),
            false,
            false,
            false,
            false,
        ),
    ] {
        assert_eq!(profile.tls(), &tls, "{name}");
        assert_eq!(profile.tcp(), None, "{name}");
        assert_eq!(profile.udp(), None, "{name}");
        assert_eq!(profile.http1(), None, "{name}");
        assert_eq!(profile.dns_cache(), None, "{name}");
        assert_eq!(profile.proxy_connect(), None, "{name}");
        assert_eq!(
            profile.cookie_placement(),
            &CookiePlacement::last(),
            "{name}"
        );
        assert_eq!(profile.request_template(), None, "{name}");
        assert_eq!(profile.http2().is_some(), has_http2, "{name}");
        assert_eq!(profile.http3().is_some(), has_http3, "{name}");
        assert_eq!(profile.client_hints().is_some(), has_hints, "{name}");
        assert_eq!(profile.websocket().is_some(), has_websocket, "{name}");
    }
    for (profile, tls) in [
        (chrome::v154_android(), chrome::v154_android_quic_tls()),
        (edge::v153_android(), edge::v153_android_quic_tls()),
        (brave::v153_android(), brave::v153_android_quic_tls()),
    ] {
        assert_eq!(profile.http3().expect("HTTP/3 recipe").tls(), &tls);
        assert_eq!(tls.alpn_protocols, vec![Box::<[u8]>::from(*b"h3")]);
        assert!(!tls.ech_from_https_records);
        assert!(!profile.tls().ech_from_https_records);
    }
}

#[test]
fn composed_profile_keeps_custom_layering_and_template_removal() {
    let profile = chrome::v154_windows();
    let template = chrome::v154_windows_fetch_template();
    let selected = profile.clone().with_request_template(template.clone());
    assert_eq!(selected.request_template(), Some(&template));
    assert_eq!(selected.clone().without_request_template(), profile);

    let mut customized = chrome::v154_http2();
    customized.headers_priority = None;
    let layered = selected.with_http2(customized.clone());
    assert_eq!(layered.http2(), Some(&customized));
    assert_eq!(layered.request_template(), Some(&template));
    assert_eq!(layered.tls(), profile.tls());
    assert_eq!(layered.http3(), profile.http3());
}

#[test]
fn composed_opera_profile_keeps_the_manual_profiles_draws() {
    let mut composed = opera::v136_windows();
    let mut manual =
        ClientProfile::new(opera::v136_tcp_tls()).with_http3(Http3ClientSettings::new(
            opera::v136_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ));
    let mut composed_draws = 0;
    let mut manual_draws = 0;
    composed
        .draw_per_client(|| {
            composed_draws += 1;
            Ok::<_, std::convert::Infallible>(7)
        })
        .expect("infallible draw");
    manual
        .draw_per_client(|| {
            manual_draws += 1;
            Ok::<_, std::convert::Infallible>(7)
        })
        .expect("infallible draw");
    assert_eq!(composed_draws, 1);
    assert_eq!(composed_draws, manual_draws);
    assert_eq!(composed.tls(), manual.tls());
    assert_eq!(composed.http3(), manual.http3());
}
