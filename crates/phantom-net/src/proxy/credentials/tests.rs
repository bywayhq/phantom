use super::*;
use crate::proxy::DigestPolicy;
use btls::ssl::{
    SessionTransferCredential, SessionTransferPolicy, SslConnector, SslMethod, SslSessionScope,
};

// Native comparison checks opaque inputs without adding a credential accessor.
fn equivalent(left: SessionTransferCredential, right: SessionTransferCredential) -> bool {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.enable_scoped_client_sessions();
    let connector = builder.build();
    let context = connector.context();
    let scope = SslSessionScope::default();
    let policy = |input, key| {
        SessionTransferPolicy::new(b"synthetic policy", &[], Some(input), &key).unwrap()
    };
    scope
        .bind_transfer_policy(context, "peer.example", policy(left, [1; 32]))
        .unwrap();
    scope
        .bind_transfer_policy(context, "peer.example", policy(right, [1; 32]))
        .is_ok()
}

#[test]
fn credential_input_binds_mechanism_values_and_digest_policy() {
    let basic = HttpBasicCredentials::new("synthetic-user", "synthetic-password").unwrap();
    let digest = HttpDigestCredentials::new("synthetic-user", "synthetic-password").unwrap();
    let input = |credentials: HttpProxyAuthentication<'_>| {
        credentials.session_transfer_credential().unwrap()
    };
    assert!(equivalent(
        input(HttpProxyAuthentication::Basic(&basic)),
        input(HttpProxyAuthentication::Basic(&basic.clone()))
    ));
    assert!(!equivalent(
        input(HttpProxyAuthentication::Basic(&basic)),
        input(HttpProxyAuthentication::Digest(&digest))
    ));
    assert!(equivalent(
        input(HttpProxyAuthentication::Digest(&digest)),
        input(HttpProxyAuthentication::Digest(&digest.clone()))
    ));
    let separate = HttpDigestCredentials::new("synthetic-user", "synthetic-password").unwrap();
    assert!(equivalent(
        input(HttpProxyAuthentication::Digest(&digest)),
        input(HttpProxyAuthentication::Digest(&separate))
    ));
    let legacy = digest.clone().with_policy(DigestPolicy::AllowLegacyMd5);
    assert!(!equivalent(
        input(HttpProxyAuthentication::Digest(&digest)),
        input(HttpProxyAuthentication::Digest(&legacy))
    ));
    let changed = HttpDigestCredentials::new("synthetic-user", "different-password").unwrap();
    assert!(!equivalent(
        input(HttpProxyAuthentication::Digest(&digest)),
        input(HttpProxyAuthentication::Digest(&changed))
    ));
}

#[test]
fn credential_input_length_prefixes_do_not_alias_field_boundaries() {
    let left = HttpDigestCredentials::new("ab", "c").unwrap();
    let right = HttpDigestCredentials::new("a", "bc").unwrap();
    assert!(!equivalent(
        HttpProxyAuthentication::Digest(&left)
            .session_transfer_credential()
            .unwrap(),
        HttpProxyAuthentication::Digest(&right)
            .session_transfer_credential()
            .unwrap()
    ));
}

#[test]
fn credential_input_is_unchanged_by_real_digest_challenges_and_nonce_counts() {
    use crate::{
        proxy::DigestForwardAuthentication,
        route::{Endpoint, ProxyTransport},
    };
    let digest = HttpDigestCredentials::new("synthetic-user", "synthetic-password").unwrap();
    let baseline = HttpDigestCredentials::new("synthetic-user", "synthetic-password").unwrap();
    for nonce in ["first-synthetic-nonce", "second-synthetic-nonce"] {
        let mut authentication = DigestForwardAuthentication::new(
            &digest,
            ProxyTransport::Tcp(Endpoint {
                host: "proxy.example",
                port: 8080,
            }),
            false,
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("proxy-authenticate", format!(
            "Digest realm=\"synthetic-realm\", nonce=\"{nonce}\", algorithm=SHA-256, qop=\"auth\""
        ).parse().unwrap());
        authentication.challenge(&headers).unwrap();
        let first = authentication
            .authorization(&http::Method::GET, "/")
            .unwrap()
            .unwrap();
        let second = authentication
            .authorization(&http::Method::GET, "/")
            .unwrap()
            .unwrap();
        assert!(first.value() != second.value());
        assert!(equivalent(
            HttpProxyAuthentication::Digest(&baseline)
                .session_transfer_credential()
                .unwrap(),
            HttpProxyAuthentication::Digest(&digest)
                .session_transfer_credential()
                .unwrap()
        ));
    }
    assert!(equivalent(
        HttpProxyAuthentication::Digest(&baseline)
            .session_transfer_credential()
            .unwrap(),
        HttpProxyAuthentication::Digest(&digest)
            .session_transfer_credential()
            .unwrap()
    ));
}

#[test]
fn credential_input_has_independent_versioned_framing() {
    let basic = HttpBasicCredentials::new("u", "p").unwrap();
    let mut frame = b"phantom-ticket-http-credential-v2".to_vec();
    frame.extend_from_slice(&[1, 0]);
    frame.extend_from_slice(&10_u32.to_be_bytes());
    frame.extend_from_slice(b"Basic dTpw");
    assert!(equivalent(
        HttpProxyAuthentication::Basic(&basic)
            .session_transfer_credential()
            .unwrap(),
        SessionTransferCredential::from_canonical_hmac_input(&frame).unwrap()
    ));
}

#[test]
fn credential_input_rejects_oversized_framing_without_secret_diagnostics() {
    let input = vec![b'x'; 64 * 1024];
    let error = crate::proxy::credential_frame::credential(2, 1, &[&input]).unwrap_err();
    assert!(matches!(error, btls::ssl::SessionTransferError::TooLarge));
    assert!(!format!("{error:?} {error}").contains("xxxx"));
    let opaque = HttpProxyAuthentication::Basic(
        &HttpBasicCredentials::new("synthetic-user", "synthetic-password").unwrap(),
    )
    .session_transfer_credential()
    .unwrap();
    assert!(!format!("{opaque:?}").contains("synthetic"));
}
