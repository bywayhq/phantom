use std::{
    sync::{Arc, atomic::Ordering},
    thread,
};

use super::*;

mod http2;
pub(super) mod proxy_peer;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const NONCE: &str = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
const CNONCE: &str = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";

fn session(algorithm: &str) -> Result<DigestSession, DigestAuthError> {
    let credentials = HttpDigestCredentials::new("Mufasa", "Circle of Life")?
        .with_policy(DigestPolicy::AllowLegacyMd5);
    let field = format!(
        "Digest realm=\"http-auth@example.org\", nonce=\"{NONCE}\", algorithm={algorithm}, qop=\"auth, auth-int\""
    );
    let challenge = DigestChallenge::select([field.as_bytes()], &credentials)?;
    DigestSession::with_cnonce(challenge, &credentials, CNONCE.into())
}

#[test]
fn digest_matches_the_rfc_sha256_example_and_independent_hashlib_vectors() -> TestResult {
    // SHA-256 is RFC 7616 section 3.9.1. Other vectors were calculated
    // independently with Python hashlib from the same published inputs.
    for (algorithm, expected, proof) in [
        (
            "MD5",
            "8ca523f5e9506fed4657c9700eebdbec",
            "9b712497bc9f91499fbcca1dfc5f09a5",
        ),
        (
            "MD5-sess",
            "e783283f46242139c486a698fec7211d",
            "b9bdf5673282d64412df46ad40660539",
        ),
        (
            "SHA-256",
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
            "86d3b25618d41854ca5039a5d7e53ff6355d5134a9b1fb088a78ac3c462195a0",
        ),
        (
            "SHA-256-sess",
            "2fd51b3a77ad75bad6afad6003e818d767133c46d9e2749e7f5232ae1ea3efd7",
            "d4ad609d150eafce2281da5c3179878fdb37e6a16021272f4bed1a082f5c2324",
        ),
        (
            "SHA-512-256",
            "430d05014cecc49cab6fbe03176d41a1da86cbfe24a16580e22aaad928d960d0",
            "c8f9593a4f49b95ce2c483cc3222ecd360a5c6ec52ca24a530b0aac18478de8c",
        ),
        (
            "SHA-512-256-sess",
            "3f2a34f923c38b0fb26dce2fdfc2ce326c23cecf86fbb1444f3e51fbbc2cb92e",
            "98012a4e63fae2aea13adaa3410368ef7278c87ca0acbd3c941ca5fe3dceeb86",
        ),
    ] {
        let session = session(algorithm)?;
        let request = session.request(&http::Method::GET, "/dir/index.html")?;
        let value = std::str::from_utf8(request.header.value())?;
        assert!(
            value.contains(&format!("response=\"{expected}\"")),
            "{algorithm}"
        );
        assert!(
            value.contains(&format!("algorithm={algorithm}")),
            "{algorithm}"
        );
        assert!(value.contains("nc=00000001"));
        assert!(request.header.is_sensitive());
        assert!(!format!("{:?}", request.header).contains("Mufasa"));
        assert!(!value.contains("Circle of Life"));
        let information = format!(
            "rspauth=\"{proof}\", qop=auth, cnonce=\"{CNONCE}\", nc=00000001, nextnonce=\"replacement\""
        );
        assert_eq!(
            request.verify([information.as_bytes()])?.as_deref(),
            Some(&b"replacement"[..])
        );
        let information = format!(",, {information}, ,");
        assert_eq!(
            request.verify([information.as_bytes()])?.as_deref(),
            Some(&b"replacement"[..])
        );
    }
    Ok(())
}

#[test]
fn digest_policy_never_substitutes_basic_or_legacy_md5() -> TestResult {
    let credentials = HttpDigestCredentials::new("user", "password")?;
    for value in [
        "Basic realm=proxy",
        "Digest realm=proxy, nonce=x, qop=auth",
        "Digest realm=proxy, nonce=x, qop=auth, algorithm=MD5-sess",
        "Digest realm=proxy, nonce=x, qop=auth-int, algorithm=SHA-256",
        "Digest realm=proxy, nonce=x, algorithm=SHA-256",
        "Digest realm=proxy, nonce=x, qop=auth, algorithm=UNKNOWN",
    ] {
        assert!(matches!(
            DigestChallenge::select([value.as_bytes()], &credentials),
            Err(DigestAuthError::UnsupportedChallenge)
        ));
    }
    let fields = [
        &b"Digest realm=proxy, nonce=x, qop=auth, algorithm=MD5"[..],
        &b"Digest realm=proxy, nonce=y, qop=auth, algorithm=SHA-512-256"[..],
        &b"Digest realm=proxy, nonce=z, qop=auth, algorithm=SHA-256"[..],
    ];
    assert_eq!(
        DigestChallenge::select(fields, &credentials)?.algorithm,
        Algorithm::Sha512256
    );
    assert_eq!(
        DigestChallenge::select(
            fields,
            &credentials.with_policy(DigestPolicy::AllowLegacyMd5)
        )?
        .algorithm,
        Algorithm::Md5
    );
    Ok(())
}

#[test]
fn hashed_username_matches_an_independent_vector_without_changing_the_response() -> TestResult {
    let credentials = HttpDigestCredentials::new("Mufasa", "Circle of Life")?;
    let field = format!(
        "Digest realm=\"http-auth@example.org\", nonce=\"{NONCE}\", algorithm=SHA-256, qop=auth, userhash=true"
    );
    let challenge = DigestChallenge::select([field.as_bytes()], &credentials)?;
    let session = DigestSession::with_cnonce(challenge, &credentials, CNONCE.into())?;
    let request = session.request(&http::Method::GET, "/dir/index.html")?;
    let value = std::str::from_utf8(request.header.value())?;
    // Python hashlib.sha256(b"Mufasa:http-auth@example.org").hexdigest().
    assert!(
        value.contains(
            "username=\"a947aad205e80e429958a387394944c6b496301e79f89d35a4cc23b6ee12b5b6\""
        )
    );
    assert!(
        value.contains(
            "response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\""
        )
    );
    assert!(value.contains("userhash=true"));
    assert!(!value.contains("Mufasa"));
    Ok(())
}

#[test]
fn malformed_challenges_do_not_retain_values_or_hide_after_a_valid_offer() -> TestResult {
    let credentials = HttpDigestCredentials::new("user", "password")?;
    for value in [
        "Digest realm=private, nonce=\"unclosed",
        "Digest realm=private, nonce=x, NONCE=y, qop=auth, algorithm=SHA-256",
        "Digest nonce=private, qop=auth, algorithm=SHA-256",
        "Digest realm=private, nonce=\"\", qop=auth, algorithm=SHA-256",
        "Digest realm=private, nonce=x, qop=auth, algorithm=SHA-256, stale=unknown",
        "Digest realm=private, nonce=x, qop=auth, algorithm=SHA-256, charset=ISO-8859-1",
        "Digest realm=private, nonce=x, qop=auth, algorithm=SHA-256, userhash=unknown",
        "Digest realm=private, nonce=x, qop=auth, algorithm=SHA-256, Basic realm=\"unclosed",
    ] {
        let Err(error) = DigestChallenge::select([value.as_bytes()], &credentials) else {
            return Err("malformed challenge accepted".into());
        };
        assert!(matches!(error, DigestAuthError::MalformedChallenge));
        assert!(!format!("{error:?} {error}").contains("private"));
    }
    Ok(())
}

#[test]
fn quoted_fields_are_unescaped_for_hashing_then_escaped_for_emission() -> TestResult {
    let credentials = HttpDigestCredentials::new("u\"ser\\", "password")?;
    let field = &b"Digest realm=\"r\\\"e\\\\alm\", nonce=\"n\\\"once\", opaque=\"o\\\\paque\", algorithm=SHA-256, qop=auth, stale=true"[..];
    let challenge = DigestChallenge::select([field], &credentials)?;
    assert_eq!(&*challenge.realm, b"r\"e\\alm");
    assert!(challenge.stale);
    let session = DigestSession::new(challenge, &credentials)?;
    let request = session.request(&http::Method::CONNECT, "origin.example:443")?;
    let value = std::str::from_utf8(request.header.value())?;
    assert!(value.contains("username=\"u\\\"ser\\\\\""));
    assert!(value.contains("realm=\"r\\\"e\\\\alm\""));
    assert!(value.contains("opaque=\"o\\\\paque\""));
    assert!(value.contains("uri=\"origin.example:443\""));
    for invalid in ["", "/path with spaces", "/path\r\ninjection", "/é"] {
        assert!(matches!(
            session.request(&http::Method::GET, invalid),
            Err(DigestAuthError::InvalidRequest)
        ));
    }
    assert_eq!(session.count.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn parallel_requests_reserve_unique_counts_and_exhaustion_never_wraps() -> TestResult {
    let session = Arc::new(session("SHA-256")?);
    let mut workers = Vec::new();
    for _ in 0..8 {
        let session = Arc::clone(&session);
        workers.push(thread::spawn(
            move || -> Result<Vec<String>, DigestAuthError> {
                (0..64)
                    .map(|_| {
                        session
                            .request(&http::Method::CONNECT, "origin.example:443")
                            .map(|request| request.nonce_count)
                    })
                    .collect()
            },
        ));
    }
    let mut counts = Vec::new();
    let results: Vec<_> = workers.into_iter().map(thread::JoinHandle::join).collect();
    for result in results {
        counts.extend(result.map_err(|_| "nonce worker panicked")??);
    }
    counts.sort();
    counts.dedup();
    assert_eq!(counts.len(), 512);
    assert_eq!(counts.first().map(String::as_str), Some("00000001"));
    assert_eq!(counts.last().map(String::as_str), Some("00000200"));
    session.count.store(u32::MAX - 1, Ordering::Relaxed);
    assert_eq!(
        session.request(&http::Method::GET, "/")?.nonce_count,
        "ffffffff"
    );
    assert!(matches!(
        session.request(&http::Method::GET, "/"),
        Err(DigestAuthError::NonceExhausted)
    ));
    assert_eq!(session.count.load(Ordering::Relaxed), u32::MAX);
    Ok(())
}

#[test]
fn response_proof_rejects_wrong_target_count_nonce_and_duplicate_information() -> TestResult {
    let session = session("SHA-256")?;
    let request = session.request(&http::Method::GET, "/dir/index.html")?;
    let proof = "86d3b25618d41854ca5039a5d7e53ff6355d5134a9b1fb088a78ac3c462195a0";
    let valid = format!("rspauth=\"{proof}\", qop=auth, cnonce=\"{CNONCE}\", nc=00000001");
    request.verify([valid.as_bytes()])?;
    request.verify(std::iter::empty::<&[u8]>())?;
    for invalid in [
        valid.replace(proof, &"0".repeat(64)),
        valid.replace("00000001", "00000002"),
        valid.replace(CNONCE, "wrong-client-nonce"),
        format!("{valid}, nc=00000001"),
        "qop=auth".into(),
        "nextnonce=\"\"".into(),
    ] {
        assert!(request.verify([invalid.as_bytes()]).is_err());
    }
    let other = session.request(&http::Method::GET, "/different")?;
    assert!(other.verify([valid.as_bytes()]).is_err());
    Ok(())
}

#[test]
fn credential_and_challenge_resource_limits_are_checked() -> TestResult {
    let credentials = HttpDigestCredentials::new("user", "password")?;
    for (username, password) in [
        ("", "p"),
        ("u:ser", "p"),
        ("é", "p"),
        ("user", "p\n"),
        ("user", "p\0"),
    ] {
        let error = HttpDigestCredentials::new(username, password)
            .err()
            .ok_or("invalid credential accepted")?;
        assert!(matches!(error, DigestAuthError::InvalidCredentials));
    }
    assert!(HttpDigestCredentials::new(&"u".repeat(1024), &"p".repeat(4096)).is_ok());
    assert!(HttpDigestCredentials::new(&"u".repeat(1025), "p").is_err());
    assert!(HttpDigestCredentials::new("u", &"p".repeat(4097)).is_err());
    assert!(!format!("{credentials:?}").contains("password"));
    let too_many = vec![&b"Bearer"[..]; 33];
    assert!(DigestChallenge::select(too_many, &credentials).is_err());
    let oversized = format!(
        "Digest realm=\"{}\", nonce=x, qop=auth, algorithm=SHA-256",
        "x".repeat(MAX_CONNECT_HEAD_BYTES)
    );
    assert!(DigestChallenge::select([oversized.as_bytes()], &credentials).is_err());
    Ok(())
}
