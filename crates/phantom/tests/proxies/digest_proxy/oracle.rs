//! Independent synthetic proxy oracle; it does not call the client engine.

use std::collections::BTreeMap;

use btls::hash::{Hasher, MessageDigest};

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(super) const ALGORITHMS: [&str; 6] = [
    "SHA-256",
    "SHA-256-sess",
    "SHA-512-256",
    "SHA-512-256-sess",
    "MD5",
    "MD5-sess",
];

pub(super) fn challenge(algorithm: &str, nonce: &str, stale: bool) -> String {
    format!(
        "Digest realm=\"proxy\", nonce=\"{nonce}\", algorithm={algorithm}, qop=\"auth\", stale={stale}"
    )
}

pub(super) struct Proof {
    pub(super) information: String,
    pub(super) cnonce: String,
    pub(super) count: String,
}

pub(super) fn verify(
    value: &str,
    method: &str,
    target: &str,
    algorithm: &str,
    nonce: &str,
) -> TestResult<Proof> {
    let value = value.strip_prefix("Digest ").ok_or("scheme changed")?;
    let fields = value
        .split(", ")
        .map(|field| {
            let (name, value) = field.split_once('=').ok_or("invalid oracle field")?;
            Ok((
                name,
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value),
            ))
        })
        .collect::<TestResult<BTreeMap<_, _>>>()?;
    let get = |name| fields.get(name).copied().ok_or("oracle field missing");
    assert_eq!(get("realm")?, "proxy");
    assert_eq!(get("username")?, "user");
    assert_eq!(get("algorithm")?, algorithm);
    assert_eq!(get("qop")?, "auth");
    assert_eq!(get("nonce")?, nonce);
    assert_eq!(get("uri")?, target);
    let cnonce = get("cnonce")?;
    let count = get("nc")?;
    assert_eq!(cnonce.len(), 32);
    assert_eq!(count.len(), 8);
    assert!(u32::from_str_radix(count, 16)? > 0);
    let mut a1 = hash(algorithm, "user:proxy:password")?;
    if algorithm.ends_with("-sess") {
        a1 = hash(algorithm, &format!("{a1}:{nonce}:{cnonce}"))?;
    }
    let a2 = hash(algorithm, &format!("{method}:{target}"))?;
    let expected = hash(
        algorithm,
        &format!("{a1}:{nonce}:{count}:{cnonce}:auth:{a2}"),
    )?;
    assert_eq!(get("response")?, expected);
    let a2 = hash(algorithm, &format!(":{target}"))?;
    let response = hash(
        algorithm,
        &format!("{a1}:{nonce}:{count}:{cnonce}:auth:{a2}"),
    )?;
    Ok(Proof {
        information: format!("rspauth=\"{response}\", qop=auth, cnonce=\"{cnonce}\", nc={count}"),
        cnonce: cnonce.into(),
        count: count.into(),
    })
}

fn hash(algorithm: &str, input: &str) -> TestResult<String> {
    let digest = match algorithm.strip_suffix("-sess").unwrap_or(algorithm) {
        "MD5" => MessageDigest::md5(),
        "SHA-256" => MessageDigest::sha256(),
        "SHA-512-256" => MessageDigest::sha512_256(),
        _ => return Err("unsupported oracle algorithm".into()),
    };
    let mut hasher = Hasher::new(digest)?;
    hasher.update(input.as_bytes())?;
    let bytes = hasher.finish()?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
