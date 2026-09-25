use btls::ssl::{Ssl, SslContext, SslMethod};
use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};

use super::{EchConfigListErrorKind, is_valid_public_name, parse};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn list(configs: &[Vec<u8>]) -> Vec<u8> {
    ech_config_list(configs)
}

fn config() -> Vec<u8> {
    ech_config(3, &TEST_ECH_KEYS[0], "public.example.test")
}

/// Rebuilds [`config`] with its contents replaced by `edit` applied to them.
fn edited(edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let original = config();
    let mut contents = original[4..].to_vec();
    edit(&mut contents);
    let mut config = vec![0xfe, 0x0d];
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);
    config
}

/// Offset of the cipher-suite list length inside the contents.
const SUITES: usize = 1 + 2 + 2 + 32;
/// Offset of `maximum_name_length` inside the contents.
const MAX_NAME: usize = SUITES + 2 + 8;

fn boringssl_accepts(bytes: &[u8]) -> TestResult<bool> {
    let context = SslContext::builder(SslMethod::tls())?.build();
    let mut ssl = Ssl::new(&context)?;
    Ok(ssl.set_ech_config_list(bytes).is_ok())
}

#[test]
fn a_supported_configuration_exposes_every_field() -> TestResult {
    let configs = parse(&list(&[config()]))?;
    let [config] = &configs[..] else {
        return Err("expected one configuration".into());
    };
    assert_eq!(config.version(), 0xfe0d);
    assert_eq!(config.config_id(), Some(3));
    assert_eq!(config.kem_id(), Some(0x0020));
    assert_eq!(config.public_key(), TEST_ECH_KEYS[0].public_key);
    let suites = config
        .cipher_suites()
        .iter()
        .map(|suite| (suite.kdf_id(), suite.aead_id()))
        .collect::<Vec<_>>();
    assert_eq!(suites, [(1, 1), (1, 3)]);
    assert_eq!(config.maximum_name_length(), Some(0));
    assert_eq!(config.public_name(), Some(&b"public.example.test"[..]));
    assert!(config.extensions().is_empty());
    assert!(config.is_supported());
    Ok(())
}

#[test]
fn another_version_is_kept_but_unsupported() -> TestResult {
    let unknown = vec![0xfe, 0x0a, 0x00, 0x02, 0xab, 0xcd];
    let configs = parse(&list(&[unknown, config()]))?;
    assert_eq!(configs.len(), 2);
    assert_eq!(configs[0].version(), 0xfe0a);
    assert_eq!(configs[0].config_id(), None);
    assert!(configs[0].public_name().is_none());
    assert!(!configs[0].is_supported());
    assert!(configs[1].is_supported());
    Ok(())
}

#[test]
fn malformed_lists_are_rejected_with_their_category() {
    let good = list(&[config()]);
    let mut trailing = good.clone();
    trailing.push(0);
    let cases: Vec<(Vec<u8>, EchConfigListErrorKind)> = vec![
        (Vec::new(), EchConfigListErrorKind::ListLength),
        (vec![0x00], EchConfigListErrorKind::ListLength),
        (vec![0x00, 0x00], EchConfigListErrorKind::Empty),
        (
            good[..good.len() - 1].to_vec(),
            EchConfigListErrorKind::ListLength,
        ),
        (trailing, EchConfigListErrorKind::ListLength),
        (
            list(&[vec![0xfe, 0x0d, 0x00]]),
            EchConfigListErrorKind::MalformedConfig,
        ),
        (
            list(&[edited(|contents| contents.push(0))]),
            EchConfigListErrorKind::MalformedConfig,
        ),
        (
            list(&[edited(|contents| {
                contents[3] = 0;
                contents[4] = 0;
                contents.drain(5..37);
            })]),
            EchConfigListErrorKind::MalformedConfig,
        ),
        (
            list(&[edited(|contents| {
                contents[SUITES + 1] = 6;
                contents.drain(SUITES + 8..SUITES + 10);
            })]),
            EchConfigListErrorKind::MalformedConfig,
        ),
        (
            list(&[edited(|contents| {
                let name = MAX_NAME + 1;
                let length = usize::from(contents[name]);
                contents[name] = 0;
                contents.drain(name + 1..name + 1 + length);
            })]),
            EchConfigListErrorKind::MalformedConfig,
        ),
    ];
    for (bytes, kind) in cases {
        match parse(&bytes) {
            Ok(_) => panic!("{bytes:02x?} parsed"),
            Err(error) => assert_eq!(error.kind(), kind, "{bytes:02x?}"),
        }
    }
}

#[test]
fn unsupported_parameters_parse_but_are_not_supported() -> TestResult {
    let other_kem = edited(|contents| contents[2] = 0x10);
    let other_kdf = edited(|contents| {
        contents[SUITES + 3] = 2;
        contents[SUITES + 7] = 2;
    });
    let other_aead = edited(|contents| {
        contents[SUITES + 5] = 0x7f;
        contents[SUITES + 9] = 0x7f;
    });
    let mandatory_extension = edited(|contents| {
        let end = contents.len();
        contents[end - 1] = 4;
        contents.extend_from_slice(&[0x80, 0x01, 0x00, 0x00]);
    });
    let numeric_name = ech_config(3, &TEST_ECH_KEYS[0], "example.123");
    for config in [
        other_kem,
        other_kdf,
        other_aead,
        mandatory_extension,
        numeric_name,
    ] {
        let configs = parse(&list(std::slice::from_ref(&config)))?;
        assert_eq!(configs.len(), 1);
        assert!(!configs[0].is_supported(), "{config:02x?}");
    }
    Ok(())
}

#[test]
fn public_names_follow_boringssl() {
    for name in ["a", "example.test", "a-b.c1", "x.0x1g"] {
        assert!(is_valid_public_name(name.as_bytes()), "{name}");
    }
    for name in [
        "",
        ".",
        "a.",
        ".a",
        "a..b",
        "-a.test",
        "a-.test",
        "a_b.test",
        "example.123",
        "example.0x1f",
        "1.2.3.4",
    ] {
        assert!(!is_valid_public_name(name.as_bytes()), "{name}");
    }
    assert!(!is_valid_public_name(&[b'a'; 64]));
}

/// The parser rejects exactly the lists the TLS client rejects, so a list
/// Phantom passes on never fails later inside BoringSSL.
#[test]
fn acceptance_matches_boringssl() -> TestResult {
    let good = list(&[config()]);
    let mut samples = vec![
        good.clone(),
        list(&[vec![0xfe, 0x0a, 0x00, 0x00]]),
        list(&[config(), vec![0xfe, 0x0a, 0x00, 0x01, 0x00]]),
        list(&[edited(|contents| contents[2] = 0x10)]),
        vec![0x00, 0x00],
        vec![0x00],
    ];
    for cut in 0..good.len() {
        samples.push(good[..cut].to_vec());
    }
    for position in 2..good.len() {
        let mut flipped = good.clone();
        flipped[position] ^= 0xff;
        samples.push(flipped);
    }
    for sample in samples {
        assert_eq!(
            parse(&sample).is_ok(),
            boringssl_accepts(&sample)?,
            "{sample:02x?}"
        );
    }
    Ok(())
}
