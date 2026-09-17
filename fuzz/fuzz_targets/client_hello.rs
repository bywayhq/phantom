#![no_main]

use libfuzzer_sys::fuzz_target;
use phantom_testkit::tls::ClientHelloSummary;
use std::sync::OnceLock;

const MINIMAL_CLIENT_HELLO: [u8; 47] = [
    1, 0, 0, 43, 3, 3, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0, 0, 2, 0x13, 1, 1, 0, 0, 0,
];

fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= usize::from(u16::MAX));
    let length = data.len() as u16;
    let mut encoded = extension_type.to_be_bytes().to_vec();
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(data);
    encoded
}

fn extension_client_hello() -> Vec<u8> {
    let mut extensions = extension(0x3a3a, &[1, 2, 3]);
    for (extension_type, data) in [
        (0, b"\x00\x16\x00\x00\x13server.phantom.test".as_slice()),
        (10, &[0, 4, 0, 29, 0x2a, 0x2a]),
        (11, &[3, 0, 2, 1]),
        (13, &[0, 4, 0x08, 0x04, 0x04, 0x03]),
        (16, &[0, 5, 2, b'h', b'2', 1, 0xff]),
        (43, &[4, 0x03, 0x04, 0x7a, 0x7a]),
        (51, &[0, 11, 0, 29, 0, 2, 1, 2, 0x4a, 0x4a, 0, 1, 3]),
        (0xca34, &[0, 5, 1, b'a', 2, b'b', b'c']),
    ] {
        extensions.extend_from_slice(&extension(extension_type, data));
    }

    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x42; 32]);
    body.extend_from_slice(&[2, 0xaa, 0xbb, 0, 6, 0x13, 2, 0x0a, 0x0a, 0x13, 1, 1, 0]);
    assert!(extensions.len() <= usize::from(u16::MAX));
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    assert!(body.len() <= 0x00ff_ffff);
    let length = body.len();
    let mut handshake = vec![
        1,
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);
    handshake
}

fn accepts(input: &[u8]) -> bool {
    std::hint::black_box(ClientHelloSummary::from_handshake_bytes(input)).is_ok()
}

fn perturb(seed: &[u8], input: &[u8]) -> Vec<u8> {
    let mut structured = seed.to_vec();
    let Some((&selector, mutation)) = input.split_first() else {
        return structured;
    };
    let offset = usize::from(selector) % structured.len();
    let replaced = mutation.len().min(structured.len() - offset);
    structured[offset..offset + replaced].copy_from_slice(&mutation[..replaced]);
    structured
}

fuzz_target!(|input: &[u8]| {
    let _ = accepts(input);

    static EXTENSION_SEED: OnceLock<Vec<u8>> = OnceLock::new();
    let extension_seed = EXTENSION_SEED.get_or_init(extension_client_hello);
    for seed in [MINIMAL_CLIENT_HELLO.as_slice(), extension_seed.as_slice()] {
        let structured = perturb(seed, input);
        let accepted = accepts(&structured);
        if input.is_empty() {
            assert!(accepted, "structural seeds must remain valid ClientHellos");
        }
    }
});
