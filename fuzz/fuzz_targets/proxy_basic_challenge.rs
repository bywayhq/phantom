#![no_main]

use http::{HeaderMap, HeaderValue, header::PROXY_AUTHENTICATE};
use libfuzzer_sys::fuzz_target;
use phantom_net::proxy::validate_basic_proxy_challenge;

// Newline-separated `Proxy-Authenticate` field values; a newline cannot occur
// inside a field value, so it cleanly separates repeated fields.
const VALID_CHALLENGES: [&[u8]; 3] = [
    b"Basic realm=\"proxy\"",
    b"Digest realm=\"other\", nonce=\"value\"\nBearer token==, Basic realm=\"proxy\", charset=\"UTF-8\"",
    b"Bearer abc==, , Basic realm=\"proxy\", charset=\"UTF\\-8\",",
];

fn validate(input: &[u8]) -> bool {
    let mut headers = HeaderMap::new();
    for value in input.split(|&byte| byte == b'\n') {
        if let Ok(value) = HeaderValue::from_bytes(value) {
            headers.append(PROXY_AUTHENTICATE, value);
        }
    }
    std::hint::black_box(validate_basic_proxy_challenge(&headers)).is_ok()
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
    let _ = validate(input);

    for seed in VALID_CHALLENGES {
        let accepted = validate(&perturb(seed, input));
        if input.is_empty() {
            assert!(accepted, "structural seeds must remain valid challenges");
        }
    }
});
