#![no_main]

use libfuzzer_sys::fuzz_target;
use quinn_proto::{Side, transport_parameters::TransportParameters};

const ORDERED_PARAMETERS: [u8; 6] = [0x04, 0x01, 0x01, 0x05, 0x01, 0x02];
const REORDERED_PARAMETERS: [u8; 6] = [0x05, 0x01, 0x02, 0x04, 0x01, 0x01];
const MALFORMED_PARAMETERS: [&[u8]; 6] = [
    &[0x03, 0x02, 0x44],
    &[0x04, 0x01, 0x40],
    &[0x04, 0x01, 0x01, 0x04, 0x01, 0x02],
    &[0x40],
    &[0x04, 0x40],
    &[0x04, 0x02, 0x01],
];

fn decode(side: Side, input: &[u8]) -> bool {
    std::hint::black_box(TransportParameters::read(side, &mut &*input)).is_ok()
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
    for side in [Side::Client, Side::Server] {
        let _ = decode(side, input);

        for seed in [
            ORDERED_PARAMETERS.as_slice(),
            REORDERED_PARAMETERS.as_slice(),
        ] {
            let structured = perturb(seed, input);
            let accepted = decode(side, &structured);
            if input.is_empty() {
                assert!(accepted, "valid structural seeds must remain decodable");
            }
        }

        for seed in MALFORMED_PARAMETERS {
            let structured = perturb(seed, input);
            let _ = decode(side, &structured);
        }
    }
});
