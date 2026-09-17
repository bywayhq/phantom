#![no_main]

use libfuzzer_sys::fuzz_target;
use phantom_testkit::http2::CapturedFrame;

const VALID_SETTINGS_FRAME: [u8; 15] = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 16, 0];
const VALID_WINDOW_UPDATE_FRAME: [u8; 13] = [0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1];

fn accepts(input: &[u8]) -> bool {
    match CapturedFrame::from_wire_bytes(input) {
        Ok(frame) => {
            let settings = frame.settings();
            let window_update = frame.window_update();
            let accepted = settings.is_ok() && window_update.is_ok();
            let _ = std::hint::black_box(settings);
            let _ = std::hint::black_box(window_update);
            accepted
        }
        Err(error) => {
            let _ = std::hint::black_box(error);
            false
        }
    }
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

    for seed in [
        VALID_SETTINGS_FRAME.as_slice(),
        VALID_WINDOW_UPDATE_FRAME.as_slice(),
    ] {
        let structured = perturb(seed, input);
        let accepted = accepts(&structured);
        if input.is_empty() {
            assert!(accepted, "structural seeds must remain valid frames");
        }
    }
});
