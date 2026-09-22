//! Structural seeds perturbed by the fuzzer's own input.
//!
//! A target embeds responses or fields that already parse and overwrites a
//! slice of one with the fuzz input. The mutator then reaches parser states
//! that lie far past a length or magic-byte check without a committed corpus.

/// Overwrites part of `seed` with `input`, starting at an offset the input's
/// first byte chooses. An empty input leaves the seed unchanged.
///
/// The caller must not also derive control values from the same bytes: an
/// offset and a chunk size taken from one byte cannot vary independently.
#[must_use]
pub fn perturb(seed: &[u8], input: &[u8]) -> Vec<u8> {
    let mut structured = seed.to_vec();
    let Some((&selector, mutation)) = input.split_first() else {
        return structured;
    };
    let offset = usize::from(selector) % structured.len();
    let replaced = mutation.len().min(structured.len() - offset);
    structured[offset..offset + replaced].copy_from_slice(&mutation[..replaced]);
    structured
}
