//! The retained Opera 136 trust-anchor orders are iteration orders of the
//! `absl::flat_hash_set` that Chromium 152 copies its trust-anchor IDs into.
//!
//! Each copy of the set takes a new 8-bit per-table seed and inserts the IDs
//! again, hashed with that seed (`absl/container/internal/raw_hash_set.cc`,
//! `Copy`, at Chromium tag 152.0.7977.130). A copy reserved for 32 IDs has
//! capacity 63 with its last 5 slots blocked
//! (`BlockedElementCountForReservedTable`), and iterates its slots in index
//! order. This module hashes each ID as the x86-64 build without SSE4.2 does
//! (`absl/hash/internal/hash.h`, `CombineSmallContiguousImpl`) and asks, for
//! each seed, whether some insertion order could leave the IDs in the
//! retained order.

use std::collections::HashSet;

use super::{TRUST_ANCHOR_ORDERS, TestResult, TrustAnchorOrders, order_ids};

/// `kMul` in `absl/hash/internal/hash.h`.
const K_MUL: u64 = 0x79d5_f9e0_de1e_8cf5;
/// The first two words of `kStaticRandomData`, which
/// `PrecombineLengthMix` reads at a byte offset equal to the input length.
const STATIC_RANDOM_DATA: [u64; 2] = [0x243f_6a88_85a3_08d3, 0x1319_8a2e_0370_7344];
/// The table capacity for 32 reserved elements.
const CAPACITY: usize = 63;
/// Slots a probe group covers (`Group::kWidth`, SSE2).
const GROUP_WIDTH: usize = 16;
/// Slots 58 to 62 are blocked: `min(CapacityToGrowth(63) - 32, 5)`.
const USABLE_SLOTS: usize = CAPACITY - 5;

/// `absl::Hash` of a 4- to 8-byte `std::vector<uint8_t>` seeded with
/// `seed`, as `MixingHashState::hash_with_seed` computes it without CRC32.
fn hash(id: &[u8], seed: u8) -> TestResult<u64> {
    let length = id.len();
    if !(4..=8).contains(&length) {
        return Err(format!("{length}-byte ID is outside the modeled hash path").into());
    }
    let mut random = [0; 16];
    random[..8].copy_from_slice(&STATIC_RANDOM_DATA[0].to_le_bytes());
    random[8..].copy_from_slice(&STATIC_RANDOM_DATA[1].to_le_bytes());
    let mut word = [0; 8];
    word.copy_from_slice(&random[length..length + 8]);
    let state = u64::from(seed) ^ u64::from_le_bytes(word);
    let read4 = |at: usize| -> TestResult<u64> {
        Ok(u64::from(u32::from_le_bytes(id[at..at + 4].try_into()?)))
    };
    let value = (read4(0)? << 32) | read4(length - 4)?;
    let product = u128::from(state ^ value) * u128::from(K_MUL);
    let high = u64::try_from(product >> 64)?;
    let low = u64::try_from(product & u128::from(u64::MAX))?;
    Ok(high ^ low)
}

/// Whether some insertion order leaves IDs with these probe starts, listed
/// in iteration order, in that order when the table iterates its slots.
///
/// An ID sits at the first free slot of the 16 its probe group covers, from
/// its probe start, wrapping past the sentinel at slot 63. So every slot
/// between its start and its slot is full. The search places the IDs at
/// increasing slots and tracks the run of full slots that ends at the last
/// one placed, and the lowest start of an ID that wrapped, whose slots up to
/// the end of the usable table must then be full.
fn fits(starts: &[usize]) -> bool {
    const NO_WRAP: usize = 64;
    // (last slot + 1, full run ending there, lowest wrapped start)
    let mut states = HashSet::from([(0, 0, NO_WRAP)]);
    for start in starts {
        let start = *start;
        let mut next = HashSet::new();
        for &(after, run, wrapped) in &states {
            for slot in after..USABLE_SLOTS {
                let run = if slot == after { run + 1 } else { 1 };
                if start < USABLE_SLOTS && (start..start + GROUP_WIDTH).contains(&slot) {
                    if slot - start < run {
                        next.insert((slot + 1, run, wrapped));
                    }
                } else if slot < start && 64 - start + slot < GROUP_WIDTH && run == slot + 1 {
                    let wrapped = if start < USABLE_SLOTS {
                        wrapped.min(start)
                    } else {
                        wrapped
                    };
                    next.insert((slot + 1, run, wrapped));
                }
            }
        }
        states = next;
    }
    states.iter().any(|&(after, run, wrapped)| {
        wrapped == NO_WRAP || (after == USABLE_SLOTS && run >= USABLE_SLOTS - wrapped)
    })
}

/// The per-table seeds whose hash layout fits `order`.
fn seeds(order: &[Box<[u8]>]) -> TestResult<Vec<u8>> {
    let mut seeds = Vec::new();
    for seed in 0..=u8::MAX {
        let starts = order
            .iter()
            .map(|id| Ok(usize::try_from(hash(id, seed)? & 63)?))
            .collect::<TestResult<Vec<_>>>()?;
        if fits(&starts) {
            seeds.push(seed);
        }
    }
    Ok(seeds)
}

/// Every retained order, over TCP and QUIC, fits exactly one of the 256
/// seeds. The 32 IDs in ascending or descending order fit none, so the fit
/// is not one any order passes. The 16 TCP orders take 16 seeds; two QUIC
/// orders from different processes share seed 94, because each copy
/// re-inserts the IDs in its source table's order, which differs between
/// processes.
#[test]
fn opera_136_trust_anchor_orders_are_chromium_152_hash_set_orders() -> TestResult<()> {
    let orders = TrustAnchorOrders(
        TRUST_ANCHOR_ORDERS
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect(),
    );
    let mut tcp_seeds = Vec::new();
    for index in 0..orders.value("distinct_order_count")?.parse::<usize>()? {
        let order = order_ids(orders.value(&format!("order_{index}"))?)?;
        let [seed] = seeds(&order)?[..] else {
            return Err(format!("TCP order {index} does not fit exactly one seed").into());
        };
        tcp_seeds.push(seed);
    }
    let mut quic_seeds = Vec::new();
    for index in 0..orders
        .value("quic_distinct_order_count")?
        .parse::<usize>()?
    {
        let order = order_ids(orders.value(&format!("quic_order_{index}"))?)?;
        let [seed] = seeds(&order)?[..] else {
            return Err(format!("QUIC order {index} does not fit exactly one seed").into());
        };
        quic_seeds.push(seed);
    }
    assert_eq!(tcp_seeds.len(), 16);
    tcp_seeds.sort_unstable();
    tcp_seeds.dedup();
    assert_eq!(tcp_seeds.len(), 16);
    assert_eq!(quic_seeds.len(), 19);
    assert_eq!(quic_seeds[5], 94);
    assert_eq!(quic_seeds[9], 94);
    quic_seeds.sort_unstable();
    quic_seeds.dedup();
    assert_eq!(quic_seeds.len(), 18);

    let mut sorted = order_ids(orders.value("order_0")?)?;
    sorted.sort_unstable();
    assert!(seeds(&sorted)?.is_empty());
    sorted.reverse();
    assert!(seeds(&sorted)?.is_empty());
    Ok(())
}

/// The fit rejects arbitrary orders but not small changes to a fitting one.
/// None of 64 pseudo-random permutations of the 32 IDs fits a seed. Swapping
/// two neighbouring IDs in a retained TCP order leaves an order that fits
/// some seed in 130 of the 496 swaps: neighbouring IDs often probe
/// overlapping slots, so either can be inserted first. The fit shows that
/// the orders follow the hash layout, not that each has only one origin.
#[test]
fn hash_set_fit_rejects_random_orders_but_not_neighbour_swaps() -> TestResult<()> {
    let orders = TrustAnchorOrders(
        TRUST_ANCHOR_ORDERS
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect(),
    );
    let ids = order_ids(orders.value("order_0")?)?;
    let mut random = SplitMix64(0);
    for _ in 0..64 {
        let mut permutation = ids.clone();
        // Fisher-Yates; the modulo bias of at most 32 / 2^64 does not matter
        // for a negative control.
        for last in (1..permutation.len()).rev() {
            let pick = usize::try_from(random.next() % u64::try_from(last + 1)?)?;
            permutation.swap(last, pick);
        }
        assert!(seeds(&permutation)?.is_empty());
    }

    let mut swaps = 0;
    let mut fitting_swaps = 0;
    for index in 0..orders.value("distinct_order_count")?.parse::<usize>()? {
        let order = order_ids(orders.value(&format!("order_{index}"))?)?;
        for first in 0..order.len() - 1 {
            let mut swapped = order.clone();
            swapped.swap(first, first + 1);
            swaps += 1;
            if !seeds(&swapped)?.is_empty() {
                fitting_swaps += 1;
            }
        }
    }
    assert_eq!((fitting_swaps, swaps), (130, 496));
    Ok(())
}

/// SplitMix64, a fixed-seed generator that keeps the negative controls the
/// same on every run.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}
