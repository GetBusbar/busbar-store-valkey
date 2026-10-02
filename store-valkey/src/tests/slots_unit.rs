// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Server-free unit tests for the store v3 keyspace's encodings and the admission rule
//! (`src/slots.rs`).

use super::*;

/// No two slots share a cap key: every caller-named part is hex, and the pool's absence is a
/// spelling no present pool can take.
#[test]
fn cap_keys_are_injective() {
    let k = |bucket, pool, dimension, window_start| {
        cap_key(&CellKey {
            bucket,
            pool,
            dimension,
            window_start,
        })
    };
    let all = [
        k("a", None, Dimension::Requests, 0),
        k("a", Some(""), Dimension::Requests, 0),
        k("a", Some("-"), Dimension::Requests, 0),
        k("a:b", None, Dimension::Requests, 0),
        k("a", None, Dimension::NanoUnits, 0),
        k("a", None, Dimension::Concurrency, 0),
        k("a", None, Dimension::Class(""), 0),
        k("a", None, Dimension::Class("x"), 0),
        k("a", None, Dimension::Requests, 60),
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.0, b.0);
        }
    }
    assert_eq!(all[4].1, 0);
    assert_eq!(all[0].1, 1);
    assert_eq!(all[5].1, 2);
    assert_eq!(all[7].1, 3);
}

/// The 1.5.5 admission rule per dimension, and an overflowing draw is refused.
#[test]
fn the_admission_rule_per_dimension() {
    // DIM_REQUESTS / DIM_CONCURRENCY: `used + amount > cap`.
    assert!(!exhausted(1, 3, 2, 5));
    assert!(exhausted(1, 3, 3, 5));
    assert!(exhausted(2, 0, 6, 5));
    // DIM_NANO_UNITS: `used >= cap || used + amount > cap`.
    assert!(!exhausted(0, 0, 5, 5));
    assert!(exhausted(0, 5, 0, 5));
    assert!(exhausted(0, 1, 5, 5));
    // DIM_CLASS: `used >= cap`; the draw that crosses the cap is granted whole.
    assert!(!exhausted(3, 4, 100, 5));
    assert!(exhausted(3, 5, 1, 5));
    assert!(exhausted(1, u64::MAX, 1, u64::MAX));
}

/// A prefix's successor bounds a byte-ordered scan; all-0xFF and empty prefixes have none.
#[test]
fn a_prefix_end_is_the_next_key_past_the_prefix() {
    assert_eq!(prefix_end(b"ab"), Some(b"ac".to_vec()));
    assert_eq!(prefix_end(b"a\xff"), Some(b"b".to_vec()));
    assert_eq!(prefix_end(b"\xff\xff"), None);
    assert_eq!(prefix_end(b""), None);
}

/// An op's record is its id in hex: sixteen bytes, thirty-two digits, one key per id.
#[test]
fn an_op_key_names_its_id_exactly() {
    let a = op_key(OpId::from_parts(1, 2));
    assert_eq!(a, "busbar:op:01000000000000000200000000000000");
    assert_ne!(a, op_key(OpId::from_parts(2, 1)));
}
