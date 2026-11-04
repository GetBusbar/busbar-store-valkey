// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Server-free unit tests for the store v3 keyspace's encodings and the admission rule
//! (`src/slots.rs`).

use super::*;

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
