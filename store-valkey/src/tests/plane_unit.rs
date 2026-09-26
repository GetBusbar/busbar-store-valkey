// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Server-free unit tests for the plane-record keyspace's encodings (`src/plane.rs`).

use super::*;

fn rec(kind: &str, id: &str, parent: Option<&str>, seq: u64, d: PlaneDisposition) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(Into::into),
        seq,
        ts: 7,
        disposition: d,
        body: b"{}".to_vec(),
    }
}

/// A position field round-trips any identity, colons included, and a chain child's position is its
/// PARENT's identity.
#[test]
fn a_position_field_round_trips_any_identity() {
    for ident in ["t1", "a:b:c", "", "99:x"] {
        let f = field(42, ident);
        assert_eq!(parse_field(&f), Some((42, ident)), "{f}");
    }
    let child = rec("task_event", "t1", Some("t1"), 3, PlaneDisposition::Active);
    assert_eq!(identity(&child), "t1");
    let top = rec("task", "t9", None, 0, PlaneDisposition::Active);
    assert_eq!(identity(&top), "t9");
}

/// No kind can make one kind's key render as another's: the kind is hex in every key.
#[test]
fn kind_keys_are_injective() {
    let a = Keys::of("x");
    let b = Keys::of("x:rec");
    assert_ne!(a.rec, b.rec);
    assert_ne!(a.body, b.rec);
    assert_ne!(Keys::of("a").idx("b:idx:c"), Keys::of("a:idx:b").idx("c"));
    assert_ne!(token_key("ask", "n"), token_key("as", "kn"));
}

/// The sidecar's two flag characters say exactly what the scripts read: parented, then disposition.
/// And it is deterministic, which is what makes the append fork check a byte comparison.
#[test]
fn the_sidecar_flags_and_determinism() {
    let child = rec("call", "c", Some("p"), 1, PlaneDisposition::Active);
    let s = sidecar(&child).unwrap();
    assert!(s.starts_with("1a{"), "{s}");
    let done = rec("task", "t", None, 0, PlaneDisposition::Terminal);
    assert!(sidecar(&done).unwrap().starts_with("0t{"));
    assert_eq!(sidecar(&child).unwrap(), s);
    let mut moved = child.clone();
    moved.ts += 1;
    assert_ne!(
        sidecar(&moved).unwrap(),
        s,
        "a different ts is a different record"
    );
}
