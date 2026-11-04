// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Server-free unit tests for the plane-record keyspace's encodings (`src/plane.rs`).

use super::*;
use busbar_contract::records::PlaneRecord;

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
    let child = rec("task_event", "e1", Some("t1"), 3, PlaneDisposition::Active);
    assert_eq!(identity(&child.view()), "t1");
    let top = rec("task", "t9", None, 0, PlaneDisposition::Active);
    assert_eq!(identity(&top.view()), "t9");
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
    let s = sidecar(&child.view()).unwrap();
    assert!(s.starts_with("1a{"), "{s}");
    let done = rec("task", "t", None, 0, PlaneDisposition::Terminal);
    assert!(sidecar(&done.view()).unwrap().starts_with("0t{"));
    let fresh = rec("task", "a", None, 0, PlaneDisposition::Active);
    assert!(sidecar(&fresh.view()).unwrap().starts_with("0a{"));
    let sealed = rec("call", "s", Some("p"), 1, PlaneDisposition::Terminal);
    assert!(sidecar(&sealed.view()).unwrap().starts_with("1t{"));
    assert_eq!(sidecar(&child.view()).unwrap(), s);
    let mut moved = child.clone();
    moved.ts += 1;
    assert_ne!(
        sidecar(&moved.view()).unwrap(),
        s,
        "a different ts is a different record"
    );
}

/// The key, field and token layouts are shared with the scripts and every other node: pin the
/// literal strings, not just their round trips.
#[test]
fn the_key_field_and_token_layouts_are_pinned() {
    assert_eq!(field(42, "a:b"), "42:a:b");
    let k = Keys::of("task");
    assert_eq!(k.rec, "busbar:plane:7461736b:rec");
    assert_eq!(k.body, "busbar:plane:7461736b:body");
    assert_eq!(k.byts, "busbar:plane:7461736b:byts");
    assert_eq!(k.pcount, "busbar:plane:7461736b:pcount");
    assert_eq!(k.idx("ab"), "busbar:plane:7461736b:idx:6162");
    assert_eq!(token_key("task", "n"), "busbar:plane:7461736b:tok:6e");
}

/// The parent the listing checks is the one the sidecar names, and only when it is flagged
/// parented: a record whose own id is a parent's name is not that parent's child.
#[test]
fn a_sidecar_names_its_parent() {
    let child = rec("task", "t1", Some("ctx"), 0, PlaneDisposition::Active);
    assert_eq!(
        parent_of(&sidecar(&child.view()).unwrap()).unwrap(),
        Some("ctx".to_string())
    );
    let top = rec("task", "ctx", None, 0, PlaneDisposition::Active);
    assert_eq!(parent_of(&sidecar(&top.view()).unwrap()).unwrap(), None);
    assert!(parent_of("1a{not json").is_err());
}

/// Substitute only the clock response, then execute the actual production script against Valkey.
fn script_at(script: &crate::resp::Script, clock_reply: &str) -> redis::Script {
    redis::Script::new(
        &script
            .source_for_test()
            .replace(SHARED_TIME_COMMAND, clock_reply),
    )
}

#[test]
fn shared_clock_equality_admits_once_and_ticket_preflight_never_spends() {
    use crate::tests::{Connect, Raw};
    use redis::Commands as _;
    let Some(_) = crate::tests::live_store() else {
        return;
    };
    let (database, _raw) = crate::tests::fresh_db_client(crate::tests::TOKEN_CLOCK_DATABASE);
    let _store = busbar_plugin_loader::store_v3::LoadedStore::connect(&crate::tests::url_for_db(
        crate::tests::TOKEN_CLOCK_DATABASE,
    ))
    .unwrap();
    let (server_now, _micros): (u64, u64) =
        database.with_conn(|c| redis::cmd("TIME").query(c)).unwrap();
    const CLOCK_AHEAD: u64 = 900;
    const TOKEN_KIND: &str = "clock-boundary";
    const TOKEN: &str = "at-boundary";
    let expires = server_now + CLOCK_AHEAD;
    let clock = format!("{{'{expires}','0'}}");
    let key = token_key(TOKEN_KIND, TOKEN);
    let redeem = script_at(&REDEEM, &clock);
    let ticket = script_at(&TICKET_LIVE, &clock);
    let purge = |clock_reply: &str, c: &mut redis::Connection| -> redis::RedisResult<Vec<i64>> {
        let keys = Keys::of(TICKET_RECORD_KIND);
        const TERMINAL_ONLY: &str = "1";
        script_at(&PURGE, clock_reply)
            .key(&keys.rec)
            .key(&keys.body)
            .key(&keys.byts)
            .key(&keys.pcount)
            .key(&keys.rec)
            .key(&keys.body)
            .key(&keys.byts)
            .key(&keys.pcount)
            .arg(u64::MAX)
            .arg(TERMINAL_ONLY)
            .arg(&keys.idx_prefix)
            .arg("")
            .arg(0)
            .arg(PURGE_BATCH)
            .arg(TICKET_RECORD_KIND)
            .invoke(c)
    };
    let keys = Keys::of(TICKET_RECORD_KIND);
    let record = rec(
        TICKET_RECORD_KIND,
        TOKEN,
        None,
        UPSERT_SEQ,
        PlaneDisposition::Terminal,
    );
    let record = PlaneRecord {
        ts: expires,
        ..record
    };
    let encoded = sidecar(&record.view()).unwrap();
    database
        .with_conn(|c| {
            let _: () = c.hset(&keys.rec, field(UPSERT_SEQ, TOKEN), &encoded)?;
            let _: () = c.hset(&keys.body, field(UPSERT_SEQ, TOKEN), b"boundary-ticket")?;
            let _: () = c.zadd(&keys.byts, field(UPSERT_SEQ, TOKEN), expires)?;
            let _: () = c.zadd(keys.idx(TOKEN), field(UPSERT_SEQ, TOKEN), UPSERT_SEQ)?;
            assert_eq!(
                purge(&clock, c)?[0],
                0,
                "store-clock equality retains the ticket"
            );
            assert_eq!(redeem.key(&key).arg(expires).invoke::<i64>(c)?, 1);
            assert_eq!(redeem.key(&key).arg(expires).invoke::<i64>(c)?, 0);
            let cleanup: u64 = redis::cmd("EXPIRETIME").arg(&key).query(c)?;
            assert_eq!(cleanup, expires + 1);
            for _ in 0..2 {
                assert_eq!(
                    ticket
                        .key(&keys.rec)
                        .arg(field(UPSERT_SEQ, TOKEN))
                        .arg(expires)
                        .invoke::<i64>(c)?,
                    1
                );
            }
            assert_eq!(
                ticket
                    .key(&keys.rec)
                    .arg(field(UPSERT_SEQ, TOKEN))
                    .arg(expires + 1)
                    .invoke::<i64>(c)?,
                0
            );
            let stored: String = c.get(&key)?;
            assert_eq!(stored, expires.to_string());
            let later = format!("{{'{}','0'}}", expires + 1);
            assert_eq!(
                script_at(&TICKET_LIVE, &later)
                    .key(&keys.rec)
                    .arg(field(UPSERT_SEQ, TOKEN))
                    .arg(expires)
                    .invoke::<i64>(c)?,
                0
            );
            assert_eq!(
                script_at(&REDEEM, &later)
                    .key(&key)
                    .arg(expires)
                    .invoke::<i64>(c)?,
                0
            );
            let stored: String = c.get(&key)?;
            assert_eq!(
                stored,
                expires.to_string(),
                "expired input cannot mutate the receipt"
            );
            assert_eq!(
                script_at(&REDEEM, &later)
                    .key(&key)
                    .arg(u64::MAX)
                    .invoke::<i64>(c)?,
                1
            );
            const INVALID_CLOCK_REPLY: &str = "{'invalid-epoch','0'}";
            assert!(script_at(&REDEEM, INVALID_CLOCK_REPLY)
                .key(&key)
                .arg(u64::MAX)
                .invoke::<i64>(c)
                .is_err());
            assert!(script_at(&TICKET_LIVE, INVALID_CLOCK_REPLY)
                .key(&keys.rec)
                .arg(field(UPSERT_SEQ, TOKEN))
                .arg(expires)
                .invoke::<i64>(c)
                .is_err());
            let stored: String = c.get(&key)?;
            assert_eq!(stored, u64::MAX.to_string());
            assert_eq!(
                purge(&later, c)?[0],
                1,
                "the first later store second permits cleanup"
            );
            Ok(())
        })
        .unwrap();
}
