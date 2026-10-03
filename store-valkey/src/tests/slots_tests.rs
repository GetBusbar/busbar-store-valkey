// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live Valkey: the durable `op_id` dedupe (S1-S4),
//! the money slots and window caps, the journal, sessions and the kernel's records.
//!
//! Every test names its own slots, streams, sessions and keys from a fresh name, so the suite runs
//! in parallel against the one shared server and leaves nothing another test reads.

use super::{live_store, live_url, vk};
use crate::slots::op_key;
use crate::ValkeyStore;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, ReserveRefused, StoreSlots,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, MeteringDelta, PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore,
    UsageDelta,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// The epoch every draw here states (fixed at 0 until WIRE-STORE adds the advance).
const EPOCH: u64 = 0;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A number no other test, process or earlier run draws: the clock, the process and a counter.
fn unique() -> u64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    (t ^ (u64::from(std::process::id()) << 40)).wrapping_add(SEQ.fetch_add(1, Ordering::Relaxed))
}

/// A name no other test (or earlier run) uses.
fn fresh(tag: &str) -> String {
    format!("{tag}-{:x}", unique())
}

/// A fresh op id: the dedupe is durable, so an id an earlier run used would replay.
fn op() -> OpId {
    OpId::from_parts(unique() | 1, 1)
}

fn key(bucket: &str, window_start: u64) -> CellKey<'_> {
    CellKey {
        bucket,
        pool: None,
        dimension: Dimension::Requests,
        window_start,
    }
}

fn reserve(s: &ValkeyStore, op: OpId, cells: &[Cell<'_>]) -> Result<Vec<Grant>, ReserveRefused> {
    let mut grants = Vec::new();
    s.reserve(op, EPOCH, cells.iter().copied(), &mut grants)?;
    Ok(grants)
}

fn release(s: &ValkeyStore, op: OpId, items: &[(u64, u64)]) -> Result<Vec<u64>, OpRefused> {
    let mut back = Vec::new();
    s.slice_release(op, EPOCH, items.iter().copied(), &mut back)?;
    Ok(back)
}

fn push_cap(s: &ValkeyStore, k: CellKey<'_>, cap: u64, config_gen: u64) {
    s.window_caps(
        op(),
        &[Cap {
            key: k,
            cap,
            config_gen,
        }],
    )
    .expect("cap");
}

fn audit(seq: u64, action: &str) -> AuditRecord {
    AuditRecord {
        seq,
        ts: 1_700_000_000,
        action: action.into(),
        resource: "slots-test".into(),
        outcome: "ok".into(),
        principal: "tester".into(),
        prev_hash: String::new(),
        hash: format!("h{seq}"),
    }
}

#[test]
fn the_statement_tail_is_a_durable_store_that_refuses_forks() {
    const {
        assert!(!ValkeyStore::TAIL.ephemeral);
        assert!(ValkeyStore::TAIL.durable_plane);
        assert!(ValkeyStore::TAIL.fork_refusal);
    }
}

#[test]
fn open_refuses_settings_it_cannot_run_in_its_own_words() {
    let e = ValkeyStore::open(b"").err().expect("no url");
    assert!(e.contains("requires a \"url\""), "{e}");
    let e = ValkeyStore::open(b"{ not json").err().expect("bad json");
    assert!(e.contains("invalid valkey plugin config"), "{e}");
    let e = ValkeyStore::open(b"\xff\xfe").err().expect("not utf-8");
    assert!(e.contains("invalid valkey plugin config"), "{e}");
    let e = ValkeyStore::open(br#"{"url": "not a url"}"#)
        .err()
        .expect("a url the driver refuses");
    assert!(e.contains("failed to connect"), "{e}");
}

/// S1/S2/S3/S4: a replay applies nothing and answers the original, a different body is a conflict
/// and applies nothing, the record survives a reconnect (it is on the server, not in the process)
/// and it expires after the retention window (a server-side TTL).
#[test]
fn an_op_id_write_applies_once_durably_and_a_different_body_conflicts() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("dedupe");
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 2,
        models: Vec::new(),
    };
    let id = op();
    s.add_usage_op(id, &bucket, 60, &delta).expect("applies");
    s.add_usage_op(id, &bucket, 60, &delta)
        .expect("a replay answers Ok");
    let again = ValkeyStore::connect(&live_url().unwrap()).expect("reconnect");
    again
        .add_usage_op(id, &bucket, 60, &delta)
        .expect("a replay after a reconnect answers Ok");
    let other = UsageDelta {
        requests: 4,
        ..delta.clone()
    };
    assert_eq!(
        again.add_usage_op(id, &bucket, 60, &other),
        Err(OpRefused::Conflict)
    );
    let ledger = s.get_usage(&bucket, 60).expect("get_usage");
    assert_eq!(ledger.requests, 3, "applied exactly once: {ledger:?}");
    assert_eq!(ledger.billable_requests, 2, "{ledger:?}");

    let mut raw = redis::Client::open(live_url().unwrap())
        .unwrap()
        .get_connection()
        .unwrap();
    let ttl: i64 = redis::cmd("TTL").arg(op_key(id)).query(&mut raw).unwrap();
    assert!(
        (1..=OP_ID_RETENTION_SECS as i64).contains(&ttl),
        "the op's record expires after the retention window, ttl {ttl}"
    );
}

/// The dedupe is atomic with the effect: eight connections presenting ONE `op_id` at once apply it
/// exactly once, and every one of them answers Ok.
#[test]
fn racing_calls_with_one_op_id_apply_once() {
    let Some(url) = live_url() else { return };
    let bucket = fresh("race");
    let id = op();
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: Vec::new(),
    };
    std::thread::scope(|scope| {
        let all: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    let s = ValkeyStore::connect(&url).expect("connect");
                    s.add_usage_op(id, &bucket, 60, &delta)
                })
            })
            .collect();
        for h in all {
            assert_eq!(h.join().unwrap(), Ok(()));
        }
    });
    let s = ValkeyStore::connect(&url).expect("connect");
    assert_eq!(s.get_usage(&bucket, 60).unwrap().requests, 1);
}

/// The floor and the sum survive the op path: a batch naming one window twice adds both cells (the
/// second onto the first's result), and no counter goes below 0.
#[test]
fn a_usage_batch_applies_every_cell_in_order_and_floors_at_zero() {
    let Some(s) = live_store() else { return };
    let (a, b) = (fresh("batch-a"), fresh("batch-b"));
    let cell = |requests| UsageDelta {
        requests,
        billable_requests: 0,
        models: Vec::new(),
    };
    s.add_usage_batch(
        op(),
        &[
            (a.as_str(), 60, cell(5)),
            (b.as_str(), 60, cell(2)),
            (a.as_str(), 60, cell(-3)),
        ],
    )
    .expect("batch");
    assert_eq!(s.get_usage(&a, 60).unwrap().requests, 2);
    assert_eq!(s.get_usage(&b, 60).unwrap().requests, 2);
    s.add_usage_batch(op(), &[(a.as_str(), 60, cell(-100))])
        .expect("a refund past zero");
    assert_eq!(s.get_usage(&a, 60).unwrap().requests, 0, "floored at 0");
}

#[test]
fn a_metering_op_applies_once_and_a_replay_adds_nothing() {
    let Some(s) = live_store() else { return };
    let bucket = 8_000_000_000 + unique() % 1_000_000_000;
    let key_id = fresh("meter");
    let d = MeteringDelta {
        key_id: key_id.clone(),
        bucket,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 5,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let id = op();
    s.add_metering_op(id, &d).expect("applies");
    s.add_metering_op(id, &d).expect("replay");
    s.add_metering_batch(op(), std::slice::from_ref(&d))
        .expect("batch");
    let rows: Vec<_> = s
        .list_metering(bucket)
        .unwrap()
        .into_iter()
        .filter(|r| r.key_id == key_id)
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].requests, 2, "the replay added nothing: {rows:?}");
    assert_eq!(rows[0].tokens_input, 10);
}

/// S3: a refused op records nothing, so a retry under the same `op_id` is judged afresh; a fork
/// anywhere in an audit batch stages nothing of it, including a fork INSIDE the batch.
#[test]
fn a_failed_batch_applies_nothing_and_records_nothing() {
    let Some(s) = live_store() else { return };
    let base = 9_000_000_000 + unique() % 1_000_000_000;
    s.append_audit(&audit(base, "first")).expect("seed");
    let id = op();
    let forked = [audit(base + 1, "new"), audit(base, "forked")];
    assert!(matches!(
        s.append_audit_batch(id, &forked),
        Err(OpRefused::Failed(_))
    ));
    let stored = |s: &ValkeyStore| -> Vec<u64> {
        s.list_audit()
            .expect("list_audit")
            .into_iter()
            .map(|r| r.seq)
            .filter(|q| (base..=base + 9).contains(q))
            .collect()
    };
    assert_eq!(
        stored(&s),
        vec![base],
        "the batch's first record was not kept"
    );
    // Not recorded: the same op id with a DIFFERENT (good) body is judged afresh, not a conflict.
    s.append_audit_batch(id, &[audit(base + 1, "new")])
        .expect("a retry after a failure is new");
    // A batch that forks against ITSELF is refused whole.
    let inner = [audit(base + 5, "a"), audit(base + 5, "b")];
    assert!(matches!(
        s.append_audit_batch(op(), &inner),
        Err(OpRefused::Failed(_))
    ));
    assert_eq!(stored(&s), vec![base, base + 1]);
    // An identical replay of a stored record is Ok and writes nothing.
    s.append_audit_op(op(), &audit(base, "first"))
        .expect("identical");
}

#[test]
fn reserve_needs_a_cap_grants_whole_cells_and_refuses_past_the_cap() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("reserve");
    let k = key(&bucket, 60);
    let cell = |amount| Cell { key: k, amount };
    assert_eq!(
        reserve(&s, op(), &[cell(1)]),
        Err(ReserveRefused::NoCap { cell: 0 })
    );
    push_cap(&s, k, 5, 1);
    let id = op();
    let g = reserve(&s, id, &[cell(2), cell(3)]).expect("2 + 3 fits 5");
    assert_eq!(g.iter().map(|g| g.granted).collect::<Vec<_>>(), vec![2, 3]);
    assert_ne!(g[0].slice_id, g[1].slice_id);
    // S1: the replay answers the ORIGINAL grants and draws nothing more.
    assert_eq!(reserve(&s, id, &[cell(2), cell(3)]), Ok(g.clone()));
    assert_eq!(reserve(&s, id, &[cell(1)]), Err(ReserveRefused::Conflict));
    assert_eq!(
        reserve(&s, op(), &[cell(1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    // A release clamps to what the slice holds and frees that much.
    let back = release(&s, op(), &[(g[1].slice_id, 10), (g[1].slice_id, 1)]).expect("release");
    assert_eq!(
        back,
        vec![3, 0],
        "clamped, and the emptied slice gives back 0"
    );
    assert_eq!(
        release(&s, op(), &[(g[1].slice_id, 1)]),
        Err(OpRefused::Failed(format!(
            "slice_release: slice {} is not held",
            g[1].slice_id
        )))
    );
    reserve(&s, op(), &[cell(3)]).expect("the released 3 can be drawn again");
}

/// The cells of ONE draw are tested against what the cells before them in the same draw add, and a
/// refused draw applies none of them.
#[test]
fn a_draw_is_all_or_nothing_across_its_cells() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("chain");
    let (a, b) = (key(&bucket, 1), key(&bucket, 2));
    push_cap(&s, a, 4, 1);
    push_cap(&s, b, 1, 1);
    let draw = [Cell { key: a, amount: 3 }, Cell { key: b, amount: 2 }];
    assert_eq!(
        reserve(&s, op(), &draw),
        Err(ReserveRefused::Exhausted { cell: 1 })
    );
    // The first cell's 3 was not drawn: all 4 of `a` is still there.
    reserve(&s, op(), &[Cell { key: a, amount: 4 }]).expect("nothing was drawn by the refusal");
    // The same slot twice in one draw adds up against the one cap.
    let twice = [Cell { key: b, amount: 1 }, Cell { key: b, amount: 1 }];
    assert_eq!(
        reserve(&s, op(), &twice),
        Err(ReserveRefused::Exhausted { cell: 1 })
    );
}

/// The three admission rules, by dimension: money refuses a draw that would pass the cap, a meter
/// class admits the draw that crosses it whole, and a requests cell refuses past the cap.
#[test]
fn each_dimension_applies_its_own_1_5_5_admission_rule() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("dims");
    let on = |dimension| CellKey {
        bucket: &bucket,
        pool: None,
        dimension,
        window_start: 0,
    };
    let (money, class) = (on(Dimension::NanoUnits), on(Dimension::Class("tokens")));
    push_cap(&s, money, 10, 1);
    push_cap(&s, class, 5, 1);
    let draw = |k, amount| reserve(&s, op(), &[Cell { key: k, amount }]);
    draw(money, 7).expect("7 of 10");
    assert_eq!(draw(money, 4), Err(ReserveRefused::Exhausted { cell: 0 }));
    draw(money, 3).expect("exactly the cap");
    draw(class, 4).expect("under the cap");
    draw(class, 4).expect("the draw that crosses the cap is granted whole");
    assert_eq!(draw(class, 1), Err(ReserveRefused::Exhausted { cell: 0 }));
}

/// Pool scope is part of the slot: a pooled cell and an every-pool cell of one bucket are two slots.
#[test]
fn a_pool_is_part_of_the_slot() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("pool");
    let all = key(&bucket, 0);
    let pooled = CellKey {
        pool: Some("fast"),
        ..all
    };
    push_cap(&s, pooled, 1, 1);
    assert_eq!(
        reserve(
            &s,
            op(),
            &[Cell {
                key: all,
                amount: 1
            }]
        ),
        Err(ReserveRefused::NoCap { cell: 0 })
    );
    reserve(
        &s,
        op(),
        &[Cell {
            key: pooled,
            amount: 1,
        }],
    )
    .expect("the pooled slot has its cap");
}

/// Epoch 0 until WIRE-STORE adds the advance: no epoch a caller states is refused, and a grant,
/// which `reserve` gives no lifetime, never expires.
#[test]
fn no_epoch_is_stale_and_a_grant_never_expires() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("epoch");
    let k = key(&bucket, 0);
    push_cap(&s, k, 100, 1);
    for epoch in [7, 0, u64::MAX] {
        let mut g = Vec::new();
        s.reserve(
            op(),
            epoch,
            [Cell { key: k, amount: 1 }].into_iter(),
            &mut g,
        )
        .expect("never stale");
        assert_eq!(g[0].valid_until_ms, u64::MAX);
    }
}

#[test]
fn window_caps_newest_generation_wins_and_an_equal_generation_must_agree() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("caps");
    let k = key(&bucket, 120);
    let cap = |cap, config_gen| Cap {
        key: k,
        cap,
        config_gen,
    };
    s.window_caps(op(), &[cap(1, 2)]).expect("first push");
    s.window_caps(op(), &[cap(9, 1)])
        .expect("an older generation is ignored");
    assert_eq!(
        s.window_caps(op(), &[cap(1, 2), cap(7, 2)]),
        Err(CapsRefused::CapConflict { index: 1 })
    );
    let cell = Cell { key: k, amount: 1 };
    reserve(&s, op(), &[cell]).expect("cap 1 holds one");
    assert_eq!(
        reserve(&s, op(), &[cell]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.window_caps(op(), &[cap(2, 3)])
        .expect("a newer generation raises it, and what is drawn stays drawn");
    reserve(&s, op(), &[cell]).expect("cap 2 holds a second");
    assert_eq!(
        reserve(&s, op(), &[cell]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

/// Draws made at once never pass the cap: sixteen connections each reserve 1 of a cap of 5.
#[test]
fn concurrent_draws_never_pass_the_cap() {
    let Some(url) = live_url() else { return };
    let bucket = fresh("conc");
    let k = key(&bucket, 0);
    push_cap(&ValkeyStore::connect(&url).unwrap(), k, 5, 1);
    let granted: usize = std::thread::scope(|scope| {
        let all: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    let s = ValkeyStore::connect(&url).expect("connect");
                    reserve(&s, op(), &[Cell { key: k, amount: 1 }]).is_ok()
                })
            })
            .collect();
        all.into_iter()
            .map(|h| h.join().expect("a draw thread"))
            .filter(|granted| *granted)
            .count()
    });
    assert_eq!(granted, 5, "exactly the cap was granted");
}

#[test]
fn the_journal_appends_in_order_and_states_its_heads() {
    let Some(s) = live_store() else { return };
    let stream = fresh("journal");
    let r = |b: &[u8]| RecordBytes::new(b.to_vec()).unwrap();
    let id = op();
    let h = s
        .append_batch(id, &stream, &[r(b"a"), r(b"b")])
        .expect("append");
    assert_eq!(h, Head { seq: 2, epoch: 0 });
    assert_eq!(
        s.append_batch(id, &stream, &[r(b"a"), r(b"b")]),
        Ok(h),
        "a replay answers the original head"
    );
    assert_eq!(
        s.append_batch(id, &stream, &[r(b"z")]),
        Err(OpRefused::Conflict)
    );
    let h = s.append_batch(op(), &stream, &[r(b"c")]).expect("append");
    assert_eq!(h.seq, 3);
    let heads = s.heads().expect("heads");
    assert!(
        heads.contains(&(stream.clone(), Head { seq: 3, epoch: 0 })),
        "{heads:?}"
    );
}

#[test]
fn sessions_upsert_list_by_principal_move_and_remove() {
    let Some(s) = live_store() else { return };
    let (principal, other) = (fresh("principal"), fresh("other"));
    let base = unique() >> 1;
    s.session_put(base + 2, "node-b", &principal).expect("put");
    s.session_put(base + 1, "node-a", &principal).expect("put");
    s.session_put(base + 1, "node-c", &principal)
        .expect("upsert");
    assert_eq!(
        s.sessions_for(&principal).expect("list"),
        vec![
            (base + 1, "node-c".to_string()),
            (base + 2, "node-b".to_string())
        ]
    );
    // A session that changes principal leaves the old principal's list.
    s.session_put(base + 2, "node-b", &other).expect("move");
    assert_eq!(
        s.sessions_for(&principal).expect("list"),
        vec![(base + 1, "node-c".to_string())]
    );
    assert_eq!(
        s.sessions_for(&other).expect("list"),
        vec![(base + 2, "node-b".to_string())]
    );
    s.session_remove(base + 1).expect("remove");
    s.session_remove(base + 1)
        .expect("an absent session removes Ok");
    assert!(s.sessions_for(&principal).expect("list").is_empty());
}

#[test]
fn records_upsert_read_back_and_scan_a_prefix_in_key_order() {
    let Some(s) = live_store() else { return };
    let schema = fresh("schema");
    s.record_put(&schema, b"b\xff", b"2").expect("put");
    s.record_put(&schema, b"a", b"0").expect("put");
    s.record_put(&schema, b"b\x00", b"1").expect("put");
    s.record_put(&schema, b"c", b"3").expect("put");
    s.record_put(&schema, b"a", b"0'").expect("upsert");
    let got = s.record_get(&schema, b"a").expect("get").expect("present");
    assert_eq!(got.as_slice(), b"0'");
    assert_eq!(s.record_get(&schema, b"z").expect("get"), None);
    let keys = |prefix: &[u8], limit| -> Vec<Vec<u8>> {
        s.record_scan(&schema, prefix, limit)
            .expect("scan")
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    };
    assert_eq!(keys(b"b", 10), vec![b"b\x00".to_vec(), b"b\xff".to_vec()]);
    assert_eq!(keys(b"", 2), vec![b"a".to_vec(), b"b\x00".to_vec()]);
    assert_eq!(keys(b"\xff", 10), Vec::<Vec<u8>>::new());
    assert!(keys(b"", 0).is_empty());
    // Two schemas never see each other's keys.
    assert_eq!(s.record_get(&fresh("schema"), b"a").expect("get"), None);
}

/// The plane-record `op_id` write and the key path still share the store's one keyspace.
#[test]
fn an_op_id_plane_append_dedupes_and_still_refuses_a_fork() {
    let Some(s) = live_store() else { return };
    s.put_key(&vk(&fresh("vk")))
        .expect("the key path is untouched");
    let parent = fresh("chain");
    let kind = fresh("slots_test");
    let rec = |body: &[u8]| PlaneRecord {
        kind: kind.clone(),
        id: parent.clone(),
        parent: Some(parent.clone()),
        seq: 1,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    let id = op();
    s.append_plane_record_op(id, rec(b"one").view())
        .expect("append");
    s.append_plane_record_op(id, rec(b"one").view())
        .expect("replay");
    assert_eq!(
        s.append_plane_record_op(id, rec(b"two").view()),
        Err(OpRefused::Conflict),
        "the same op id with other value fields conflicts"
    );
    assert!(matches!(
        s.append_plane_record_op(op(), rec(b"two").view()),
        Err(OpRefused::Failed(_))
    ));
    // The refused fork recorded nothing: the same op id is judged afresh.
    let retry = op();
    assert!(s.append_plane_record_op(retry, rec(b"two").view()).is_err());
    assert!(s.append_plane_record_op(retry, rec(b"two").view()).is_err());
    let chain = s
        .list_plane_records(&kind, &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"one".to_vec()]);
}
