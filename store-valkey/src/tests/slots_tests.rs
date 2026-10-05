// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live Valkey: the durable `op_id` dedupe (S1-S4),
//! the money slots and window caps, the journal, sessions and the kernel's records. The settings
//! refusals need no server and always run.
//!
//! Every test names its own slots, streams, sessions and keys freshly (process, clock, counter), so
//! the suite runs in parallel against the one shared Valkey and leaves nothing another test reads.

use super::{live_store, Connect, Raw};
use crate::ValkeyStore as Door;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, OpResult, ReserveRefused,
    StoreSlots,
};
use busbar_contract::store_calls::StoreFailure;

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, UsageDelta,
};

/// The store under test: the door as the host opens it (`super::open_with`).
type ValkeyStore = busbar_plugin_loader::store_v3::LoadedStore;

/// Run one of the store's async calls to its answer (each is one op through the host's connector).
fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(f)
}

/// A store call's failure, in the slot's own refusal type.
trait FromFailure {
    fn from_failure(f: StoreFailure) -> Self;
}

impl FromFailure for OpRefused {
    fn from_failure(f: StoreFailure) -> Self {
        match f {
            StoreFailure::Conflict => OpRefused::Conflict,
            StoreFailure::Failed(t) | StoreFailure::Refused(t) | StoreFailure::Fault(t) => {
                OpRefused::Failed(t)
            }
            other => OpRefused::Failed(other.to_string()),
        }
    }
}

impl FromFailure for ReserveRefused {
    fn from_failure(f: StoreFailure) -> Self {
        match f {
            StoreFailure::Reserve(r) => r,
            StoreFailure::Conflict => ReserveRefused::Conflict,
            _ => ReserveRefused::Unavailable,
        }
    }
}

impl FromFailure for CapsRefused {
    fn from_failure(f: StoreFailure) -> Self {
        match f {
            StoreFailure::Conflict => CapsRefused::Conflict,
            StoreFailure::CapConflict(index) => CapsRefused::CapConflict { index },
            StoreFailure::Failed(t) | StoreFailure::Refused(t) | StoreFailure::Fault(t) => {
                CapsRefused::Failed(t)
            }
            other => CapsRefused::Failed(other.to_string()),
        }
    }
}

impl FromFailure for String {
    fn from_failure(f: StoreFailure) -> Self {
        match f {
            StoreFailure::Failed(t) | StoreFailure::Refused(t) | StoreFailure::Fault(t) => t,
            other => other.to_string(),
        }
    }
}

fn call<T, E: FromFailure>(
    f: impl std::future::Future<Output = Result<T, StoreFailure>>,
) -> Result<T, E> {
    block(f).map_err(E::from_failure)
}

/// The store v3 slots these tests drive, through the store's async calls (`StoreCalls`, named by
/// path only: its methods share these names), answered
/// synchronously in each slot's own result type.
trait Slots {
    fn add_usage_op(&self, op: OpId, bucket: &str, window: u64, d: &UsageDelta) -> OpResult<()>;
    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()>;
    fn add_metering_op(
        &self,
        op: OpId,
        d: &busbar_contract::records::MeteringDelta,
    ) -> OpResult<()>;
    fn add_metering_batch(
        &self,
        op: OpId,
        d: &[busbar_contract::records::MeteringDelta],
    ) -> OpResult<()>;
    fn append_audit_op(&self, op: OpId, e: &AuditRecord) -> OpResult<()>;
    fn append_audit_batch(&self, op: OpId, e: &[AuditRecord]) -> OpResult<()>;
    fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused>;
    fn append_batch(&self, op: OpId, stream: &str, r: &[RecordBytes]) -> OpResult<Head>;
    fn heads(&self) -> Result<Vec<(String, Head)>, String>;
    fn session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String>;
    fn session_remove(&self, session: u64) -> Result<(), String>;
    fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String>;
    fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String>;
    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String>;
    fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String>;
    fn append_plane_record_op(
        &self,
        op: OpId,
        r: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> OpResult<()>;
}

impl Slots for ValkeyStore {
    fn add_usage_op(&self, op: OpId, bucket: &str, window: u64, d: &UsageDelta) -> OpResult<()> {
        let cells = [(bucket, window, d.clone())];
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::add_usage_batch(
                self, op, &cells,
            ),
        )
    }
    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::add_usage_batch(
                self, op, cells,
            ),
        )
    }
    fn add_metering_op(
        &self,
        op: OpId,
        d: &busbar_contract::records::MeteringDelta,
    ) -> OpResult<()> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::add_metering_batch(
                self,
                op,
                std::slice::from_ref(d),
            ),
        )
    }
    fn add_metering_batch(
        &self,
        op: OpId,
        d: &[busbar_contract::records::MeteringDelta],
    ) -> OpResult<()> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::add_metering_batch(
                self, op, d,
            ),
        )
    }
    fn append_audit_op(&self, op: OpId, e: &AuditRecord) -> OpResult<()> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::append_audit_batch(
                self,
                op,
                std::slice::from_ref(e),
            ),
        )
    }
    fn append_audit_batch(&self, op: OpId, e: &[AuditRecord]) -> OpResult<()> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::append_audit_batch(
                self, op, e,
            ),
        )
    }
    fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
        call(<ValkeyStore as busbar_contract::store_calls::StoreCalls>::window_caps(self, op, caps))
    }
    fn append_batch(&self, op: OpId, stream: &str, r: &[RecordBytes]) -> OpResult<Head> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::append_batch(
                self, op, stream, r,
            ),
        )
    }
    fn heads(&self) -> Result<Vec<(String, Head)>, String> {
        call(<ValkeyStore as busbar_contract::store_calls::StoreCalls>::heads(self))
    }
    fn session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::session_put(
                self, session, node, principal,
            ),
        )
    }
    fn session_remove(&self, session: u64) -> Result<(), String> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::session_remove(
                self, session,
            ),
        )
    }
    fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::sessions_for(
                self, principal,
            ),
        )
    }
    fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let value = RecordBytes::new(value.to_vec()).map_err(|n| format!("{n} bytes"))?;
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::record_put(
                self, schema, key, &value,
            ),
        )
    }
    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::record_get(
                self, schema, key,
            ),
        )
    }
    fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::record_scan(
                self, schema, prefix, limit,
            ),
        )
    }
    fn append_plane_record_op(
        &self,
        op: OpId,
        r: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> OpResult<()> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::append_plane_record(
                self, op, r,
            ),
        )
    }
}

/// The epoch every draw here states (fixed at 0 until WIRE-STORE adds the advance).
const EPOCH: u64 = 0;

/// A number no other test, instance or earlier run uses.
fn unique() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    (t ^ (u64::from(std::process::id()) << 32))
        .wrapping_add(N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) << 48)
}

/// A name no other test (or earlier run) uses.
fn fresh(tag: &str) -> String {
    format!("{tag}-{:x}", unique())
}

/// A fresh op id: the dedupe is durable, so an op id an earlier run used would replay.
fn op(counter: u64) -> OpId {
    OpId::from_parts(unique() | 1, counter * 2 + 1)
}

fn key(bucket: &str, window_start: u64) -> CellKey<'_> {
    CellKey {
        bucket,
        pool: None,
        dimension: Dimension::Requests,
        window_start,
    }
}

fn reserve(
    s: &ValkeyStore,
    op: OpId,
    epoch: u64,
    cells: &[Cell<'_>],
) -> Result<Vec<Grant>, ReserveRefused> {
    call(<ValkeyStore as busbar_contract::store_calls::StoreCalls>::reserve(s, op, epoch, cells))
}

fn release(s: &ValkeyStore, op: OpId, items: &[(u64, u64)]) -> Result<Vec<u64>, OpRefused> {
    call(
        <ValkeyStore as busbar_contract::store_calls::StoreCalls>::slice_release(
            s, op, EPOCH, items,
        ),
    )
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

/// An audit `seq` far from every other test's.
fn audit_base() -> u64 {
    8_000_000_000 + unique() % 1_000_000_000 * 4
}

#[test]
fn the_statement_tail_is_a_durable_store_that_refuses_forks() {
    const {
        assert!(!Door::TAIL.ephemeral);
        assert!(Door::TAIL.durable_plane);
        assert!(Door::TAIL.fork_refusal);
    }
}

/// The settings refusals are the 1.5.5 texts, through the door's `open`. No server needed.
#[test]
fn open_refuses_settings_it_cannot_run_in_its_own_words() {
    let e = Door::open(b"", None).expect_err("no url");
    assert!(e.contains("requires a \"url\""), "{e}");
    let e = Door::open(b"{}", None).expect_err("no url");
    assert!(e.contains("requires a \"url\""), "{e}");
    let e = Door::open(b"{ not json", None).expect_err("bad json");
    assert!(e.contains("invalid valkey plugin config"), "{e}");
    let e =
        Door::open(br#"{"url":"not-a-valkey-url"}"#, None).expect_err("a url the driver refuses");
    assert!(e.contains("valkey plugin: failed to connect"), "{e}");
}

/// S1/S2/S3/S4: a replay applies nothing and answers the original, a different body is a conflict
/// and applies nothing, and the record survives a reconnect (it is in Valkey, not the process).
#[test]
fn an_op_id_write_applies_once_durably_and_a_different_body_conflicts() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("dedupe");
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 2,
        models: Vec::new(),
    };
    let id = op(1);
    s.add_usage_op(id, &bucket, 60, &delta).expect("applies");
    s.add_usage_op(id, &bucket, 60, &delta)
        .expect("a replay answers Ok");
    let url = std::env::var("VALKEY_URL").expect("live_store read it");
    let again = ValkeyStore::connect(&url).expect("reconnect");
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
}

/// The batch slots apply every cell once, and a replay none.
#[test]
fn a_usage_and_a_metering_batch_apply_once() {
    let Some(s) = live_store() else { return };
    let (a, b) = (fresh("batch-a"), fresh("batch-b"));
    let d = |n| UsageDelta {
        requests: n,
        billable_requests: 0,
        models: Vec::new(),
    };
    let cells = [
        (a.as_str(), 0, d(1)),
        (b.as_str(), 0, d(2)),
        (a.as_str(), 0, d(3)),
    ];
    let id = op(30);
    s.add_usage_batch(id, &cells).expect("applies");
    s.add_usage_batch(id, &cells).expect("replays");
    assert_eq!(s.get_usage(&a, 0).unwrap().requests, 4);
    assert_eq!(s.get_usage(&b, 0).unwrap().requests, 2);

    let bucket = super::unique_bucket(31);
    let m = busbar_contract::records::MeteringDelta {
        key_id: fresh("vk"),
        bucket,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 5,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let id = op(32);
    s.add_metering_batch(id, &[m.clone(), m.clone()])
        .expect("applies");
    s.add_metering_batch(id, &[m.clone(), m.clone()])
        .expect("replays");
    s.add_metering_op(op(33), &m).expect("applies");
    let rows = s.list_metering(bucket).expect("list");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].tokens_input, 15,
        "three deltas, once each: {rows:?}"
    );
}

/// S3: a refused op records nothing, so a retry under the same `op_id` is judged afresh; a fork
/// anywhere in an audit batch writes none of the batch.
#[test]
fn a_failed_batch_applies_nothing_and_records_nothing() {
    let Some(s) = live_store() else { return };
    let base = audit_base();
    s.append_audit(&audit(base, "first")).expect("seed");
    let id = op(2);
    let forked = [audit(base + 1, "new"), audit(base, "forked")];
    let e = s.append_audit_batch(id, &forked);
    assert!(
        matches!(&e, Err(OpRefused::Failed(t)) if t.contains("the audit chain has forked")),
        "{e:?}"
    );
    let stored: Vec<u64> = s
        .list_audit()
        .expect("list_audit")
        .into_iter()
        .map(|r| r.seq)
        .filter(|q| *q == base || *q == base + 1)
        .collect();
    assert_eq!(
        stored,
        vec![base],
        "the batch's first record was not written"
    );
    // Not recorded: the same op id with a DIFFERENT (good) body is judged afresh, not a conflict.
    s.append_audit_batch(id, &[audit(base + 1, "new")])
        .expect("a retry after a failure is new");
    // The identical record already at its seq is the write-through retrying: Ok, nothing written.
    s.append_audit_op(op(3), &audit(base, "first"))
        .expect("an identical record is not a fork");
    for q in [base, base + 1] {
        s.purge_audit_seq_for_test(q).unwrap();
    }
}

/// Two records of one batch at one `seq`: the same record twice is one write; two different
/// records are a fork inside the batch.
#[test]
fn an_audit_batch_judges_its_own_records_against_each_other() {
    let Some(s) = live_store() else { return };
    let base = audit_base();
    s.append_audit_batch(op(4), &[audit(base, "a"), audit(base, "a")])
        .expect("the same record twice");
    assert!(matches!(
        s.append_audit_batch(op(5), &[audit(base + 1, "a"), audit(base + 1, "b")]),
        Err(OpRefused::Failed(_))
    ));
    let at: Vec<u64> = s
        .list_audit()
        .unwrap()
        .into_iter()
        .map(|r| r.seq)
        .filter(|q| *q == base || *q == base + 1)
        .collect();
    assert_eq!(at, vec![base]);
    s.purge_audit_seq_for_test(base).unwrap();
}

#[test]
fn reserve_needs_a_cap_grants_whole_cells_and_refuses_past_the_cap() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("reserve");
    let k = key(&bucket, 60);
    let cell = |amount| Cell { key: k, amount };
    assert_eq!(
        reserve(&s, op(3), EPOCH, &[cell(1)]),
        Err(ReserveRefused::NoCap { cell: 0 })
    );
    s.window_caps(
        op(4),
        &[Cap {
            key: k,
            cap: 5,
            config_gen: 1,
        }],
    )
    .expect("cap");
    let id = op(5);
    let g = reserve(&s, id, EPOCH, &[cell(2), cell(3)]).expect("2 + 3 fits 5");
    assert_eq!(g.iter().map(|g| g.granted).collect::<Vec<_>>(), vec![2, 3]);
    assert_ne!(g[0].slice_id, g[1].slice_id);
    // S1: the replay answers the ORIGINAL grants and draws nothing more.
    assert_eq!(reserve(&s, id, EPOCH, &[cell(2), cell(3)]), Ok(g.clone()));
    assert_eq!(
        reserve(&s, id, EPOCH, &[cell(1)]),
        Err(ReserveRefused::Conflict)
    );
    assert_eq!(
        reserve(&s, op(6), EPOCH, &[cell(1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    // A release clamps to what the slice holds and frees that much.
    let rid = op(7);
    let items = [(g[1].slice_id, 10), (g[1].slice_id, 1)];
    let back = release(&s, rid, &items).expect("release");
    assert_eq!(
        back,
        vec![3, 0],
        "clamped, and the emptied slice gives back 0"
    );
    assert_eq!(
        release(&s, rid, &items),
        Ok(vec![3, 0]),
        "a replayed release answers the ORIGINAL amounts and frees nothing more"
    );
    assert_eq!(
        release(&s, op(8), &[(g[1].slice_id, 1)]),
        Err(OpRefused::Failed(format!(
            "slice_release: slice {} is not held",
            g[1].slice_id
        )))
    );
    reserve(&s, op(9), EPOCH, &[cell(3)]).expect("the released 3 can be drawn again");
    assert_eq!(
        reserve(&s, op(10), EPOCH, &[cell(1)]),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "the replayed release freed nothing twice"
    );
}

/// A draw is all or nothing: a refused cell leaves every earlier cell undrawn.
#[test]
fn a_refused_draw_applies_none_of_its_cells() {
    let Some(s) = live_store() else { return };
    let (a, b) = (fresh("all-a"), fresh("all-b"));
    let (ka, kb) = (key(&a, 0), key(&b, 0));
    s.window_caps(
        op(40),
        &[
            Cap {
                key: ka,
                cap: 2,
                config_gen: 1,
            },
            Cap {
                key: kb,
                cap: 1,
                config_gen: 1,
            },
        ],
    )
    .expect("caps");
    assert_eq!(
        reserve(
            &s,
            op(41),
            EPOCH,
            &[Cell { key: ka, amount: 2 }, Cell { key: kb, amount: 2 }]
        ),
        Err(ReserveRefused::Exhausted { cell: 1 })
    );
    reserve(&s, op(42), EPOCH, &[Cell { key: ka, amount: 2 }])
        .expect("cell 0 of the refused draw took nothing");
}

/// Epoch 0 until WIRE-STORE adds the advance: no epoch a caller states is refused, and a grant,
/// which `reserve` gives no lifetime, never expires.
#[test]
fn no_epoch_is_stale_and_a_grant_never_expires() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("epoch");
    let k = key(&bucket, 0);
    s.window_caps(
        op(10),
        &[Cap {
            key: k,
            cap: 100,
            config_gen: 1,
        }],
    )
    .expect("cap");
    for (i, epoch) in [7, 0, u64::MAX].into_iter().enumerate() {
        let g = reserve(&s, op(11 + i as u64), epoch, &[Cell { key: k, amount: 1 }])
            .expect("never stale");
        assert_eq!(g[0].valid_until_ms, u64::MAX);
    }
}

/// Caps and drawn totals are exact `u64`s, past what a double holds.
#[test]
fn a_cap_past_two_to_the_fifty_three_is_exact() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("big");
    let k = CellKey {
        bucket: &bucket,
        pool: Some("pool-a"),
        dimension: Dimension::NanoUnits,
        window_start: 0,
    };
    let cap = (1u64 << 60) + 1;
    s.window_caps(
        op(50),
        &[Cap {
            key: k,
            cap,
            config_gen: 1,
        }],
    )
    .expect("cap");
    reserve(
        &s,
        op(51),
        EPOCH,
        &[Cell {
            key: k,
            amount: cap,
        }],
    )
    .expect("exactly the cap");
    assert_eq!(
        reserve(&s, op(52), EPOCH, &[Cell { key: k, amount: 1 }]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
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
    s.window_caps(op(13), &[cap(1, 2)]).expect("first push");
    s.window_caps(op(14), &[cap(9, 1)])
        .expect("an older generation is ignored");
    assert_eq!(
        s.window_caps(op(15), &[cap(1, 2), cap(7, 2)]),
        Err(CapsRefused::CapConflict { index: 1 })
    );
    let cell = Cell { key: k, amount: 1 };
    reserve(&s, op(16), EPOCH, &[cell]).expect("cap 1 holds one");
    assert_eq!(
        reserve(&s, op(17), EPOCH, &[cell]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.window_caps(op(18), &[cap(2, 3)])
        .expect("a newer generation raises it");
    reserve(&s, op(19), EPOCH, &[cell]).expect("cap 2 holds a second");
}

#[test]
fn the_journal_appends_in_order_and_states_its_heads() {
    let Some(s) = live_store() else { return };
    let stream = fresh("journal");
    let r = |b: &[u8]| RecordBytes::new(b.to_vec()).unwrap();
    let id = op(20);
    let h = s
        .append_batch(id, &stream, &[r(b"a"), r(b"b")])
        .expect("append");
    assert_eq!(h, Head { seq: 2, epoch: 0 });
    assert_eq!(
        s.append_batch(id, &stream, &[r(b"a"), r(b"b")]),
        Ok(h),
        "a replay answers the original head"
    );
    let h = s.append_batch(op(21), &stream, &[r(b"c")]).expect("append");
    assert_eq!(h.seq, 3);
    let heads = s.heads().expect("heads");
    assert!(
        heads.contains(&(stream.clone(), Head { seq: 3, epoch: 0 })),
        "{heads:?}"
    );
}

#[test]
fn sessions_upsert_list_by_principal_and_remove() {
    let Some(s) = live_store() else { return };
    let principal = fresh("principal");
    let other = fresh("principal-other");
    let base = unique() >> 2;
    s.session_put(base + 2, "node-b", &principal).expect("put");
    s.session_put(base + 1, "node-a", &other).expect("put");
    s.session_put(base + 1, "node-c", &principal)
        .expect("upsert moves it to another principal");
    assert_eq!(
        s.sessions_for(&principal).expect("list"),
        vec![
            (base + 1, "node-c".to_string()),
            (base + 2, "node-b".to_string())
        ]
    );
    assert_eq!(s.sessions_for(&other).expect("list"), vec![]);
    s.session_remove(base + 1).expect("remove");
    s.session_remove(base + 1)
        .expect("an absent session removes Ok");
    assert_eq!(
        s.sessions_for(&principal).expect("list"),
        vec![(base + 2, "node-b".to_string())]
    );
    s.session_remove(base + 2).expect("remove");
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
    assert!(keys(b"", 0).is_empty());
    assert_eq!(
        s.record_scan(&schema, b"b\xff", 10).expect("scan")[0]
            .1
            .as_slice(),
        b"2",
        "a prefix with no successor scans to the end"
    );
}

/// The plane-record `op_id` write dedupes, still refuses a fork, and refuses a reused op id.
#[test]
fn an_op_id_plane_append_dedupes_and_still_refuses_a_fork() {
    let Some(s) = live_store() else { return };
    let parent = fresh("chain");
    let rec = |seq: u64, body: &[u8]| PlaneRecord {
        kind: "slots_test".into(),
        id: parent.clone(),
        parent: Some(parent.clone()),
        seq,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    let id = op(22);
    s.append_plane_record_op(id, rec(1, b"one").view())
        .expect("append");
    s.append_plane_record_op(id, rec(1, b"one").view())
        .expect("replay");
    let e = s.append_plane_record_op(op(23), rec(1, b"two").view());
    assert!(
        matches!(&e, Err(OpRefused::Failed(t)) if t.contains("the chain has forked")),
        "{e:?}"
    );
    assert_eq!(
        s.append_plane_record_op(id, rec(2, b"two").view()),
        Err(OpRefused::Conflict),
        "the op id was used with different value fields"
    );
    s.append_plane_record_op(op(24), rec(1, b"one").view())
        .expect("the identical record under a new op id is not a fork");
    let chain = s
        .list_plane_records("slots_test", &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"one".to_vec()]);
    s.delete_plane_record("slots_test", &parent).unwrap();
}
