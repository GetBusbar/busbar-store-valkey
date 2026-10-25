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

/// The epoch every draw in the shared database 0 states: nothing there raises the fleet epoch
/// above 0 (every test that does runs over a database of its own, [`Iso`]), so it is never stale.
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
    let _serialised = super::audit_seq_guard();
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
    let _serialised = super::audit_seq_guard();
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
        Ok(vec![0]),
        "a closed slice answers 0 under a new op_id"
    );
    reserve(&s, op(9), EPOCH, &[cell(3)]).expect("the released 3 can be drawn again");
    assert_eq!(
        reserve(&s, op(10), EPOCH, &[cell(1)]),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "the replayed release freed nothing twice"
    );
}

/// A batch naming an emptied rolling slice and a live one answers [0, n]; n is drawable again.
#[test]
fn a_batch_release_of_a_closed_and_a_live_slice_answers_zero_and_the_rest() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("batch-closed");
    let k = key(&bucket, 60);
    s.window_caps(
        op(80),
        &[Cap {
            key: k,
            cap: 5,
            config_gen: 1,
        }],
    )
    .expect("cap");
    let cell = |amount| Cell { key: k, amount };
    let g = reserve(&s, op(81), EPOCH, &[cell(2), cell(3)]).expect("2 + 3 fits 5");
    assert_eq!(release(&s, op(82), &[(g[0].slice_id, 2)]), Ok(vec![2]));
    assert_eq!(
        release(&s, op(83), &[(g[0].slice_id, 1), (g[1].slice_id, 3)]),
        Ok(vec![0, 3])
    );
    assert_eq!(
        reserve(&s, op(84), EPOCH, &[cell(5)]).expect("all 5 drawable again")[0].granted,
        5
    );
}

/// An id never handed out (0, or past the counter) is Failed "was never granted", applying nothing.
#[test]
fn a_release_naming_a_slice_never_granted_is_refused_and_applies_nothing() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("never-granted");
    let k = key(&bucket, 60);
    s.window_caps(
        op(90),
        &[Cap {
            key: k,
            cap: 5,
            config_gen: 1,
        }],
    )
    .expect("cap");
    let cell = |amount| Cell { key: k, amount };
    let g = reserve(&s, op(91), EPOCH, &[cell(5)]).expect("draw");
    let counter: u64 = s
        .with_conn(|c| redis::Commands::get(c, "busbar:slices"))
        .expect("counter");
    for (n, bad) in [0, counter + 1_000_000, u64::MAX].into_iter().enumerate() {
        let r = release(&s, op(92 + n as u64), &[(g[0].slice_id, 5), (bad, 1)]);
        match r {
            Err(OpRefused::Failed(m)) => assert!(
                m.contains("was never granted"),
                "id {bad}: wrong message {m}"
            ),
            other => panic!("id {bad}: expected Failed(never granted), got {other:?}"),
        }
    }
    assert_eq!(
        reserve(&s, op(99), EPOCH, &[cell(1)]),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "a refused release applied nothing"
    );
}

/// A window-0 slice's key is deleted at its first release; a second release still answers 0.
#[test]
fn a_window_0_slice_key_is_deleted_at_its_first_release() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("w0-del");
    let zero = key(&bucket, 0);
    s.window_caps(
        op(100),
        &[Cap {
            key: zero,
            cap: 10,
            config_gen: 1,
        }],
    )
    .expect("cap");
    let g = reserve(
        &s,
        op(101),
        EPOCH,
        &[Cell {
            key: zero,
            amount: 6,
        }],
    )
    .expect("draw");
    let skey = format!("busbar:slice:{}", g[0].slice_id);
    let exists = |s: &ValkeyStore| -> bool {
        s.with_conn(|c| redis::Commands::exists(c, skey.as_str()))
            .expect("exists")
    };
    assert!(exists(&s), "the slice is held before its release");
    assert_eq!(release(&s, op(102), &[(g[0].slice_id, 2)]), Ok(vec![2]));
    assert!(!exists(&s), "a closed window-0 slice key must be deleted");
    assert_eq!(release(&s, op(103), &[(g[0].slice_id, 4)]), Ok(vec![0]));
}

/// RED before slice life (e): a release on window 0 is final. The holder of a 6-unit window-0 slice
/// spent 4 and hands back 2; the slice closes, so a second release returns 0, the 4 spent stay
/// counted (6 more fill the cap of 10) and nothing past the cap is granted. A slice on a rolling
/// window keeps the partial-release rule.
#[test]
fn a_release_on_window_0_is_final() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("w0-final");
    let zero = key(&bucket, 0);
    s.window_caps(
        op(60),
        &[Cap {
            key: zero,
            cap: 10,
            config_gen: 1,
        }],
    )
    .expect("the window-0 cap");
    let draw = |n: u64, amount: u64| reserve(&s, op(n), EPOCH, &[Cell { key: zero, amount }]);
    let g = draw(61, 6).expect("a window-0 draw within its cap");
    assert_eq!(release(&s, op(62), &[(g[0].slice_id, 2)]), Ok(vec![2]));
    assert_eq!(
        release(&s, op(63), &[(g[0].slice_id, 4)]),
        Ok(vec![0]),
        "a window-0 slice stayed open after its release"
    );
    assert_eq!(
        draw(64, 6).expect("the returned 2 are drawable")[0].granted,
        6
    );
    assert_eq!(
        draw(65, 1),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "the spent part of a released window-0 slice was not counted"
    );

    let rolling = fresh("w0-rolling");
    let k = key(&rolling, 120);
    s.window_caps(
        op(66),
        &[Cap {
            key: k,
            cap: 10,
            config_gen: 1,
        }],
    )
    .expect("the rolling cap");
    let g = reserve(&s, op(67), EPOCH, &[Cell { key: k, amount: 6 }]).expect("a rolling draw");
    assert_eq!(release(&s, op(68), &[(g[0].slice_id, 2)]), Ok(vec![2]));
    assert_eq!(
        release(&s, op(69), &[(g[0].slice_id, 4)]),
        Ok(vec![4]),
        "a rolling-window slice keeps what it still holds for a later release"
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

/// A store over a DATABASE of its own (`VALKEY_URL` re-pointed at `db`, emptied first and on drop).
/// The fleet epoch is one key for the whole namespace, so a test that raises it must not do so in
/// the shared database 0: every other test reserves at epoch 0 there and would be stale. Each test
/// below owns one database number (1 to 10; the suite's other live tests use 0 and 11 to 15), so the
/// tests run in parallel without sharing an epoch.
struct Iso {
    url: String,
    store: Option<ValkeyStore>,
}

impl Iso {
    fn new(db: u32) -> Option<Self> {
        live_store()?;
        let url = super::url_for_db(db);
        Self::flush(&url);
        let store = Some(ValkeyStore::connect(&url).expect("connect"));
        Some(Iso { url, store })
    }

    fn flush(url: &str) {
        let mut c = redis::Client::open(url)
            .and_then(|c| c.get_connection())
            .expect("an independent client");
        redis::cmd("FLUSHDB").query::<()>(&mut c).expect("FLUSHDB");
    }

    fn s(&self) -> &ValkeyStore {
        self.store.as_ref().expect("open")
    }

    /// A RESTART: the instance goes away and a fresh one opens over the same state.
    fn restart(&mut self) {
        self.store = None;
        self.store = Some(ValkeyStore::connect(&self.url).expect("reconnect"));
    }

    /// A second, independent instance over the same state (another node of the fleet).
    fn node(&self) -> ValkeyStore {
        ValkeyStore::connect(&self.url).expect("another node")
    }

    /// An independent upstream client on this test's database.
    fn raw(&self) -> redis::Connection {
        redis::Client::open(self.url.as_str())
            .and_then(|c| c.get_connection())
            .expect("an independent client")
    }

    /// The server's clock in ms (`TIME`): the store's one clock.
    fn now_ms(&self) -> u64 {
        let (secs, micros): (u64, u64) = redis::cmd("TIME").query(&mut self.raw()).unwrap();
        secs * 1000 + micros / 1000
    }

    /// Move the store's clock forward by `ms`: every slice's expiry (its hash's `until` and its
    /// score in its slot's open-slice index) moves back by as much.
    fn advance_ms(&self, ms: u64) {
        let mut c = self.raw();
        let slices: Vec<String> = c
            .scan_match::<_, String>("busbar:slice:*")
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for k in slices {
            let until: Option<u64> = c.hget(&k, "until").unwrap();
            if let Some(until) = until {
                let _: () = c.hset(&k, "until", until.saturating_sub(ms)).unwrap();
            }
        }
        let indexes: Vec<String> = c
            .scan_match::<_, String>("busbar:open:*")
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for k in indexes {
            let ids: Vec<(String, u64)> = c.zrange_withscores(&k, 0, -1).unwrap();
            for (id, until) in ids {
                let _: () = c.zadd(&k, id, until.saturating_sub(ms)).unwrap();
            }
        }
    }

    fn cap(&self, bucket: &str, cap: u64) {
        self.s()
            .window_caps(
                op(1),
                &[Cap {
                    key: requests(bucket),
                    cap,
                    config_gen: 1,
                }],
            )
            .expect("the cap is pushed");
    }

    fn draw(&self, bucket: &str, amount: u64, epoch: u64) -> Result<Grant, ReserveRefused> {
        reserve(
            self.s(),
            op(2),
            epoch,
            &[Cell {
                key: requests(bucket),
                amount,
            }],
        )
        .map(|g| g[0])
    }
}

impl Drop for Iso {
    fn drop(&mut self) {
        self.store = None;
        Self::flush(&self.url);
    }
}

use redis::Commands as _;

fn requests(bucket: &str) -> CellKey<'_> {
    key(bucket, 1_790_000_000_000)
}

const TTL: u64 = busbar_contract::abi::store::SLICE_TTL_MS;

/// Rule (b): a reserve under an epoch below the stored one is StaleEpoch, applies nothing and records
/// nothing under its `op_id` (the same id retried under a current epoch is evaluated afresh).
#[test]
fn a_stale_epoch_is_refused_and_applies_nothing() {
    let Some(iso) = Iso::new(1) else { return };
    iso.cap("stale", 10);
    iso.draw("stale", 1, 2).expect("epoch 2 draws");
    let id = op(3);
    let cell = Cell {
        key: requests("stale"),
        amount: 1,
    };
    assert_eq!(
        reserve(iso.s(), id, 1, &[cell]),
        Err(ReserveRefused::StaleEpoch),
        "a reserve under an epoch below the stored one is StaleEpoch"
    );
    assert!(
        reserve(iso.s(), id, 2, &[cell]).is_ok(),
        "the refused reserve left a row under its op_id"
    );
    iso.draw("stale", 8, 2)
        .expect("the stale reserve applied nothing: 1 + 1 + 8 of 10");
    assert_eq!(
        iso.draw("stale", 1, 2).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

/// Rule (a): the stored epoch survives a restart, and a second node sees the same fleet epoch.
#[test]
fn the_epoch_survives_a_restart() {
    let Some(mut iso) = Iso::new(2) else { return };
    iso.cap("restart", 10);
    iso.draw("restart", 1, 3).expect("epoch 3 draws");
    let other = iso.node();
    iso.restart();
    assert_eq!(
        iso.draw("restart", 1, 2).map(drop),
        Err(ReserveRefused::StaleEpoch),
        "the epoch was lost on restart"
    );
    assert_eq!(
        reserve(
            &other,
            op(4),
            2,
            &[Cell {
                key: requests("restart"),
                amount: 1
            }]
        ),
        Err(ReserveRefused::StaleEpoch),
        "another node of the fleet did not see the epoch"
    );
}

/// Rule (c): a grant is valid for at most SLICE_TTL_MS from the store's clock, and an expired slice's
/// unreturned part is drawable again.
#[test]
fn a_grant_is_bounded_and_an_expired_slice_returns_to_the_window() {
    let Some(iso) = Iso::new(3) else { return };
    iso.cap("ttl", 5);
    let before = iso.now_ms();
    let g = iso.draw("ttl", 5, 2).expect("draws the whole window");
    let after = iso.now_ms();
    assert!(
        g.valid_until_ms >= before + TTL && g.valid_until_ms <= after + TTL,
        "valid_until_ms {} is not within [{before} + SLICE_TTL_MS, {after} + SLICE_TTL_MS]",
        g.valid_until_ms
    );
    assert_eq!(
        iso.draw("ttl", 1, 2).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    iso.advance_ms(TTL + 1);
    iso.draw("ttl", 5, 2)
        .expect("an expired slice's unspent returned to the window");
}

/// A release applies whatever the epoch, returns each unit once, and an expiry after the release
/// returns nothing more.
#[test]
fn a_stale_epoch_release_applies_exactly_once() {
    let Some(iso) = Iso::new(4) else { return };
    iso.cap("release", 10);
    iso.cap("release-fence", 1);
    let g = iso.draw("release", 4, 5).expect("epoch 5 draws");
    iso.draw("release-fence", 1, 6).expect("epoch 6 draws");
    let rel = |id: u64, epoch: u64, n: u64| {
        call::<_, OpRefused>(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::slice_release(
                iso.s(),
                op(5),
                epoch,
                &[(id, n)],
            ),
        )
    };
    assert_eq!(rel(g.slice_id, 5, 4), Ok(vec![4]), "never refused");
    assert_eq!(rel(g.slice_id, 6, 4), Ok(vec![0]), "nothing left");
    iso.advance_ms(TTL + 1);
    iso.draw("release", 10, 6)
        .expect("the returned 4 are drawable");
    assert_eq!(
        iso.draw("release", 1, 6).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "expiry returned the released slice again"
    );
    assert_eq!(
        rel(g.slice_id, 6, 4),
        Ok(vec![0]),
        "a slice closed and gone answers 0"
    );
}

/// A closed rolling-window slice is a granted id: a later release of it (a new `op_id`) answers 0 and
/// does not fail the batch it rides in; an id never granted still FAILS.
#[test]
fn a_closed_slice_releases_zero_and_a_never_granted_id_fails() {
    let Some(iso) = Iso::new(5) else { return };
    iso.cap("closed", 10);
    iso.cap("closed-peer", 10);
    let a = iso.draw("closed", 3, 0).expect("draw a");
    let b = iso.draw("closed-peer", 4, 0).expect("draw b");
    let rel = |items: &[(u64, u64)]| release(iso.s(), op(6), items);
    assert_eq!(rel(&[(a.slice_id, 3)]), Ok(vec![3]), "fully returned");
    assert_eq!(
        rel(&[(b.slice_id, 4), (a.slice_id, 3)]),
        Ok(vec![4, 0]),
        "the closed slice answers 0 and the other item still lands"
    );
    assert_eq!(rel(&[(a.slice_id, 3)]), Ok(vec![0]));
    // Expired and reclaimed by a later reserve is closed too.
    let c = iso.draw("closed", 2, 0).expect("draw c");
    iso.advance_ms(TTL + 1);
    iso.draw("closed", 10, 0).expect("c's 2 came back");
    assert_eq!(rel(&[(c.slice_id, 2)]), Ok(vec![0]));
    let last: u64 = iso.raw().get("busbar:slices").unwrap();
    for never in [last + 1, last + 1000, u64::MAX, 0] {
        assert!(
            matches!(rel(&[(never, 1)]), Err(OpRefused::Failed(_))),
            "slice {never} was never granted"
        );
    }
}

/// Two nodes pushing the first cap of a new window at once: the higher generation wins whichever
/// lands first, and the same generation with a different cap is a CapConflict for exactly one.
#[test]
fn a_concurrent_first_cap_push_keeps_the_higher_generation() {
    const ROUNDS: usize = 150;
    let Some(iso) = Iso::new(6) else { return };
    let barrier = std::sync::Barrier::new(2);
    let push = |cap: u64, gen: u64, tag: &'static str| {
        let node = iso.node();
        let barrier = &barrier;
        move || {
            (0..ROUNDS)
                .map(|i| {
                    barrier.wait();
                    node.window_caps(
                        op(7),
                        &[Cap {
                            key: requests(&format!("race-{tag}-{i}")),
                            cap,
                            config_gen: gen,
                        }],
                    )
                })
                .collect::<Vec<_>>()
        }
    };
    // Round i of "lt" is gen 6 cap 200 against gen 5 cap 100; of "eq" gen 7 cap 100 against 200.
    let (hi, lo) = std::thread::scope(|sc| {
        let hi = sc.spawn(push(200, 6, "lt"));
        let lo = sc.spawn(push(100, 5, "lt"));
        (hi.join().unwrap(), lo.join().unwrap())
    });
    assert!(hi.iter().all(Result::is_ok), "{hi:?}");
    assert!(lo.iter().all(Result::is_ok), "{lo:?}");
    let mut admin = iso.raw();
    let slots: Vec<String> = admin
        .scan_match::<_, String>("busbar:cap:*")
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let rows: Vec<(u64, u64)> = slots
        .iter()
        .map(|k| {
            let (cap, gen): (u64, u64) = redis::cmd("HMGET")
                .arg(k)
                .arg("cap")
                .arg("gen")
                .query(&mut admin)
                .unwrap();
            (cap, gen)
        })
        .collect();
    let lower_won = rows.iter().filter(|&&(c, g)| c != 200 || g != 6).count();
    assert_eq!(rows.len(), ROUNDS);
    assert_eq!(lower_won, 0, "a lower generation overwrote a higher one");

    let (x, y) = std::thread::scope(|sc| {
        let x = sc.spawn(push(100, 7, "eq"));
        let y = sc.spawn(push(200, 7, "eq"));
        (x.join().unwrap(), y.join().unwrap())
    });
    for (i, (x, y)) in x.iter().zip(&y).enumerate() {
        let ok = x.is_ok() as u8 + y.is_ok() as u8;
        let conflict = [x, y]
            .iter()
            .filter(|r| matches!(r, Err(CapsRefused::CapConflict { index: 0 })))
            .count();
        assert_eq!(
            (ok, conflict),
            (1, 1),
            "round {i}: the same generation with a different cap must conflict: {x:?} {y:?}"
        );
    }
}

/// A slice of 2^63 or more must still expire and come back (its amounts are exact `u64`s).
#[test]
fn a_huge_expired_slice_returns_to_the_window() {
    let Some(iso) = Iso::new(7) else { return };
    iso.cap("huge", u64::MAX);
    iso.draw("huge", u64::MAX - 1, 0).expect("a huge draw");
    iso.advance_ms(TTL + 1);
    iso.draw("huge", u64::MAX - 1, 0)
        .expect("the expired huge slice came back");
}

/// The v7 -> v8 step: slices a v7 build left open (granted `u64::MAX`, never expiring) are stamped
/// to expire one SLICE_TTL_MS after the upgrade and indexed for reclaim, the epoch key exists at 0,
/// and the step runs once.
#[test]
fn the_v8_upgrade_stamps_open_slices_and_creates_the_epoch() {
    let Some(mut iso) = Iso::new(8) else { return };
    iso.cap("legacy", 5);
    iso.draw("legacy", 5, 0).expect("a slice");
    let slice: String = {
        // Put the namespace back to what a v7 build left: no epoch key, no expiry, no index.
        let mut c = iso.raw();
        let slices: Vec<String> = c
            .scan_match::<_, String>("busbar:slice:*")
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(slices.len(), 1, "{slices:?}");
        let _: () = c.hdel(&slices[0], "until").unwrap();
        let _: () = c.del("busbar:epoch").unwrap();
        let indexes: Vec<String> = c
            .scan_match::<_, String>("busbar:open:*")
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for k in indexes {
            let _: () = c.del(k).unwrap();
        }
        let _: () = c.set("busbar:schema", 7).unwrap();
        slices[0].clone()
    };
    let before = iso.now_ms();
    iso.restart();
    let after = iso.now_ms();
    let mut c = iso.raw();
    let until: u64 = c.hget(&slice, "until").unwrap();
    let epoch: Option<u64> = c.get("busbar:epoch").unwrap();
    assert_eq!(epoch, Some(0));
    assert!(
        before + TTL <= until && until <= after + TTL,
        "the stranded slice expires one TTL after the upgrade, not never: {until}"
    );
    let marker: i64 = c.get("busbar:schema").unwrap();
    assert_eq!(marker, 8);
    iso.restart();
    let again: u64 = c.hget(&slice, "until").unwrap();
    assert_eq!(again, until, "the step ran once");
    iso.advance_ms(TTL + 1);
    iso.draw("legacy", 5, 0)
        .expect("the stranded slice's money came back");
}

/// Rule (a) and (c) over a run of epochs: one below the stored epoch is stale, the stored epoch and
/// any above it draw (and only rise), and no grant is `u64::MAX`.
#[test]
fn an_epoch_below_the_stored_one_is_stale_and_a_grant_expires() {
    let Some(iso) = Iso::new(9) else { return };
    iso.cap("epoch", 100);
    let before = iso.now_ms();
    for (epoch, stale) in [
        (7, false),
        (0, true),
        (7, false),
        (u64::MAX, false),
        (7, true),
        (u64::MAX, false),
    ] {
        match iso.draw("epoch", 1, epoch) {
            Ok(g) => {
                assert!(!stale, "epoch {epoch} drew under a higher stored epoch");
                assert_ne!(g.valid_until_ms, u64::MAX, "a fleet slice never expires");
                assert!(
                    g.valid_until_ms >= before + TTL && g.valid_until_ms <= iso.now_ms() + TTL,
                    "valid_until_ms {} is not now + SLICE_TTL_MS",
                    g.valid_until_ms
                );
            }
            Err(e) => {
                assert!(stale, "epoch {epoch} refused: {e:?}");
                assert_eq!(e, ReserveRefused::StaleEpoch);
            }
        }
    }
}

/// Rule (c) at release: once the server's clock passes `valid_until_ms` the slice is EXPIRED and its
/// unreturned part already went back to the window, so a release of it (with no reserve in between
/// to reclaim it) answers 0, and the headroom comes back exactly once.
#[test]
fn an_expired_slice_releases_zero_and_its_headroom_returns_once() {
    let Some(iso) = Iso::new(10) else { return };
    iso.cap("expired-release", 5);
    let g = iso.draw("expired-release", 3, 0).expect("draw");
    iso.advance_ms(TTL + 1);
    assert_eq!(
        release(iso.s(), op(8), &[(g.slice_id, 3)]),
        Ok(vec![0]),
        "an expired slice's money went back at expiry, not at its release"
    );
    iso.draw("expired-release", 5, 0)
        .expect("the expired 3 are back: the whole cap draws");
    assert_eq!(
        iso.draw("expired-release", 1, 0).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "the expired slice's headroom came back twice"
    );
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

/// S2 for the remaining op-id slots: the same `op_id` with a DIFFERENT body answers `Conflict` and
/// applies nothing.
#[test]
fn the_same_op_id_with_a_different_body_conflicts_on_every_slot() {
    let _serialised = super::audit_seq_guard();
    let Some(s) = live_store() else { return };

    // slice_release: the second body hands back more, and must change nothing.
    let bucket = fresh("s2-release");
    let k = key(&bucket, 120);
    s.window_caps(
        op(80),
        &[Cap {
            key: k,
            cap: 10,
            config_gen: 1,
        }],
    )
    .expect("cap");
    let g = reserve(&s, op(81), EPOCH, &[Cell { key: k, amount: 6 }]).expect("draw");
    let id = op(82);
    assert_eq!(release(&s, id, &[(g[0].slice_id, 1)]), Ok(vec![1]));
    assert_eq!(
        release(&s, id, &[(g[0].slice_id, 2)]),
        Err(OpRefused::Conflict),
        "a different release body under one op id must conflict"
    );
    assert_eq!(
        release(&s, op(83), &[(g[0].slice_id, 5)]),
        Ok(vec![5]),
        "the conflicting release applied nothing: 5 are still held"
    );

    // window_caps: a different cap under one op id conflicts and the first cap stands.
    let capped = fresh("s2-caps");
    let ck = key(&capped, 120);
    let cap = |cap| Cap {
        key: ck,
        cap,
        config_gen: 1,
    };
    let id = op(84);
    s.window_caps(id, &[cap(1)]).expect("first push");
    assert_eq!(s.window_caps(id, &[cap(2)]), Err(CapsRefused::Conflict));
    let cell = Cell { key: ck, amount: 1 };
    reserve(&s, op(85), EPOCH, &[cell]).expect("cap 1 holds one");
    assert_eq!(
        reserve(&s, op(86), EPOCH, &[cell]),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "the conflicting push applied nothing"
    );

    // add_usage_batch
    let a = fresh("s2-batch");
    let d = |n| UsageDelta {
        requests: n,
        billable_requests: 0,
        models: Vec::new(),
    };
    let id = op(87);
    s.add_usage_batch(id, &[(a.as_str(), 0, d(1))])
        .expect("applies");
    assert_eq!(
        s.add_usage_batch(id, &[(a.as_str(), 0, d(5))]),
        Err(OpRefused::Conflict)
    );
    assert_eq!(s.get_usage(&a, 0).unwrap().requests, 1);

    // add_metering_batch
    let bucket = super::unique_bucket(88);
    let m = |n| busbar_contract::records::MeteringDelta {
        key_id: fresh("vk"),
        bucket,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: n,
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
    let first = m(5);
    let id = op(89);
    s.add_metering_batch(id, std::slice::from_ref(&first))
        .expect("applies");
    let other = busbar_contract::records::MeteringDelta {
        tokens_input: 99,
        ..first.clone()
    };
    assert_eq!(s.add_metering_batch(id, &[other]), Err(OpRefused::Conflict));
    let rows = s.list_metering(bucket).expect("list");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].tokens_input, 5, "{rows:?}");

    // append_audit_batch
    let base = audit_base();
    let id = op(90);
    s.append_audit_batch(id, &[audit(base, "one")])
        .expect("applies");
    assert_eq!(
        s.append_audit_batch(id, &[audit(base, "one"), audit(base + 1, "two")]),
        Err(OpRefused::Conflict)
    );
    let stored: Vec<u64> = s
        .list_audit()
        .unwrap()
        .into_iter()
        .map(|r| r.seq)
        .filter(|q| *q == base || *q == base + 1)
        .collect();
    assert_eq!(stored, vec![base], "the conflicting batch wrote nothing");
    s.purge_audit_seq_for_test(base).unwrap();
}

/// A `window_caps` push that conflicts part-way applies NONE of itself: the first cap here would
/// CHANGE its stored value (a newer generation), and must still read back unchanged.
#[test]
fn a_conflicting_window_caps_push_does_not_apply_its_earlier_caps() {
    let Some(s) = live_store() else { return };
    let (a, b) = (fresh("atomic-a"), fresh("atomic-b"));
    let (ka, kb) = (key(&a, 120), key(&b, 120));
    let cap = |key, cap, config_gen| Cap {
        key,
        cap,
        config_gen,
    };
    s.window_caps(op(91), &[cap(ka, 1, 1)]).expect("a: cap 1");
    assert_eq!(
        s.window_caps(op(92), &[cap(ka, 5, 2), cap(kb, 1, 1), cap(kb, 2, 1)]),
        Err(CapsRefused::CapConflict { index: 2 })
    );
    let cell = Cell { key: ka, amount: 1 };
    reserve(&s, op(93), EPOCH, &[cell]).expect("a still holds one");
    assert_eq!(
        reserve(&s, op(94), EPOCH, &[cell]),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "the conflicting push raised a's cap to 5 before it failed"
    );
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
