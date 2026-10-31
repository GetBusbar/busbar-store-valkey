// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live Valkey: the durable `op_id` dedupe (S1-S4),
//! the usage and metering batches, the plane-record append and the kernel's records, and the v9
//! upgrade that drops what the deleted slots kept. The settings refusals need no server and always
//! run.
//!
//! Every test names its own buckets, schemas and keys freshly (process, clock, counter), so
//! the suite runs in parallel against the one shared Valkey and leaves nothing another test reads.

use super::{live_store, Connect};
use crate::ValkeyStore as Door;
use busbar_contract::abi::sdk::store::{OpRefused, OpResult, StoreSlots};
use busbar_contract::store_calls::StoreFailure;

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, UsageDelta,
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
            StoreFailure::Refused(t) => OpRefused::Refused(t),
            StoreFailure::Failed(t) | StoreFailure::Fault(t) => OpRefused::Failed(t),
            other => OpRefused::Failed(other.to_string()),
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
    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()>;
    fn add_metering_batch(
        &self,
        op: OpId,
        d: &[busbar_contract::records::MeteringDelta],
    ) -> OpResult<()>;
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
    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        call(
            <ValkeyStore as busbar_contract::store_calls::StoreCalls>::add_usage_batch(
                self, op, cells,
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
    assert!(e.contains("`url` is required"), "{e}");
    let e = Door::open(b"{}", None).expect_err("no url");
    assert!(e.contains("`url` is required"), "{e}");
    let e = Door::open(b"{ not json", None).expect_err("bad json");
    assert!(e.contains("invalid valkey plugin config"), "{e}");
    let e =
        Door::open(br#"{"url":"not-a-valkey-url"}"#, None).expect_err("a url the driver refuses");
    assert!(e.contains("invalid valkey plugin config: url: "), "{e}");
    assert!(!e.contains("failed to connect"), "{e}");
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
    let cells = |d: &UsageDelta| [(bucket.as_str(), 60, d.clone())];
    s.add_usage_batch(id, &cells(&delta)).expect("applies");
    s.add_usage_batch(id, &cells(&delta))
        .expect("a replay answers Ok");
    let url = std::env::var("VALKEY_URL").expect("live_store read it");
    let again = ValkeyStore::connect(&url).expect("reconnect");
    again
        .add_usage_batch(id, &cells(&delta))
        .expect("a replay after a reconnect answers Ok");
    let other = UsageDelta {
        requests: 4,
        ..delta.clone()
    };
    assert_eq!(
        again.add_usage_batch(id, &cells(&other)),
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
    let rows = s.list_metering(bucket).expect("list");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].tokens_input, 10, "two deltas, once each: {rows:?}");
}

/// A store over a DATABASE of its own (`VALKEY_URL` re-pointed at `db`, emptied first and on drop):
/// a test that seeds whole key families and asserts they are gone must not do it in the shared
/// database 0. Each test below owns one database number (the suite's other live tests use 0 and 11 to
/// 15), so the tests run in parallel without sharing a namespace.
struct Iso {
    url: String,
    store: Option<ValkeyStore>,
}

impl Iso {
    fn new(db: u32) -> Option<Self> {
        live_store()?;
        super::assert_private_db(db);
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

    /// An independent upstream client on this test's database.
    fn raw(&self) -> redis::Connection {
        redis::Client::open(self.url.as_str())
            .and_then(|c| c.get_connection())
            .expect("an independent client")
    }
}

impl Drop for Iso {
    fn drop(&mut self) {
        self.store = None;
        Self::flush(&self.url);
    }
}

use redis::Commands as _;

/// S2 for the batch slots: the same `op_id` with a DIFFERENT body answers `Conflict` and
/// applies nothing.
#[test]
fn the_same_op_id_with_a_different_body_conflicts_on_every_batch_slot() {
    let Some(s) = live_store() else { return };

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

/// AN EMPTY PUT REMOVES THE ROW (slot 40's rule, ARCHITECT 2026-10-21): the host writes every
/// strike as an empty `record_put` and reads empty as absent, so the key LEAVES both the ordered key
/// set and the values hash: `record_get` answers `None`, `record_scan` never returns it, and both
/// shrink. Removing a row that is not there is `Ok`.
#[test]
fn an_empty_put_removes_the_row() {
    let Some(s) = live_store() else { return };
    let schema = fresh("schema");
    let p = format!("busbar:records:{}", crate::hex(schema.as_bytes()));
    let url = std::env::var("VALKEY_URL").expect("a live store has a URL");
    let mut raw = redis::Client::open(url.as_str())
        .and_then(|c| c.get_connection())
        .expect("an independent client");
    let mut held = || -> (u64, u64) {
        let keys: u64 = redis::cmd("ZCARD")
            .arg(format!("{p}:k"))
            .query(&mut raw)
            .expect("ZCARD");
        let values: u64 = redis::cmd("HLEN")
            .arg(format!("{p}:v"))
            .query(&mut raw)
            .expect("HLEN");
        (keys, values)
    };
    s.record_put(&schema, b"a/1", b"one").expect("put");
    s.record_put(&schema, b"a/2", b"two").expect("put");
    assert_eq!(held(), (2, 2));

    s.record_put(&schema, b"a/1", b"").expect("strike");
    assert_eq!(
        held(),
        (1, 1),
        "the struck row left the key set and the values"
    );
    assert_eq!(s.record_get(&schema, b"a/1").expect("get"), None);
    let scan: Vec<(Vec<u8>, Vec<u8>)> = s
        .record_scan(&schema, b"a/", 10)
        .expect("scan")
        .into_iter()
        .map(|(k, v)| (k, v.as_slice().to_vec()))
        .collect();
    assert_eq!(
        scan,
        vec![(b"a/2".to_vec(), b"two".to_vec())],
        "a scan never returns a struck row"
    );

    s.record_put(&schema, b"a/9", b"")
        .expect("a strike of nothing is Ok");
    assert_eq!(held(), (1, 1));
    s.record_put(&schema, b"a/1", b"again").expect("put again");
    assert_eq!(
        s.record_get(&schema, b"a/1")
            .expect("get")
            .map(|r| r.as_slice().to_vec()),
        Some(b"again".to_vec())
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

/// A body an older build recorded (`<slot>:<values {:?}>`) still dedupes after the upgrade: the
/// same op replays and applies nothing, a different op under its id conflicts.
#[test]
fn an_older_builds_recorded_body_replays_and_a_different_op_conflicts() {
    let Some(s) = live_store() else { return };
    let mut raw = redis::Client::open(std::env::var("VALKEY_URL").expect("live_store read it"))
        .and_then(|c| c.get_connection())
        .expect("an independent client");
    let mut seed = |id: OpId, body: String| {
        let k = format!("busbar:op:{}", crate::hex(&id.0));
        let _: () = raw
            .hset_multiple(&k, &[("b", body.as_str()), ("a", "")])
            .unwrap();
    };

    let bucket = fresh("older-usage");
    let d = |n| UsageDelta {
        requests: n,
        billable_requests: 0,
        models: Vec::new(),
    };
    let cells = [(bucket.as_str(), 0, d(2))];
    let id = op(90);
    seed(id, format!("add_usage_batch:{:?}", &cells[..]));
    s.add_usage_batch(id, &cells).expect("replays");
    assert_eq!(
        s.add_usage_batch(id, &[(bucket.as_str(), 0, d(3))]),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        s.get_usage(&bucket, 0).unwrap().requests,
        0,
        "nothing applied"
    );

    let mbucket = super::unique_bucket(91);
    let m = busbar_contract::records::MeteringDelta {
        key_id: fresh("vk"),
        bucket: mbucket,
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
    let deltas = [m.clone()];
    let id = op(92);
    seed(id, format!("add_metering_batch:{:?}", &deltas[..]));
    s.add_metering_batch(id, &deltas).expect("replays");
    let other = busbar_contract::records::MeteringDelta {
        tokens_input: 6,
        ..m
    };
    assert_eq!(s.add_metering_batch(id, &[other]), Err(OpRefused::Conflict));
    assert!(
        s.list_metering(mbucket).expect("list").is_empty(),
        "nothing applied"
    );

    let kind = fresh("older-plane");
    let rec = |body: &[u8]| PlaneRecord {
        kind: kind.clone(),
        id: "r".into(),
        parent: None,
        seq: 0,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    let one = rec(b"one");
    let id = op(93);
    seed(id, format!("append_plane_record:{:?}", one.view()));
    s.append_plane_record_op(id, one.view()).expect("replays");
    assert_eq!(
        s.append_plane_record_op(id, rec(b"two").view()),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        s.get_plane_record(&kind, "r").unwrap(),
        None,
        "nothing applied"
    );
}

/// An `op_id` write still runs, once, when the server's script cache lost its script.
#[test]
fn an_op_id_write_runs_after_the_script_cache_is_flushed() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("noscript");
    let cells = [(
        bucket.as_str(),
        0,
        UsageDelta {
            requests: 1,
            billable_requests: 0,
            models: Vec::new(),
        },
    )];
    s.add_usage_batch(op(94), &cells).expect("applies");
    let mut raw = redis::Client::open(std::env::var("VALKEY_URL").expect("live_store read it"))
        .and_then(|c| c.get_connection())
        .expect("an independent client");
    redis::cmd("SCRIPT")
        .arg("FLUSH")
        .query::<()>(&mut raw)
        .expect("SCRIPT FLUSH");
    let id = op(95);
    s.add_usage_batch(id, &cells)
        .expect("applies after the flush");
    s.add_usage_batch(id, &cells).expect("replays");
    assert_eq!(s.get_usage(&bucket, 0).unwrap().requests, 2);
}

/// The v8 -> v9 step: every key the deleted slots kept (the money keys, the journal, the sessions)
/// is gone after the upgrade, and so are the dedupe hashes of the deleted slots; the dedupe hash of
/// a kept slot survives, so its op replays across the upgrade and applies nothing.
#[test]
fn the_v9_upgrade_drops_the_money_and_dead_slot_keys() {
    let Some(mut iso) = Iso::new(8) else { return };
    let bucket = fresh("v9");
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 2,
        models: Vec::new(),
    };
    let cells = [(bucket.as_str(), 60, delta.clone())];
    let kept = op(40);
    iso.s().add_usage_batch(kept, &cells).expect("applies");
    iso.s()
        .record_put("v9-schema", b"k", b"v")
        .expect("a record the upgrade must keep");

    // The namespace a v8 build left: the dead slots' keys, and their op hashes.
    let dead_ops = [
        "reserve:0:[]",
        "slice_release:0:[]",
        "window_caps:[]",
        "append_batch:\"s\":[]",
        "add_usage:\"b\":1:UsageDelta",
        "add_metering:MeteringDelta",
        "append_audit:AuditRecord",
        "append_audit_batch:[]",
    ];
    let mut c = iso.raw();
    let dead_keys = [
        "busbar:cap:62:-:1::60",
        "busbar:slice:1",
        "busbar:slices",
        "busbar:open:62:-:1::60",
        "busbar:epoch",
        "busbar:journal:73",
        "busbar:journal:streams",
        "busbar:session:7",
        "busbar:sessions:70",
    ];
    for k in dead_keys {
        let _: () = c.set(k, "x").unwrap();
    }
    for (i, body) in dead_ops.iter().enumerate() {
        let k = format!("busbar:op:dead{i}");
        let _: () = c.hset_multiple(&k, &[("b", *body), ("a", "")]).unwrap();
    }
    // A v8 build recorded the kept op's body in its own form.
    let kept_key = format!("busbar:op:{}", crate::hex(&kept.0));
    let v8_body = format!("add_usage_batch:{:?}", &cells[..]);
    let _: () = c.hset(&kept_key, "b", v8_body).unwrap();
    let _: () = c.set("busbar:schema", 8).unwrap();
    drop(c);

    iso.restart();

    let mut c = iso.raw();
    for k in dead_keys {
        let there: bool = c.exists(k).unwrap();
        assert!(!there, "{k} survived the upgrade");
    }
    for i in 0..dead_ops.len() {
        let k = format!("busbar:op:dead{i}");
        let there: bool = c.exists(&k).unwrap();
        assert!(!there, "the dedupe hash {k} of a deleted slot survived");
    }
    let marker: i64 = c.get("busbar:schema").unwrap();
    assert_eq!(marker, 9);
    // A kept slot's op replays across the upgrade and applies nothing.
    iso.s()
        .add_usage_batch(kept, &cells)
        .expect("a replay across the upgrade answers Ok");
    assert_eq!(iso.s().get_usage(&bucket, 60).unwrap().requests, 3);
    let other = [(
        bucket.as_str(),
        60,
        UsageDelta {
            requests: 9,
            ..delta
        },
    )];
    assert_eq!(
        iso.s().add_usage_batch(kept, &other),
        Err(OpRefused::Conflict),
        "the kept op's record survived, so a different body still conflicts"
    );
    let got = iso.s().record_get("v9-schema", b"k").unwrap();
    assert_eq!(got.as_ref().map(RecordBytes::as_slice), Some(&b"v"[..]));
}

fn raw_conn() -> redis::Connection {
    let url = std::env::var("VALKEY_URL").expect("live_store read it");
    redis::Client::open(url)
        .and_then(|c| c.get_connection())
        .expect("an independent client")
}

fn metering_delta(bucket: u64, tokens_input: u64) -> busbar_contract::records::MeteringDelta {
    busbar_contract::records::MeteringDelta {
        key_id: "vk-pin".into(),
        bucket,
        model: "m".into(),
        provider: "p".into(),
        tokens_input,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 0,
        billable_requests: 0,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    }
}

/// A counter at i64::MAX plus a positive delta pins at i64::MAX (rule 8): the batch answers Ok.
#[test]
fn a_usage_counter_at_i64_max_pins_instead_of_failing() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("pin-usage");
    let key = format!("busbar:usage:{bucket}:0");
    let mut r = raw_conn();
    let _: () = r.hset(&key, "requests", i64::MAX).unwrap();
    let d = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: Vec::new(),
    };
    s.add_usage_batch(op(40), &[(bucket.as_str(), 0, d)])
        .expect("pins, does not fail");
    let got: String = r.hget(&key, "requests").unwrap();
    assert_eq!(got, i64::MAX.to_string());
    let one: String = r.hget(&key, "billable_requests").unwrap();
    assert_eq!(one, "1");
}

#[test]
fn a_metering_counter_at_i64_max_pins_instead_of_failing() {
    let Some(s) = live_store() else { return };
    let bucket = super::unique_bucket(41);
    s.add_metering_batch(op(41), &[metering_delta(bucket, u64::MAX)])
        .expect("fills the counter to i64::MAX");
    s.add_metering_batch(op(42), &[metering_delta(bucket, 1)])
        .expect("pins, does not fail");
    let rows = s.list_metering(bucket).expect("list");
    assert_eq!(rows[0].tokens_input, i64::MAX as u64, "{rows:?}");
}

/// A cell the batch cannot add to refuses the WHOLE batch: no other cell applies and the op is not
/// recorded, so a retry under the same op id with the key fixed applies.
#[test]
fn a_batch_with_an_unusable_cell_applies_nothing_and_records_nothing() {
    let Some(s) = live_store() else { return };
    let (bad, good) = (fresh("atomic-bad"), fresh("atomic-good"));
    let mut r = raw_conn();
    let bad_key = format!("busbar:usage:{bad}:0");
    let _: () = r.set(&bad_key, "secret-text").unwrap();
    let d = UsageDelta {
        requests: 2,
        billable_requests: 0,
        models: Vec::new(),
    };
    let cells = [(bad.as_str(), 0, d.clone()), (good.as_str(), 0, d)];
    let id = op(43);
    let e = s.add_usage_batch(id, &cells).expect_err("refused");
    assert!(
        matches!(&e, OpRefused::Refused(t) if t.contains(&bad_key) && !t.contains("secret-text")),
        "{e:?}"
    );
    assert_eq!(s.get_usage(&good, 0).unwrap().requests, 0, "cell 2 applied");
    let _: () = r.del(&bad_key).unwrap();
    s.add_usage_batch(id, &cells).expect("the retry applies");
    assert_eq!(s.get_usage(&good, 0).unwrap().requests, 2);
    assert_eq!(s.get_usage(&bad, 0).unwrap().requests, 2);
}

/// A non-integer field refuses the batch the same way, and names the field, not its value.
#[test]
fn a_non_integer_counter_field_refuses_the_batch_without_echoing_it() {
    let Some(s) = live_store() else { return };
    let (bad, good) = (fresh("field-bad"), fresh("field-good"));
    let mut r = raw_conn();
    let _: () = r
        .hset(format!("busbar:usage:{bad}:0"), "requests", "secret-text")
        .unwrap();
    let d = UsageDelta {
        requests: 1,
        billable_requests: 0,
        models: Vec::new(),
    };
    let e = s
        .add_usage_batch(
            op(44),
            &[(bad.as_str(), 0, d.clone()), (good.as_str(), 0, d)],
        )
        .expect_err("refused");
    assert!(
        matches!(&e, OpRefused::Refused(t) if t.contains("requests") && !t.contains("secret-text")),
        "{e:?}"
    );
    assert_eq!(s.get_usage(&good, 0).unwrap().requests, 0);
}

#[test]
fn a_metering_batch_with_a_wrong_typed_row_applies_nothing() {
    let Some(s) = live_store() else { return };
    let (bad, good) = (super::unique_bucket(45), super::unique_bucket(46));
    let mut r = raw_conn();
    let probe = metering_delta(bad, 1);
    s.add_metering_batch(op(47), std::slice::from_ref(&probe))
        .expect("seed");
    let rows: Vec<String> = r.smembers(format!("busbar:metering:{bad}")).unwrap();
    let _: () = r.del(&rows[0]).unwrap();
    let _: () = r.set(&rows[0], "not a hash").unwrap();
    let id = op(48);
    let batch = [metering_delta(good, 1), probe];
    let e = s.add_metering_batch(id, &batch).expect_err("refused");
    assert!(matches!(e, OpRefused::Refused(_)), "{e:?}");
    assert!(s.list_metering(good).unwrap().is_empty(), "applied");
    let _: () = r.del(&rows[0]).unwrap();
    s.add_metering_batch(id, &batch).expect("the retry applies");
    assert_eq!(s.list_metering(good).unwrap().len(), 1);
}

/// The v9 step keeps an op record whose body is a kept slot's digest (32 bytes, or 64 lowercase hex):
/// a node upgrading concurrently with live writers must not erase their dedupe records.
#[test]
fn the_v9_upgrade_keeps_digest_bodied_op_records() {
    let Some(mut iso) = Iso::new(9) else { return };
    let mut c = iso.raw();
    let mut raw32 = [0xABu8; 32];
    raw32[3] = b':';
    let hex64 = "0123456789abcdef".repeat(4);
    let _: () = c.hset("busbar:op:digest32", "b", &raw32[..]).unwrap();
    let _: () = c.hset("busbar:op:digest64", "b", &hex64).unwrap();
    let _: () = c.hset("busbar:op:deadtext", "b", "reserve:0:[]").unwrap();
    let _: () = c.set("busbar:schema", 8).unwrap();
    drop(c);

    iso.restart();

    let mut c = iso.raw();
    for k in ["busbar:op:digest32", "busbar:op:digest64"] {
        let there: bool = c.exists(k).unwrap();
        assert!(there, "{k} (a kept slot's digest record) was deleted");
    }
    let there: bool = c.exists("busbar:op:deadtext").unwrap();
    assert!(!there, "a dead slot's textual record survived");
}

/// A terminal-only purge over more records than one script call handles: every terminal row goes,
/// none of the active rows older than it (which fill the first batches) is touched, and the count is
/// the whole sweep's.
#[test]
fn a_purge_larger_than_one_batch_counts_and_removes_exactly_the_terminal_rows() {
    let Some(s) = live_store() else { return };
    let kind = fresh("purge-batches");
    let rec = |i: u64, ts: u64, disposition| PlaneRecord {
        kind: kind.clone(),
        id: format!("r{i}"),
        parent: None,
        seq: 0,
        ts,
        disposition,
        body: b"b".to_vec(),
    };
    for i in 0..1200 {
        s.upsert_plane_record(rec(i, 1, PlaneDisposition::Active).view())
            .unwrap();
    }
    for i in 1200..2400 {
        s.upsert_plane_record(rec(i, 2, PlaneDisposition::Terminal).view())
            .unwrap();
    }
    let n = s
        .purge_plane_records(&kind, 10, busbar_contract::records::Retention::TerminalOnly)
        .unwrap();
    assert_eq!(n, 1200);
    let n = s
        .purge_plane_records(&kind, 10, busbar_contract::records::Retention::Age)
        .unwrap();
    assert_eq!(n, 1200);
    let n = s
        .purge_plane_records(&kind, 10, busbar_contract::records::Retention::Age)
        .unwrap();
    assert_eq!(n, 0);
}

/// The v6 -> v7 copy never deletes a v6 task-event chain whose position holds a DIFFERENT record
/// already (a fork): the v6 event is the only copy of that evidence, so it stays for an operator.
#[test]
fn the_v6_copy_keeps_an_event_chain_whose_position_forked() {
    use crate::legacy::TASK_EVENTS_PREFIX;
    let Some(mut iso) = Iso::new(6) else { return };
    let id = fresh("t_fork");
    let v6 = super::sample_event(&id, 1, "task.submitted", "", "x1");
    iso.s()
        .append_plane_record_op(
            op(60),
            PlaneRecord {
                kind: "task_event".into(),
                id: id.clone(),
                parent: Some(id.clone()),
                seq: 1,
                ts: 9,
                disposition: PlaneDisposition::Active,
                body: b"a different v7 record".to_vec(),
            }
            .view(),
        )
        .unwrap();
    let mut c = iso.raw();
    let key = format!("{TASK_EVENTS_PREFIX}{id}");
    let _: () = c
        .zadd(&key, serde_json::to_string(&v6).unwrap(), 1)
        .unwrap();
    let _: () = c.set("busbar:schema", 6).unwrap();
    drop(c);

    iso.restart();

    let mut c = iso.raw();
    let there: bool = c.exists(&key).unwrap();
    assert!(there, "the v6 chain was deleted though its copy forked");
    let marker: i64 = c.get("busbar:schema").unwrap();
    assert_eq!(marker, 9, "the upgrade still completes");
}

/// A page is read at ONE instant: a strike landing while the scan is in flight cannot shorten it.
/// The scan is held right after its key range is read; the row is struck; the scan is released.
#[test]
fn a_record_scan_page_is_not_shortened_by_a_concurrent_strike() {
    let Some(direct) = live_store() else { return };
    let url = std::env::var("VALKEY_URL").unwrap();
    let schema = fresh("scan-atomic");
    for k in [b"a", b"b", b"c"] {
        direct.record_put(&schema, k, b"v").unwrap();
    }
    // Warm the server's script cache, so the held scan sends no `SCRIPT LOAD`.
    assert_eq!(direct.record_scan(&schema, b"", 10).unwrap().len(), 3);
    let gate = super::interleave::gate(&url, false, |c| {
        let has = |t: &[u8]| super::interleave::contains(c, t);
        (has(b"ZRANGEBYLEX") || has(b"EVALSHA")) && !has(b"SCRIPT")
    });
    let scanner = ValkeyStore::connect(&gate.url).unwrap();
    let name = schema.clone();
    let page = std::thread::spawn(move || scanner.record_scan(&name, b"", 10));
    gate.held
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the scan is in flight");
    direct.record_put(&schema, b"b", b"").unwrap();
    gate.release.send(()).unwrap();
    let page = page.join().unwrap().unwrap();
    assert_eq!(page.len(), 3, "the page was cut by a strike: {page:?}");
}

/// The contract upserts by `(kind, id)` and reads at seq 0: a second upsert of an id with another
/// `seq` replaces the first, never stands beside it.
#[test]
fn an_upsert_replaces_by_id_whatever_its_seq() {
    let Some(s) = live_store() else { return };
    let kind = fresh("upsert-seq");
    let rec = |seq: u64, body: &[u8]| PlaneRecord {
        kind: kind.clone(),
        id: "a".into(),
        parent: None,
        seq,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    s.upsert_plane_record(rec(3, b"three").view()).unwrap();
    s.upsert_plane_record(rec(4, b"four").view()).unwrap();
    assert_eq!(
        s.list_plane_records(&kind, &PlaneSelector::All).unwrap(),
        vec![b"four".to_vec()]
    );
    assert_eq!(
        s.get_plane_record(&kind, "a").unwrap(),
        Some(b"four".to_vec())
    );
}

/// A reply that does not fit is refused by naming where and what was expected, never by echoing the
/// stored value into the error.
#[test]
fn a_malformed_stored_value_is_not_echoed_into_the_error() {
    let Some(s) = live_store() else { return };
    let bucket = fresh("echo");
    let mut r = raw_conn();
    let _: () = r
        .hset(
            format!("busbar:usage:{bucket}:0"),
            "requests",
            "secret-text",
        )
        .unwrap();
    let e = s
        .get_usage(&bucket, 0)
        .expect_err("not an integer")
        .to_string();
    // Debug-printed bytes are digits, so the text check alone would miss the echo.
    let bytes = format!("{:?}", b"secret-text".to_vec());
    assert!(!e.contains("secret-text") && !e.contains(&bytes), "{e}");
    assert!(!e.contains("response was"), "{e}");
}

/// A fork-refused append records nothing under its op id: the same op id retried with a record that
/// does not fork applies, instead of conflicting with a body the refusal wrongly recorded.
#[test]
fn a_fork_refused_append_records_nothing_under_its_op_id() {
    let Some(s) = live_store() else { return };
    let parent = fresh("fork-op");
    let rec = |seq: u64, body: &[u8]| PlaneRecord {
        kind: "slots_test".into(),
        id: parent.clone(),
        parent: Some(parent.clone()),
        seq,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    s.append_plane_record_op(op(70), rec(1, b"one").view())
        .expect("first");
    let id = op(71);
    assert!(matches!(
        s.append_plane_record_op(id, rec(1, b"forked").view()),
        Err(OpRefused::Failed(_))
    ));
    s.append_plane_record_op(id, rec(2, b"two").view())
        .expect("the refusal recorded nothing, so the op id is still free");
}
