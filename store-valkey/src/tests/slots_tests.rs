// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live Valkey: the durable `op_id` dedupe (S1-S4),

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
    let e = Door::open_with_secrets(b"", &[], None).expect_err("no url");
    assert!(e.contains("`url` is required"), "{e}");
    let e = Door::open_with_secrets(b"{}", &[], None).expect_err("no url");
    assert!(e.contains("`url` is required"), "{e}");
    let e = Door::open_with_secrets(b"{ not json", &[], None).expect_err("bad json");
    assert!(e.contains("invalid valkey plugin config"), "{e}");
    let e = Door::open_with_secrets(br#"{"url":"not-a-valkey-url"}"#, &[], None)
        .expect_err("a url the driver refuses");
    assert!(e.contains("invalid valkey plugin config: url: "), "{e}");
    assert!(!e.contains("failed to connect"), "{e}");
}

/// S1/S2/S3/S4: a replay applies nothing and answers the original, a different body is a conflict
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
struct Iso {
    url: String,
    store: Option<ValkeyStore>,
    _database: super::database::Database,
}

impl Iso {
    fn new(db: u32) -> Option<Self> {
        live_store()?;
        super::assert_private_db(db);
        let url = super::url_for_db(db);
        let database = super::database::Database::take(&url);
        let store = Some(ValkeyStore::connect(&url).expect("connect"));
        Some(Iso {
            url,
            store,
            _database: database,
        })
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
    }
}

use redis::Commands as _;

/// S2 for the batch slots: the same `op_id` with a DIFFERENT body answers `Conflict` and
#[test]
fn the_same_op_id_with_a_different_body_conflicts_on_every_batch_slot() {
    let Some(s) = live_store() else { return };

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

/// An empty put removes the stored row.
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

/// A fresh op id that successfully replays an existing position is spent durably too.
#[test]
fn an_identical_append_under_a_fresh_op_id_records_the_success() {
    let Some(s) = live_store() else { return };
    let kind = fresh("append-replay-op");
    let rec = |seq, body: &[u8]| PlaneRecord {
        kind: kind.clone(),
        id: "row".into(),
        parent: Some("parent".into()),
        seq,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    let mut raw = raw_conn();
    let prefix = format!("busbar:plane:{}:", crate::hex(kind.as_bytes()));
    let keys = ["rec", "body", "byts", "idx:706172656e74", "pcount"]
        .map(|suffix| format!("{prefix}{suffix}"));
    s.append_plane_record_op(op(130), rec(1, b"one").view())
        .unwrap();
    let before = plane_key_snapshot(&mut raw, &keys);
    let replay = op(131);
    s.append_plane_record_op(replay, rec(1, b"one").view())
        .unwrap();
    assert_eq!(
        plane_key_snapshot(&mut raw, &keys),
        before,
        "replay changed the record"
    );
    let op_key = format!("busbar:op:{}", crate::hex(&replay.0));
    let recorded: Option<Vec<u8>> = raw.hget(&op_key, "b").unwrap();
    assert!(
        recorded.is_some(),
        "successful replay did not record its op id"
    );
    let ttl: i64 = raw.ttl(&op_key).unwrap();
    assert!(ttl > 0 && ttl as u64 <= busbar_contract::abi::store::OP_ID_RETENTION_SECS);
    let again = ValkeyStore::connect(&std::env::var("VALKEY_URL").unwrap()).unwrap();
    again
        .append_plane_record_op(replay, rec(1, b"one").view())
        .unwrap();
    for changed in [rec(2, b"two"), rec(1, b"changed")] {
        assert_eq!(
            again.append_plane_record_op(replay, changed.view()),
            Err(OpRefused::Conflict)
        );
    }
    assert_eq!(
        plane_key_snapshot(&mut raw, &keys),
        before,
        "conflict applied another row"
    );
    assert_eq!(
        again
            .list_plane_records(&kind, &PlaneSelector::All)
            .unwrap(),
        vec![b"one".to_vec()]
    );
    s.delete_plane_record(&kind, "parent").unwrap();
}

/// Inspect exact backend state independently, including malformed keys that public reads refuse.
fn plane_key_snapshot(raw: &mut redis::Connection, keys: &[String]) -> Vec<Option<Vec<u8>>> {
    keys.iter()
        .map(|key| redis::cmd("DUMP").arg(key).query(raw).unwrap())
        .collect()
}

/// A script error must precede every mutation: repairing the bad target lets the same op retry.
#[test]
fn a_plane_append_validates_all_targets_before_writing_anything() {
    let Some(s) = live_store() else { return };
    let mut raw = raw_conn();
    for fault in [
        "rec",
        "body",
        "byts",
        "idx:706172656e74",
        "pcount",
        "op",
        "counter",
        "overflow",
    ] {
        let kind = fresh("append-atomic");
        let prefix = format!("busbar:plane:{}:", crate::hex(kind.as_bytes()));
        let id = op(132);
        let op_key = format!("busbar:op:{}", crate::hex(&id.0));
        let mut keys: Vec<_> = ["rec", "body", "byts", "idx:706172656e74", "pcount"]
            .map(|suffix| format!("{prefix}{suffix}"))
            .into();
        keys.push(op_key.clone());
        let bad = match fault {
            "op" => op_key.clone(),
            "counter" | "overflow" => format!("{prefix}pcount"),
            _ => format!("{prefix}{fault}"),
        };
        if matches!(fault, "counter" | "overflow") {
            let value = if fault == "counter" {
                "not-an-integer"
            } else {
                "9223372036854775807"
            };
            let _: () = raw.hset(&bad, "parent", value).unwrap();
        } else {
            let _: () = raw.set(&bad, "wrong-type").unwrap();
        }
        let record = PlaneRecord {
            kind: kind.clone(),
            id: "row".into(),
            parent: Some("parent".into()),
            seq: 1,
            ts: 1,
            disposition: PlaneDisposition::Active,
            body: b"one".to_vec(),
        };
        let before = plane_key_snapshot(&mut raw, &keys);
        assert!(
            matches!(
                s.append_plane_record_op(id, record.view()),
                Err(OpRefused::Failed(_))
            ),
            "{fault}"
        );
        assert_eq!(
            plane_key_snapshot(&mut raw, &keys),
            before,
            "partial append after {fault}"
        );
        let _: () = raw.del(&bad).unwrap();
        s.append_plane_record_op(id, record.view())
            .expect("repair permits the original op");
        assert_eq!(
            s.list_plane_records(&kind, &PlaneSelector::Parent("parent".into()))
                .unwrap(),
            vec![b"one".to_vec()]
        );
        let count: i64 = raw.hget(format!("{prefix}pcount"), "parent").unwrap();
        assert_eq!(count, 1, "{fault}");
        let retained: u64 = raw.zcard(format!("{prefix}byts")).unwrap();
        assert_eq!(retained, 1, "missing retention index after {fault}");
        assert!(raw.hexists::<_, _, bool>(&op_key, "b").unwrap());
        s.delete_plane_record(&kind, "parent").unwrap();
    }
}

/// Upserts share the writer: validate old links as well as the new parent's late index/counter.
#[test]
fn a_plane_replacement_validates_old_and_new_links_before_unlinking() {
    let Some(s) = live_store() else { return };
    let mut raw = raw_conn();
    for fault in [
        "old-index",
        "new-index",
        "old-counter",
        "new-counter",
        "underflow",
        "sidecar",
    ] {
        let kind = fresh("upsert-atomic");
        let prefix = format!("busbar:plane:{}:", crate::hex(kind.as_bytes()));
        let keys = [
            "rec",
            "body",
            "byts",
            "idx:726f77",
            "pcount",
            "idx:6f6c64",
            "idx:6e6577",
        ]
        .map(|suffix| format!("{prefix}{suffix}"));
        let record = |parent: &str, body: &[u8]| PlaneRecord {
            kind: kind.clone(),
            id: "row".into(),
            parent: Some(parent.into()),
            seq: 0,
            ts: 1,
            disposition: PlaneDisposition::Active,
            body: body.to_vec(),
        };
        s.upsert_plane_record(record("old", b"before").view())
            .unwrap();
        let sidecar: Vec<u8> = raw.hget(&keys[0], "0:row").unwrap();
        match fault {
            "old-index" | "new-index" => {
                let key = &keys[if fault == "old-index" { 5 } else { 6 }];
                let _: () = raw.del(key).unwrap();
                let _: () = raw.set(key, "wrong-type").unwrap();
            }
            "sidecar" => {
                let _: () = raw.hset(&keys[0], "0:row", "1a{broken").unwrap();
            }
            _ => {
                let parent = if fault == "new-counter" { "new" } else { "old" };
                let value = if fault == "underflow" {
                    "-9223372036854775808"
                } else {
                    "not-an-integer"
                };
                let _: () = raw.hset(&keys[4], parent, value).unwrap();
            }
        }
        let before = plane_key_snapshot(&mut raw, &keys);
        assert!(
            s.upsert_plane_record(record("new", b"after").view())
                .is_err(),
            "{fault}"
        );
        assert_eq!(
            plane_key_snapshot(&mut raw, &keys),
            before,
            "partial replacement after {fault}"
        );
        match fault {
            "old-index" | "new-index" => {
                let _: () = raw
                    .del(&keys[if fault == "old-index" { 5 } else { 6 }])
                    .unwrap();
                let _: () = raw.zadd(&keys[5], "0:row", 0).unwrap();
            }
            "sidecar" => {
                let _: () = raw.hset(&keys[0], "0:row", &sidecar).unwrap();
            }
            "new-counter" => {
                let _: () = raw.hdel(&keys[4], "new").unwrap();
            }
            _ => {
                let _: () = raw.hset(&keys[4], "old", 1).unwrap();
            }
        }
        s.upsert_plane_record(record("new", b"after").view())
            .expect("repair permits replacement");
        assert_eq!(
            s.get_plane_record(&kind, "row").unwrap(),
            Some(b"after".to_vec())
        );
        assert!(s
            .list_plane_records(&kind, &PlaneSelector::Parent("old".into()))
            .unwrap()
            .is_empty());
        assert_eq!(
            s.list_plane_records(&kind, &PlaneSelector::Parent("new".into()))
                .unwrap(),
            vec![b"after".to_vec()]
        );
        assert_eq!(
            s.list_plane_record_parents(&kind).unwrap(),
            vec!["new".to_string()]
        );
        s.delete_plane_record(&kind, "row").unwrap();
    }
}

/// A body an older build recorded (`<slot>:<values {:?}>`) still dedupes after the upgrade: the
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

/// `SCRIPT FLUSH` empties the script cache of the whole server, so it must not land under a gated
/// test that warmed the cache first and holds a script call across the gap.
fn flush_scripts() {
    let _alone = super::interleave::SCRIPT_CACHE
        .write()
        .unwrap_or_else(|e| e.into_inner());
    let mut raw = redis::Client::open(std::env::var("VALKEY_URL").expect("live_store read it"))
        .and_then(|c| c.get_connection())
        .expect("an independent client");
    redis::cmd("SCRIPT")
        .arg("FLUSH")
        .query::<()>(&mut raw)
        .expect("SCRIPT FLUSH");
}

/// A live gate keeps the script cache: the flush waits until the gated test is done.
#[test]
fn a_script_flush_waits_for_a_live_gate() {
    let Some(_) = live_store() else { return };
    let url = std::env::var("VALKEY_URL").unwrap();
    let gate = super::interleave::gate(&url, false, |_| false);
    let (done, flushed) = std::sync::mpsc::channel();
    let flusher = std::thread::spawn(move || {
        flush_scripts();
        done.send(()).unwrap();
    });
    assert!(
        flushed
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "SCRIPT FLUSH ran while a gated test was live"
    );
    drop(gate);
    flushed
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the flush runs once the gate is gone");
    flusher.join().unwrap();
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
    // The flush lands on the proxy's thread right before the first `EVALSHA` chunk is forwarded,
    // so the cache is cold for exactly that call (a parallel test cannot re-warm it in between),
    // and the `EVAL` fallback is counted on the wire.
    let url = std::env::var("VALKEY_URL").unwrap();
    let flushed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let evals = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (f, e) = (flushed.clone(), evals.clone());
    let proxied = super::interleave::tamper(
        &url,
        move |c| {
            let has = |t: &[u8]| super::interleave::contains(c, t);
            if has(b"$4\r\nEVAL\r\n") {
                e.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            has(b"EVALSHA") && !f.swap(true, std::sync::atomic::Ordering::SeqCst)
        },
        flush_scripts,
    );
    let via =
        <super::LoadedStore as Connect>::connect(&proxied.url).expect("connect through the proxy");
    let id = op(95);
    via.add_usage_batch(id, &cells)
        .expect("applies after the flush");
    assert!(flushed.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        evals.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the cold cache must send exactly one EVAL fallback"
    );
    via.add_usage_batch(id, &cells).expect("replays");
    assert_eq!(
        evals.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the replay is a plain EVALSHA"
    );
    assert_eq!(s.get_usage(&bucket, 0).unwrap().requests, 2);
}

/// The v8 -> v9 step: every key the deleted slots kept (the money keys, the journal, the sessions)
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
    assert_eq!(marker, crate::SCHEMA_VERSION);

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

/// Usage retains the unsigned range: adding above the old signed boundary preserves the count.
#[test]
fn a_usage_counter_crosses_i64_max_without_narrowing() {
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
        .expect("unsigned usage addition succeeds");
    let got: String = r.hget(&key, "requests").unwrap();
    assert_eq!(got, (i64::MAX as u64 + 1).to_string());
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

    let cells = [(good.as_str(), 0, d.clone()), (bad.as_str(), 0, d)];
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
            &[(good.as_str(), 0, d.clone()), (bad.as_str(), 0, d)],
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
#[test]
fn a_purge_larger_than_one_batch_counts_and_removes_exactly_the_terminal_rows() {
    let Some(s) = live_store() else { return };
    let kind = fresh("purge-batches");
    let cutoff = (1u64 << 53) + 1;
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
        s.upsert_plane_record(rec(i, cutoff, PlaneDisposition::Active).view())
            .unwrap();
    }
    for i in 1200..2400 {
        s.upsert_plane_record(rec(i, cutoff - 1, PlaneDisposition::Terminal).view())
            .unwrap();
    }
    // Rows stamped EXACTLY at `before` (10) are not strictly older: the purge bound is exclusive,
    // so neither retention mode may touch them.
    s.upsert_plane_record(rec(2400, 10, PlaneDisposition::Terminal).view())
        .unwrap();
    s.upsert_plane_record(rec(2401, 10, PlaneDisposition::Active).view())
        .unwrap();
    let n = s
        .purge_plane_records(
            &kind,
            cutoff,
            busbar_contract::records::Retention::TerminalOnly,
        )
        .unwrap();
    assert_eq!(n, 1200);
    let n = s
        .purge_plane_records(&kind, cutoff + 1, busbar_contract::records::Retention::Age)
        .unwrap();
    assert_eq!(n, 1200);
    let n = s
        .purge_plane_records(&kind, cutoff + 1, busbar_contract::records::Retention::Age)
        .unwrap();
    assert_eq!(n, 0, "rows at ts == before must survive the purge");
}

#[test]
fn plane_retention_uses_exact_timestamps_and_cleans_every_index() {
    use busbar_contract::records::Retention;

    let Some(s) = live_store() else { return };
    let mut raw = raw_conn();
    let large = 1u64 << 53;
    let max = i64::MAX as u64;
    let timestamps = [
        0,
        large - 1,
        large,
        large + 1,
        large + 2,
        large + 3,
        max - 1,
        max,
        max + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    for terminal_only in [false, true] {
        for before in [
            0,
            large,
            large + 1,
            large + 3,
            large + 4,
            max,
            max + 1,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let kind = fresh("purge-exact-ts");
            let prefix = format!("busbar:plane:{}:", crate::hex(kind.as_bytes()));
            let records: Vec<_> = timestamps
                .iter()
                .flat_map(|&ts| {
                    [PlaneDisposition::Active, PlaneDisposition::Terminal]
                        .into_iter()
                        .map(move |disposition| (ts, disposition))
                })
                .enumerate()
                .map(|(i, (ts, disposition))| PlaneRecord {
                    kind: kind.clone(),
                    id: format!("r{i}"),
                    parent: Some(format!("p{i}")),
                    seq: large + i as u64,
                    ts,
                    disposition,
                    body: format!("body-{i}").into_bytes(),
                })
                .collect();
            for record in records.iter().rev() {
                s.append_plane_record_op(op(80), record.view()).unwrap();
            }
            let should_remove = |record: &PlaneRecord| {
                record.ts < before
                    && (!terminal_only || record.disposition == PlaneDisposition::Terminal)
            };
            let expected: Vec<_> = records
                .iter()
                .filter(|r| !should_remove(r))
                .map(|r| r.body.clone())
                .collect();
            let gone = if terminal_only {
                s.purge_plane_records(&kind, before, Retention::TerminalOnly)
            } else {
                s.purge_plane_records_before(&kind, before)
            }
            .unwrap();
            assert_eq!(
                gone as usize,
                records.len() - expected.len(),
                "{before}, {terminal_only}"
            );
            assert_eq!(
                s.list_plane_records(&kind, &PlaneSelector::All).unwrap(),
                expected
            );
            let mut parents: Vec<_> = records
                .iter()
                .filter(|r| !should_remove(r))
                .map(|r| r.parent.clone().unwrap())
                .collect();
            parents.sort();
            assert_eq!(s.list_plane_record_parents(&kind).unwrap(), parents);
            for record in &records {
                let parent = record.parent.as_deref().unwrap();
                let kept = !should_remove(record);
                let rows = s
                    .list_plane_records(&kind, &PlaneSelector::Parent(parent.into()))
                    .unwrap();
                assert_eq!(
                    rows,
                    if kept {
                        vec![record.body.clone()]
                    } else {
                        Vec::new()
                    }
                );
                let field = format!("{}:{parent}", record.seq);
                for suffix in ["rec", "body"] {
                    let present: bool = raw.hexists(format!("{prefix}{suffix}"), &field).unwrap();
                    assert_eq!(present, kept, "{suffix}: {field}");
                }
                let score: Option<f64> = raw.zscore(format!("{prefix}byts"), &field).unwrap();
                assert_eq!(score.is_some(), kept, "timestamp index: {field}");
                let index_len: usize = raw
                    .zcard(format!("{prefix}idx:{}", crate::hex(parent.as_bytes())))
                    .unwrap();
                assert_eq!(index_len, usize::from(kept), "parent index: {field}");
            }
            assert_eq!(
                s.purge_plane_records(
                    &kind,
                    before,
                    if terminal_only {
                        Retention::TerminalOnly
                    } else {
                        Retention::Age
                    },
                )
                .unwrap(),
                0,
                "repeated cutoff is a no-op"
            );
            for record in &records {
                s.delete_plane_record(&kind, record.parent.as_deref().unwrap())
                    .unwrap();
            }
            let keys: Vec<String> = raw.keys(format!("{prefix}*")).unwrap();
            assert!(
                keys.is_empty(),
                "plane keys survived full cleanup: {keys:?}"
            );
        }
    }
}

/// The v6 -> v7 copy never deletes a v6 task-event chain whose position holds a DIFFERENT record
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
    assert_eq!(marker, crate::SCHEMA_VERSION, "the upgrade still completes");
}

/// A page is read at ONE instant: a strike landing while the scan is in flight cannot shorten it.
#[test]
fn a_record_scan_page_is_not_shortened_by_a_concurrent_strike() {
    let Some(direct) = live_store() else { return };
    let url = std::env::var("VALKEY_URL").unwrap();
    let schema = fresh("scan-atomic");
    for k in [b"a", b"b", b"c"] {
        direct.record_put(&schema, k, b"v").unwrap();
    }

    assert_eq!(direct.record_scan(&schema, b"", 10).unwrap().len(), 3);
    let gate = super::interleave::gate(&url, false, |c| {
        let has = |t: &[u8]| super::interleave::contains(c, t);
        (has(b"ZRANGEBYLEX") || has(b"EVALSHA")) && !has(b"SCRIPT")
    });
    let scanner = ValkeyStore::connect(&gate.url).unwrap();
    let name = schema.clone();
    let page = gate.spawn(move || scanner.record_scan(&name, b"", 10));
    gate.held
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the scan is in flight");
    direct.record_put(&schema, b"b", b"").unwrap();
    gate.release.send(()).unwrap();
    let page = page.join().unwrap().unwrap();
    assert_eq!(page.len(), 3, "the page was cut by a strike: {page:?}");
}

/// The contract upserts by `(kind, id)` and reads at seq 0: a second upsert of an id with another
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

    let bytes = format!("{:?}", b"secret-text".to_vec());
    assert!(!e.contains("secret-text") && !e.contains(&bytes), "{e}");
    assert!(!e.contains("response was"), "{e}");
}

/// A fork-refused append records nothing under its op id: the same op id retried with a record that
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

#[path = "conditional_records.rs"]
mod conditional_records;
#[path = "usage_correction.rs"]
mod usage_correction;

#[test]
fn a_missing_indexed_record_value_refuses_instead_of_falsely_ending_a_scan() {
    use super::Raw;
    use redis::Commands;
    let Some(store) = live_store() else { return };
    let schema = fresh("orphan_scan");
    store.record_put(&schema, b"a", b"first").unwrap();
    store.record_put(&schema, b"b", b"second").unwrap();
    let values = format!("busbar:records:{}:v", crate::hex(schema.as_bytes()));
    store
        .with_conn(|raw| raw.hdel::<_, _, ()>(&values, b"a"))
        .unwrap();
    let error = store
        .record_scan(&schema, b"", 1)
        .expect_err("a missing value must not masquerade as a successful end of iteration");
    assert!(
        error.contains("record_scan") && error.contains("missing"),
        "{error}"
    );
    assert_eq!(
        store.record_get(&schema, b"b").unwrap().unwrap().as_slice(),
        b"second"
    );
    store.record_put(&schema, b"a", b"repaired").unwrap();
    let page = store.record_scan(&schema, b"", 2).unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].0, b"a");
    assert_eq!(page[0].1.as_slice(), b"repaired");
    assert_eq!(page[1].0, b"b");
}

#[test]
fn full_width_upsert_timestamps_survive_reopen_and_exact_retention() {
    let Some(store) = live_store() else { return };
    let kind = fresh("upsert-full-width-ts");
    let edge = i64::MAX as u64;
    let records: Vec<_> = [edge, edge + 1, edge + 2, u64::MAX]
        .into_iter()
        .enumerate()
        .map(|(i, ts)| PlaneRecord {
            kind: kind.clone(),
            id: format!("r{i}"),
            parent: None,
            seq: 0,
            ts,
            disposition: PlaneDisposition::Terminal,
            body: format!("body-{i}").into_bytes(),
        })
        .collect();
    for record in &records {
        store.upsert_plane_record(record.view()).unwrap();
    }
    drop(store);
    let store = ValkeyStore::connect(&std::env::var("VALKEY_URL").unwrap()).unwrap();
    assert_eq!(
        store.purge_plane_records_before(&kind, edge + 2).unwrap(),
        2
    );
    for (i, record) in records.iter().enumerate() {
        assert_eq!(
            store.get_plane_record(&kind, &record.id).unwrap(),
            (i >= 2).then(|| record.body.clone())
        );
    }
    assert_eq!(
        store.purge_plane_records_before(&kind, u64::MAX).unwrap(),
        1
    );
    assert_eq!(
        store.purge_plane_records_before(&kind, u64::MAX).unwrap(),
        0
    );
    assert_eq!(
        store.get_plane_record(&kind, "r3").unwrap(),
        Some(b"body-3".to_vec())
    );
    store.delete_plane_record(&kind, "r3").unwrap();
}

#[test]
fn historical_metering_attribution_survives_batch_replay_and_reopen() {
    use busbar_contract::records::MeteringDelta;
    let Some(mut iso) = Iso::new(12) else { return };
    let bucket = u64::MAX;

    let make = |group: &str, version: &str, n| MeteringDelta {
        key_id: "history|key%".into(),
        bucket,
        model: "m|%".into(),
        provider: "p".into(),
        tokens_input: n,
        tokens_output: n + 1,
        tokens_cache_read: n + 2,
        tokens_cache_write: n + 3,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: group.into(),
        pricing_version: version.into(),
        priced_from_ms: 17,
        usage_units: [("tool_calls".into(), n + 4)].into_iter().collect(),
    };
    let cells = [
        make("", "", 1),
        make("a|%", "v", 10),
        make("a", "|%v", 100),
        make("a|%", "V", 1000),
        make("a|%", "v", 10),
    ];

    let id = op(181);
    iso.s().add_metering_batch(id, &cells).unwrap();
    iso.s().add_metering_batch(id, &cells).unwrap();
    let mut changed = cells.clone();
    changed[0].pricing_version = "changed".into();
    assert_eq!(
        iso.s().add_metering_batch(id, &changed),
        Err(OpRefused::Conflict)
    );
    iso.restart();
    let s = iso.s();

    let mut rows = s.list_metering(bucket).unwrap();
    rows.sort_by(|a, b| {
        (&a.key_group_at_use, &a.pricing_version).cmp(&(&b.key_group_at_use, &b.pricing_version))
    });
    assert_eq!(
        rows.len(),
        4,
        "each historical attribution owns its counts: {rows:?}"
    );
    for (group, version, n, repeats) in [
        ("", "", 1, 1),
        ("a", "|%v", 100, 1),
        ("a|%", "V", 1000, 1),
        ("a|%", "v", 10, 2),
    ] {
        let r = rows
            .iter()
            .find(|r| r.key_group_at_use == group && r.pricing_version == version)
            .unwrap();
        assert_eq!(
            (
                r.tokens_input,
                r.tokens_output,
                r.tokens_cache_read,
                r.tokens_cache_write
            ),
            (
                n * repeats,
                (n + 1) * repeats,
                (n + 2) * repeats,
                (n + 3) * repeats
            )
        );
        assert_eq!((r.requests, r.billable_requests), (repeats, repeats));
        assert_eq!(r.usage_units.get("tool_calls"), Some(&((n + 4) * repeats)));
    }
}

#[test]
fn v10_metering_migration_preserves_raw_rows_and_replays() {
    let Some(mut iso) = Iso::new(12) else { return };
    let bucket = u64::MAX;
    let mut r = iso.raw();
    let set = format!("busbar:metering:{bucket}");
    let old = format!("{set}:history|m|p|9007199254740993");
    let unknown = format!("{set}:unknown|m|p");
    let _: () = redis::cmd("HSET")
        .arg(&old)
        .arg(&[
            "key_id",
            "history",
            "model",
            "m",
            "provider",
            "p",
            "priced_from_ms",
            "9007199254740993",
            "key_group_at_use",
            "old|group",
            "pricing_version",
            "old%version",
            "tokens_input",
            "7",
            "u:tool_calls",
            "11",
            "opaque",
            "kept",
        ])
        .query(&mut r)
        .unwrap();
    let _: () = redis::cmd("HSET")
        .arg(&unknown)
        .arg(&[
            "key_id",
            "unknown",
            "model",
            "m",
            "provider",
            "p",
            "tokens_input",
            "3",
            "u:tool_calls",
            "5",
        ])
        .query(&mut r)
        .unwrap();
    let _: () = r.sadd(&set, &[&old, &unknown]).unwrap();
    let _: () = r.set("busbar:schema", 10).unwrap();
    iso.restart();
    iso.restart();
    let rows = iso.s().list_metering(bucket).unwrap();
    assert_eq!(rows.len(), 2);
    let oldrow = rows.iter().find(|r| r.key_id == "history").unwrap();
    assert_eq!(
        (&*oldrow.key_group_at_use, &*oldrow.pricing_version),
        ("old|group", "old%version")
    );
    assert_eq!(
        (oldrow.tokens_input, oldrow.priced_from_ms),
        (7, 9007199254740993)
    );
    assert_eq!(oldrow.usage_units.get("tool_calls"), Some(&11));
    let unknownrow = rows.iter().find(|r| r.key_id == "unknown").unwrap();
    assert_eq!(
        (&*unknownrow.key_group_at_use, &*unknownrow.pricing_version),
        ("", "")
    );
    assert_eq!(unknownrow.usage_units.get("tool_calls"), Some(&5));
    let mut delta = metering_delta(bucket, 2);
    delta.key_id = "history".into();
    delta.key_group_at_use = "new".into();
    delta.pricing_version = "old%version".into();
    delta.priced_from_ms = 9007199254740993;
    delta.usage_units.insert("tool_calls".into(), 13);
    let id = op(182);
    iso.s().add_metering_batch(id, &[delta.clone()]).unwrap();
    iso.s().add_metering_batch(id, &[delta]).unwrap();
    let rows = iso.s().list_metering(bucket).unwrap();
    assert_eq!(rows.len(), 3);
    let oldrow = rows
        .iter()
        .find(|r| r.key_group_at_use == "old|group")
        .unwrap();
    assert_eq!(oldrow.tokens_input, 7);
    assert_eq!(oldrow.usage_units.get("tool_calls"), Some(&11));
    let names: Vec<String> = r.smembers(&set).unwrap();
    let mut opaque = 0;
    for name in names {
        let value: Option<String> = r.hget(name, "opaque").unwrap();
        if value.as_deref() == Some("kept") {
            opaque += 1;
        }
    }
    assert_eq!(
        opaque, 1,
        "unknown hash metadata survives the migration unchanged"
    );
}

#[test]
fn v10_metering_destination_collision_refuses_without_overwriting_evidence() {
    let Some(mut iso) = Iso::new(12) else { return };
    let mut r = iso.raw();
    let set = "busbar:metering:17";
    let old = "busbar:metering:17:k|m|p";
    let destination = "busbar:metering:17:k|m|p|0|g|v";
    let _: () = redis::cmd("HSET")
        .arg(old)
        .arg(&[
            "key_id",
            "k",
            "model",
            "m",
            "provider",
            "p",
            "key_group_at_use",
            "g",
            "pricing_version",
            "v",
            "tokens_input",
            "9007199254740993",
        ])
        .query(&mut r)
        .unwrap();
    let _: () = r.sadd(set, old).unwrap();
    let _: () = r.set(destination, "retained collision").unwrap();
    let _: () = r.set("busbar:schema", 10).unwrap();
    iso.store = None;
    assert!(ValkeyStore::connect(&iso.url).is_err());
    let stamp: i64 = r.get("busbar:schema").unwrap();
    assert_eq!(stamp, 10);
    let value: String = r.get(destination).unwrap();
    assert_eq!(value, "retained collision");
    let count: String = r.hget(old, "tokens_input").unwrap();
    assert_eq!(count, "9007199254740993");
    let names: Vec<String> = r.smembers(set).unwrap();
    assert_eq!(names, [old]);
    let _: () = r.del(destination).unwrap();
    iso.restart();
    let rows = iso.s().list_metering(17).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tokens_input, 9007199254740993);
    assert_eq!(
        (&*rows[0].key_group_at_use, &*rows[0].pricing_version),
        ("g", "v")
    );

    let _: () = r.set("busbar:schema", 10).unwrap();
    iso.restart();
    assert_eq!(iso.s().list_metering(17).unwrap(), rows);
}

#[test]
fn v10_metering_upgrade_keeps_the_existing_replay_receipt_and_same_cell() {
    let Some(mut iso) = Iso::new(12) else { return };
    let bucket = 19;
    let mut delta = metering_delta(bucket, 7);
    delta.key_id = "history".into();
    delta.key_group_at_use = "g".into();
    delta.pricing_version = "v".into();
    delta.usage_units.insert("tool_calls".into(), 11);
    let id = op(183);
    iso.s().add_metering_batch(id, &[delta.clone()]).unwrap();
    let mut r = iso.raw();
    let set = format!("busbar:metering:{bucket}");
    let names: Vec<String> = r.smembers(&set).unwrap();
    assert_eq!(names.len(), 1);
    let old = format!("{set}:history|m|p");

    if names[0] != old {
        let _: () = redis::cmd("RENAME")
            .arg(&names[0])
            .arg(&old)
            .query(&mut r)
            .unwrap();
    }
    let _: () = r.del(&set).unwrap();
    let _: () = r.sadd(&set, &old).unwrap();
    let _: () = r.set("busbar:schema", 10).unwrap();
    iso.restart();
    iso.s().add_metering_batch(id, &[delta.clone()]).unwrap();
    let rows = iso.s().list_metering(bucket).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tokens_input, 7);
    assert_eq!(rows[0].usage_units.get("tool_calls"), Some(&11));
    iso.s().add_metering_batch(op(184), &[delta]).unwrap();
    let rows = iso.s().list_metering(bucket).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tokens_input, 14);
    assert_eq!(rows[0].usage_units.get("tool_calls"), Some(&22));
}
