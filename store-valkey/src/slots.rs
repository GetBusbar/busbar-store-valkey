// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE V3 DOOR over [`ValkeyStore`]: `store_door!` and the slots the store v3 table adds to
//! the 1.5.5 op set ([`StoreSlots`]): the `op_id`-carrying writes, the journal, sessions, the
//! kernel's records, the money slots and `window_caps`.
//!
//! DEDUPE (`abi::store` S1-S4), DURABLE: every `op_id` write is ONE `WATCH`/`MULTI`/`EXEC`
//! transaction that watches the op's record key (`busbar:op:<hex op_id>`) and every key the effect
//! reads, reads the op's record, and either answers from it or stages the effect and the op's own
//! record (its value fields' digest and its answer) in the same `EXEC`. Two racing calls with one
//! `op_id` serialise on the record key: the loser's `EXEC` aborts, it runs again, and reads the
//! winner's committed record (same value fields: the original answer, nothing applied; different:
//! a conflict). A refused or failed op stages nothing, so nothing is recorded (S3). The record
//! carries a server-side TTL of [`OP_ID_RETENTION_SECS`], which is the sweep (S4). The plane-record
//! append is already one server-side script, so its record is written by that script
//! ([`plane::append_recorded`]) rather than by a transaction.
//!
//! EPOCH (ARCHITECT 2026-10-02): fixed at 0. No store ABI operation advances the epoch yet, so a
//! `reserve` or `slice_release` is never refused for the epoch it states and every head states 0.
//! When WIRE-STORE adds the advance, the store persists the epoch and refuses stale writers.
//!
//! GRANT LIFETIME: `reserve` carries no requested lifetime (`ReserveIn`, `UnitCell`), so a grant
//! never expires (`valid_until_ms = u64::MAX`): a slice holds its draw until it is released.
//!
//! KEYSPACE (additive; the schema marker does not move, see `SCHEMA_VERSION`):
//! - `busbar:op:<hex op_id>`: one op's record (a JSON string, TTL [`OP_ID_RETENTION_SECS`]).
//! - `busbar:cap:<slot>`: a hash `{cap, gen, used}` per capped slot; `<slot>` is the slot's key
//!   columns, each caller-supplied text hex-encoded so no separator can collide.
//! - `busbar:slice:<id>`: a hash `{cap, remaining}`: the slice's cap row and what it still holds;
//!   `busbar:slices:seq` mints the ids. A slice emptied by a release is deleted.
//! - `busbar:journal:<hex stream>`: a list, one element per record, its length the stream's head;
//!   `busbar:journal:streams` is the SET of streams with a record.
//! - `busbar:session:<n>`: a hash `{node, principal}`; `busbar:sessions:<hex principal>` the SET of
//!   that principal's session numbers.
//! - `busbar:rec:k:<hex schema>` (a ZSET, every score 0, so it orders by key bytes) and
//!   `busbar:rec:v:<hex schema>` (a hash `key -> value`): the kernel's records.
//!
//! One server, no cluster: every transaction here spans keys that need not share a slot, the same
//! assumption the credential cascades already make.

use std::collections::BTreeMap;

use redis::{Commands, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, OpResult, ReserveRefused,
    StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{AuditRecord, MeteringDelta, PlaneRecordRef, UsageDelta};

use crate::plane::{self, Appended};
use crate::{
    hex, refusal, stage_audit, stage_metering, stage_usage, usage_fields, usage_key, ValkeyStore,
    AUDIT_ZSET, NAME,
};

busbar_contract::store_door!(ValkeyStore, NAME, env!("CARGO_PKG_VERSION"), 64);

const OP_PREFIX: &str = "busbar:op:";
const SLICE_SEQ: &str = "busbar:slices:seq";
const JOURNAL_STREAMS: &str = "busbar:journal:streams";

/// A slot as its key columns: `(bucket, pooled, pool, dimension, class_key, window_start)`.
type Slot = (String, bool, String, u32, String, u64);

/// A cap row as read: `(cap, config_gen, used)`.
type CapRow = (u64, u64, u64);

fn slot_of(k: &CellKey<'_>) -> Slot {
    let (dimension, class_key) = match k.dimension {
        Dimension::NanoUnits => (0, ""),
        Dimension::Requests => (1, ""),
        Dimension::Concurrency => (2, ""),
        Dimension::Class(c) => (3, c),
    };
    (
        k.bucket.to_string(),
        k.pool.is_some(),
        k.pool.unwrap_or_default().to_string(),
        dimension,
        class_key.to_string(),
        k.window_start,
    )
}

fn cap_key(slot: &Slot) -> String {
    let (bucket, pooled, pool, dimension, class_key, window_start) = slot;
    format!(
        "busbar:cap:{}:{}:{}:{dimension}:{}:{window_start}",
        hex(bucket.as_bytes()),
        u8::from(*pooled),
        hex(pool.as_bytes()),
        hex(class_key.as_bytes()),
    )
}

fn slice_key(id: u64) -> String {
    format!("busbar:slice:{id}")
}

fn journal_key(stream: &str) -> String {
    format!("busbar:journal:{}", hex(stream.as_bytes()))
}

fn session_key(session: u64) -> String {
    format!("busbar:session:{session}")
}

fn principal_key(principal: &str) -> String {
    format!("busbar:sessions:{}", hex(principal.as_bytes()))
}

fn record_keys_key(schema: &str) -> String {
    format!("busbar:rec:k:{}", hex(schema.as_bytes()))
}

fn record_values_key(schema: &str) -> String {
    format!("busbar:rec:v:{}", hex(schema.as_bytes()))
}

/// The record key of one op.
pub(crate) fn op_key(op: OpId) -> String {
    format!("{OP_PREFIX}{}", hex(&op.0))
}

/// The digest of an op's value fields, which is what its record keeps of them: the same op replayed
/// must present the same digest, and nothing larger than 32 bytes per op sits in the server for the
/// retention window.
fn digest(body: &str) -> String {
    hex(&Sha256::digest(body.as_bytes()))
}

/// What an op's record holds: the digest of its value fields and its answer.
fn op_record(body: &str, answer: &Value) -> String {
    json!({ "b": digest(body), "a": answer }).to_string()
}

/// The 1.5.5 admission test for one cell (`abi::store::ReserveIn`, GRANT SIZE): whether drawing
/// `amount` onto `used` under `cap` is refused. `used + amount` is checked: an overflow refuses.
fn exhausted(dimension: u32, used: u64, amount: u64, cap: u64) -> bool {
    let Some(after) = used.checked_add(amount) else {
        return true;
    };
    match dimension {
        // DIM_CLASS: `tokens >= cap`: the draw that crosses the cap is granted whole.
        3 => used >= cap,
        // DIM_NANO_UNITS: `derived >= cap || derived + fee > cap`.
        0 => used >= cap || after > cap,
        // DIM_REQUESTS / DIM_CONCURRENCY: `used + amount > cap`.
        _ => after > cap,
    }
}

/// How an `op_id` write's refusal type spells the two refusals the dedupe itself answers.
trait Refusal {
    /// The same `op_id` with different value fields.
    fn conflict() -> Self;
    /// The backend could not run the op; nothing applied.
    fn backend(text: String) -> Self;
}

impl Refusal for OpRefused {
    fn conflict() -> Self {
        OpRefused::Conflict
    }
    fn backend(text: String) -> Self {
        OpRefused::Failed(text)
    }
}

impl Refusal for ReserveRefused {
    fn conflict() -> Self {
        ReserveRefused::Conflict
    }
    fn backend(_: String) -> Self {
        ReserveRefused::Unavailable
    }
}

impl Refusal for CapsRefused {
    fn conflict() -> Self {
        CapsRefused::Conflict
    }
    fn backend(text: String) -> Self {
        CapsRefused::Failed(text)
    }
}

fn backend<E: Refusal, D: std::fmt::Display>(e: D) -> E {
    E::backend(e.to_string())
}

fn failed(e: busbar_contract::records::RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

/// An answer that does not decode as its op's shape: the stored record is not this op's.
fn undecodable<E: Refusal>(answer: &Value) -> E {
    E::backend(format!(
        "an op record holds an answer this op cannot read: {answer}"
    ))
}

/// How a transaction settled.
enum Settled<E> {
    /// The op's record was already there: its raw text.
    Replayed(String),
    /// The effect refused; nothing was staged.
    Refused(E),
    /// The effect and the op's record committed together: the answer.
    Applied(Value),
}

/// A stored number, or the refusal that names the field that is not one.
fn number(raw: &str, what: &'static str) -> redis::RedisResult<u64> {
    raw.parse()
        .map_err(|_| refusal(what, format!("{raw:?} is not a number")))
}

/// The cap row of each distinct slot in `slots` that has a cap, as it stands now.
fn read_caps(c: &mut Connection, slots: &[Slot]) -> redis::RedisResult<BTreeMap<Slot, CapRow>> {
    let mut held = BTreeMap::new();
    for slot in slots {
        if held.contains_key(slot) {
            continue;
        }
        let (cap, gen, used): (Option<String>, Option<String>, Option<String>) =
            redis::cmd("HMGET")
                .arg(cap_key(slot))
                .arg("cap")
                .arg("gen")
                .arg("used")
                .query(c)?;
        let Some(cap) = cap else { continue };
        held.insert(
            slot.clone(),
            (
                number(&cap, "cap")?,
                number(&gen.unwrap_or_default(), "config_gen")?,
                used.map_or(Ok(0), |u| number(&u, "used"))?,
            ),
        );
    }
    Ok(held)
}

/// The cap keys of `slots`, each once.
fn cap_keys(slots: &[Slot]) -> Vec<String> {
    let mut keys: Vec<String> = slots.iter().map(cap_key).collect();
    keys.sort();
    keys.dedup();
    keys
}

impl ValkeyStore {
    /// Run one `op_id`-carrying write (module doc, DEDUPE): a replay answers the original answer, a
    /// conflict applies nothing, and a new op runs `stage` inside the op's transaction and is
    /// recorded only if it applied. `watch` names every key `stage` reads; `stage` queues its
    /// writes on the pipeline and answers the value to record, or the refusal.
    fn deduped<E: Refusal>(
        &self,
        op: OpId,
        body: &str,
        watch: &[String],
        mut stage: impl FnMut(
            &mut Connection,
            &mut redis::Pipeline,
        ) -> redis::RedisResult<Result<Value, E>>,
    ) -> Result<Value, E> {
        let key = op_key(op);
        let mut keys = vec![key.clone()];
        keys.extend_from_slice(watch);
        let settled = self
            .with_conn_no_retry(|c| {
                redis::transaction(c, &keys, |c, pipe| {
                    if let Some(raw) = c.get::<_, Option<String>>(&key)? {
                        return Ok(Some(Settled::Replayed(raw)));
                    }
                    match stage(c, pipe)? {
                        Err(refused) => Ok(Some(Settled::Refused(refused))),
                        Ok(answer) => {
                            pipe.set_ex(&key, op_record(body, &answer), OP_ID_RETENTION_SECS)
                                .ignore();
                            Ok(pipe
                                .query::<Option<()>>(c)?
                                .map(|()| Settled::Applied(answer)))
                        }
                    }
                })
            })
            .map_err(|e| E::backend(e.0))?;
        match settled {
            Settled::Applied(answer) => Ok(answer),
            Settled::Refused(e) => Err(e),
            Settled::Replayed(raw) => Self::replay(body, &raw),
        }
    }

    /// The answer an op's record holds, or a conflict when it was recorded for other value fields.
    fn replay<E: Refusal>(body: &str, raw: &str) -> Result<Value, E> {
        let recorded: Value = serde_json::from_str(raw).map_err(backend::<E, _>)?;
        if recorded["b"].as_str() == Some(digest(body).as_str()) {
            Ok(recorded["a"].clone())
        } else {
            Err(E::conflict())
        }
    }

    /// A deduped write whose answer is "done".
    fn done_op(
        &self,
        op: OpId,
        body: &str,
        watch: &[String],
        mut stage: impl FnMut(&mut Connection, &mut redis::Pipeline) -> redis::RedisResult<()>,
    ) -> OpResult<()> {
        self.deduped::<OpRefused>(op, body, watch, |c, pipe| {
            stage(c, pipe).map(|()| Ok(Value::Null))
        })
        .map(drop)
    }
}

impl StoreSlots for ValkeyStore {
    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    fn open(settings: &[u8]) -> Result<Self, String> {
        Self::from_settings(settings)
    }

    fn add_usage_op(
        &self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> OpResult<()> {
        let body = format!("add_usage:{bucket:?}:{window_start}:{delta:?}");
        let key = usage_key(bucket, window_start);
        let fields = usage_fields(delta);
        self.done_op(op, &body, std::slice::from_ref(&key), |c, pipe| {
            stage_usage(c, pipe, &key, &fields)
        })
    }

    fn add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()> {
        let body = format!("add_metering:{delta:?}");
        self.done_op(op, &body, &[], |_, pipe| {
            stage_metering(pipe, delta);
            Ok(())
        })
    }

    fn append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()> {
        let body = format!("append_audit:{entry:?}");
        self.done_op(op, &body, &[AUDIT_ZSET.to_string()], |c, pipe| {
            stage_audit(c, pipe, entry, &mut BTreeMap::new())
        })
    }

    fn append_plane_record_op(&self, op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()> {
        let body = format!("append_plane_record:{record:?}");
        let recorded = op_record(&body, &Value::Null);
        match plane::append_recorded(self, &op_key(op), &record, &recorded).map_err(failed)? {
            Appended::Written => Ok(()),
            Appended::Fork => Err(failed(plane::fork_error(&record))),
            Appended::Recorded(raw) => Self::replay::<OpRefused>(&body, &raw).map(drop),
        }
    }

    fn append_batch(&self, op: OpId, stream: &str, records: &[RecordBytes]) -> OpResult<Head> {
        let body = format!("append_batch:{stream:?}:{records:?}");
        let key = journal_key(stream);
        let answer =
            self.deduped::<OpRefused>(op, &body, std::slice::from_ref(&key), |c, pipe| {
                let len: u64 = c.llen(&key)?;
                if !records.is_empty() {
                    let mut push = redis::cmd("RPUSH");
                    push.arg(&key);
                    for r in records {
                        push.arg(r.as_slice());
                    }
                    pipe.add_command(push).ignore();
                    pipe.sadd(JOURNAL_STREAMS, stream).ignore();
                }
                Ok(Ok(json!([len + records.len() as u64, 0])))
            })?;
        match serde_json::from_value::<(u64, u64)>(answer.clone()) {
            Ok((seq, epoch)) => Ok(Head { seq, epoch }),
            Err(_) => Err(undecodable(&answer)),
        }
    }

    fn heads(&self) -> Result<Vec<(String, Head)>, String> {
        self.with_conn(|c| {
            let mut streams: Vec<String> = c.smembers(JOURNAL_STREAMS)?;
            streams.sort();
            streams
                .into_iter()
                .map(|s| {
                    let seq: u64 = c.llen(journal_key(&s))?;
                    Ok((s, Head { seq, epoch: 0 }))
                })
                .collect()
        })
        .map_err(|e| e.0)
    }

    fn session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String> {
        let key = session_key(session);
        self.with_conn(|c| {
            redis::transaction(c, &[&key], |c, pipe| {
                let held: Option<String> = c.hget(&key, "principal")?;
                if let Some(old) = held.filter(|old| old != principal) {
                    pipe.srem(principal_key(&old), session).ignore();
                }
                pipe.hset_multiple(&key, &[("node", node), ("principal", principal)])
                    .ignore()
                    .sadd(principal_key(principal), session)
                    .ignore();
                pipe.query(c)
            })
        })
        .map_err(|e| e.0)
    }

    fn session_remove(&self, session: u64) -> Result<(), String> {
        let key = session_key(session);
        self.with_conn(|c| {
            redis::transaction(c, &[&key], |c, pipe| {
                let held: Option<String> = c.hget(&key, "principal")?;
                let Some(principal) = held else {
                    return Ok(Some(()));
                };
                pipe.del(&key)
                    .ignore()
                    .srem(principal_key(&principal), session)
                    .ignore();
                pipe.query(c)
            })
        })
        .map_err(|e| e.0)
    }

    fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        self.with_conn(|c| {
            let mut sessions: Vec<u64> = c.smembers(principal_key(principal))?;
            sessions.sort_unstable();
            let mut out = Vec::with_capacity(sessions.len());
            for s in sessions {
                // A session removed since the listing read it is gone from the answer.
                if let Some(node) = c.hget::<_, _, Option<String>>(session_key(s), "node")? {
                    out.push((s, node));
                }
            }
            Ok(out)
        })
        .map_err(|e| e.0)
    }

    fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .zadd(record_keys_key(schema), key, 0)
                .ignore()
                .hset(record_values_key(schema), key, value)
                .ignore()
                .query(c)
        })
        .map_err(|e| e.0)
    }

    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String> {
        let v: Option<Vec<u8>> = self
            .with_conn(|c| c.hget(record_values_key(schema), key))
            .map_err(|e| e.0)?;
        v.map(record).transpose()
    }

    fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        // A key-ordered RANGE over the key index: `[prefix, the prefix's successor)`; a prefix with
        // no successor (empty, or every byte 0xFF) has no upper bound.
        let min = if prefix.is_empty() {
            b"-".to_vec()
        } else {
            [b"[".as_slice(), prefix].concat()
        };
        let max = match prefix_end(prefix) {
            Some(end) => [b"(".as_slice(), &end].concat(),
            None => b"+".to_vec(),
        };
        let found: Vec<(Vec<u8>, Option<Vec<u8>>)> = self
            .with_conn(|c| {
                let keys: Vec<Vec<u8>> = redis::cmd("ZRANGEBYLEX")
                    .arg(record_keys_key(schema))
                    .arg(&min)
                    .arg(&max)
                    .arg("LIMIT")
                    .arg(0)
                    .arg(limit)
                    .query(c)?;
                if keys.is_empty() {
                    return Ok(Vec::new());
                }
                let values: Vec<Option<Vec<u8>>> = redis::cmd("HMGET")
                    .arg(record_values_key(schema))
                    .arg(&keys)
                    .query(c)?;
                Ok(keys.into_iter().zip(values).collect())
            })
            .map_err(|e| e.0)?;
        found
            .into_iter()
            .filter_map(|(k, v)| Some((k, v?)))
            .map(|(k, v)| Ok((k, record(v)?)))
            .collect()
    }

    fn reserve<'c>(
        &self,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Result<(), ReserveRefused> {
        let cells: Vec<Cell<'_>> = cells.collect();
        let body = format!("reserve:{epoch}:{cells:?}");
        let slots: Vec<Slot> = cells.iter().map(|c| slot_of(&c.key)).collect();
        let answer = self.deduped(op, &body, &cap_keys(&slots), |c, pipe| {
            let held = read_caps(c, &slots)?;
            // The chain draw is all or nothing: test every cell against what the cells before it
            // in THIS draw add, and apply only when every cell passes.
            let mut drawn: BTreeMap<&Slot, u64> = BTreeMap::new();
            for (i, (cell, slot)) in cells.iter().zip(&slots).enumerate() {
                let Some(&(cap, _, used)) = held.get(slot) else {
                    return Ok(Err(ReserveRefused::NoCap { cell: i as u32 }));
                };
                let used = used.saturating_add(drawn.get(slot).copied().unwrap_or(0));
                if exhausted(slot.3, used, cell.amount, cap) {
                    return Ok(Err(ReserveRefused::Exhausted { cell: i as u32 }));
                }
                let total = drawn.entry(slot).or_default();
                *total = total.saturating_add(cell.amount);
            }
            for (slot, amount) in &drawn {
                let (_, _, used) = held[*slot];
                pipe.hset(cap_key(slot), "used", used.saturating_add(*amount))
                    .ignore();
            }
            // Slice ids come off one counter; a draw that is retried or refused leaves a gap.
            let last: u64 = c.incr(SLICE_SEQ, cells.len() as u64)?;
            let first = last + 1 - cells.len() as u64;
            let mut granted = Vec::with_capacity(cells.len());
            for (id, (cell, slot)) in (first..).zip(cells.iter().zip(&slots)) {
                pipe.hset_multiple(
                    slice_key(id),
                    &[
                        ("cap", cap_key(slot)),
                        ("remaining", cell.amount.to_string()),
                    ],
                )
                .ignore();
                granted.push(json!([id, cell.amount, u64::MAX]));
            }
            Ok(Ok(Value::Array(granted)))
        })?;
        let rows: Vec<(u64, u64, u64)> =
            serde_json::from_value(answer.clone()).map_err(|_| undecodable(&answer))?;
        grants.extend(
            rows.into_iter()
                .map(|(slice_id, granted, valid_until_ms)| Grant {
                    slice_id,
                    granted,
                    valid_until_ms,
                }),
        );
        Ok(())
    }

    fn slice_release(
        &self,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> OpResult<()> {
        let items: Vec<(u64, u64)> = items.collect();
        let body = format!("slice_release:{epoch}:{items:?}");
        let mut ids: Vec<u64> = items.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        let watch: Vec<String> = ids.iter().map(|id| slice_key(*id)).collect();
        let answer = self.deduped::<OpRefused>(op, &body, &watch, |c, pipe| {
            // Read every named slice, then refuse the whole call on one not held.
            let mut held: BTreeMap<u64, (String, u64)> = BTreeMap::new();
            for id in &ids {
                let (cap, remaining): (Option<String>, Option<String>) = redis::cmd("HMGET")
                    .arg(slice_key(*id))
                    .arg("cap")
                    .arg("remaining")
                    .query(c)?;
                let (Some(cap), Some(remaining)) = (cap, remaining) else {
                    return Ok(Err(OpRefused::Failed(format!(
                        "slice_release: slice {id} is not held"
                    ))));
                };
                held.insert(*id, (cap, number(&remaining, "remaining")?));
            }
            // Clamp each item to what its slice has left: an item naming a slice an EARLIER item
            // of this call emptied takes back 0.
            let mut back_all = Vec::with_capacity(items.len());
            let mut by_cap: BTreeMap<String, u64> = BTreeMap::new();
            for (id, unspent) in &items {
                let (cap, left) = held.get_mut(id).expect("every item's slice is held");
                let back = (*unspent).min(*left);
                *left -= back;
                *by_cap.entry(cap.clone()).or_default() += back;
                back_all.push(back);
            }
            for (id, (_, left)) in &held {
                if *left == 0 {
                    pipe.del(slice_key(*id)).ignore();
                } else {
                    pipe.hset(slice_key(*id), "remaining", *left).ignore();
                }
            }
            // The cap rows are known only now: watch them, THEN read what they hold.
            if !by_cap.is_empty() {
                redis::cmd("WATCH")
                    .arg(by_cap.keys().collect::<Vec<_>>())
                    .exec(c)?;
            }
            for (cap, back) in &by_cap {
                if let Some(used) = c.hget::<_, _, Option<String>>(cap, "used")? {
                    let used = number(&used, "used")?;
                    pipe.hset(cap, "used", used - used.min(*back)).ignore();
                }
            }
            Ok(Ok(json!(back_all)))
        })?;
        let amounts: Vec<u64> =
            serde_json::from_value(answer.clone()).map_err(|_| undecodable(&answer))?;
        released.extend(amounts);
        Ok(())
    }

    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        let body = format!("add_usage_batch:{cells:?}");
        let keys: Vec<(String, Vec<(String, i64)>)> = cells
            .iter()
            .map(|(bucket, window, delta)| (usage_key(bucket, *window), usage_fields(delta)))
            .collect();
        let mut watch: Vec<String> = keys.iter().map(|(k, _)| k.clone()).collect();
        watch.sort();
        watch.dedup();
        // The cells apply in order and atomically. A window named twice reads the server's value
        // once, so the second cell would add onto the first's input and lose it: each window's
        // pairs are therefore folded into ONE staging.
        let mut by_window: BTreeMap<&str, Vec<(String, i64)>> = BTreeMap::new();
        for (key, fields) in &keys {
            by_window
                .entry(key.as_str())
                .or_default()
                .extend(fields.iter().cloned());
        }
        self.done_op(op, &body, &watch, |c, pipe| {
            for (key, fields) in &by_window {
                stage_usage(c, pipe, key, fields)?;
            }
            Ok(())
        })
    }

    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = format!("add_metering_batch:{deltas:?}");
        self.done_op(op, &body, &[], |_, pipe| {
            for d in deltas {
                stage_metering(pipe, d);
            }
            Ok(())
        })
    }

    fn append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()> {
        let body = format!("append_audit_batch:{entries:?}");
        // One transaction: a fork anywhere in the batch stages nothing of it.
        self.done_op(op, &body, &[AUDIT_ZSET.to_string()], |c, pipe| {
            let mut staged = BTreeMap::new();
            for e in entries {
                stage_audit(c, pipe, e, &mut staged)?;
            }
            Ok(())
        })
    }

    fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
        let body = format!("window_caps:{caps:?}");
        let slots: Vec<Slot> = caps.iter().map(|c| slot_of(&c.key)).collect();
        self.deduped(op, &body, &cap_keys(&slots), |c, pipe| {
            let stored = read_caps(c, &slots)?;
            // Atomic per push: find the first conflict before applying any cap.
            let mut pushed: BTreeMap<&Slot, (u64, u64)> = BTreeMap::new();
            for (index, (cap, slot)) in caps.iter().zip(&slots).enumerate() {
                let prior = pushed
                    .get(slot)
                    .copied()
                    .or_else(|| stored.get(slot).map(|&(cap, gen, _)| (cap, gen)));
                match prior {
                    Some((value, gen)) if gen == cap.config_gen && value != cap.cap => {
                        return Ok(Err(CapsRefused::CapConflict { index }));
                    }
                    Some((_, gen)) if gen >= cap.config_gen => {}
                    _ => {
                        pushed.insert(slot, (cap.cap, cap.config_gen));
                    }
                }
            }
            for (slot, (cap, gen)) in pushed {
                pipe.hset_multiple(
                    cap_key(slot),
                    &[("cap", cap.to_string()), ("gen", gen.to_string())],
                )
                .ignore();
            }
            Ok(Ok(Value::Null))
        })
        .map(drop)
    }
}

/// A stored record's bytes as a [`RecordBytes`] (the door never lets a longer one in).
fn record(v: Vec<u8>) -> Result<RecordBytes, String> {
    RecordBytes::new(v).map_err(|n| format!("a stored record of {n} bytes is over the ceiling"))
}

/// The smallest key above every key that starts with `prefix`, or `None` when there is none.
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}
