// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE V3 DOOR over [`ValkeyStore`]: `store_door!` and the slots the store v3 table adds to
//! the 1.5.5 op set ([`StoreSlots`]): the `op_id`-carrying writes, the journal, sessions, the
//! kernel's records, the money slots and `window_caps`.
//!
//! ## Layout (additive: no key an earlier schema wrote changes, so the schema marker stays at 7)
//!
//! - `busbar:op:<hex op_id>`            HASH `b` = the op's value fields, `a` = its answer; expires
//!   [`OP_ID_RETENTION_SECS`] after it is written (S4).
//! - `busbar:cap:<slot>`                HASH `cap`, `gen` (the `config_gen`), `used` (drawn), each a
//!   decimal `u64`. `<slot>` is `<hex bucket>:<pool>:<dimension>:<hex class>:<window_start>`, the
//!   pool `-` for every pool or `p<hex pool>`: hex has no `:`, so two slots never share a key.
//! - `busbar:slice:<id>`                HASH `cap` (its slot's key), `left` (what it still holds).
//! - `busbar:slices`                    STRING, the last slice id handed out (`INCRBY`; never reused).
//! - `busbar:journal:<hex stream>`      LIST of records, oldest first: a record's `seq` is its
//!   position from 1, so the stream's head is its length. `busbar:journal:streams` SET names them.
//! - `busbar:session:<id>`              HASH `node`, `principal`; `busbar:sessions:<hex principal>`
//!   SET of the principal's session ids.
//! - `busbar:records:<hex schema>:k`    ZSET of keys, every score 0, so `ZRANGEBYLEX` reads them in
//!   byte order; `busbar:records:<hex schema>:v` HASH key -> value.
//!
//! ## Dedupe (`abi::store` S1-S4), durable and atomic
//!
//! Every `op_id` write checks the op's record, applies its effect and writes the record in ONE
//! atomic step, the Valkey equivalent of the SQL stores' one transaction:
//!
//! - an `op_id` write whose effect reads before it decides (the money slots, the audit chain, the
//!   journal head) runs as an optimistic `WATCH`/`MULTI`/`EXEC` over the op's record and every key
//!   it reads ([`ValkeyStore::deduped`]); a concurrent writer of any of them aborts the `EXEC` and
//!   the whole step re-runs against fresh state. The usage and metering adds read nothing, so they
//!   watch only the op's record; the usage add is the floored-add script queued as a plain `EVAL`.
//! - `append_plane_record` under an `op_id` is one server-side script ([`crate::plane`]), so the
//!   kind's records are never watched (see that module's doc for why).
//!
//! A replay with the same value fields applies nothing and answers the recorded answer; different
//! value fields are a conflict and apply nothing; a refused or failed op writes nothing, its
//! record included (S3).
//!
//! EPOCH (ARCHITECT 2026-10-02): fixed at 0. No store ABI operation advances the epoch yet, so a
//! `reserve` or `slice_release` is never refused for the epoch it states and every head states 0.
//! When WIRE-STORE adds the advance, the store persists the epoch and refuses stale writers.
//!
//! GRANT LIFETIME: `reserve` carries no requested lifetime (`ReserveIn`, `UnitCell`), so a grant
//! never expires (`valid_until_ms = u64::MAX`): a slice holds its draw until it is released.
//!
//! The money arithmetic is exact `u64` in Rust, never in Lua (whose numbers are doubles): the cap
//! rows are read under `WATCH` and written back whole.

use std::collections::BTreeMap;

use redis::{Commands, Connection, Pipeline};

use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, OpResult, ReserveRefused,
    StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{AuditRecord, MeteringDelta, PlaneRecordRef, UsageDelta};

use crate::{
    audit_fork, clamp, hex, queue_metering, usage_fields, usage_key, ValkeyStore, ADD_FLOORED_LUA,
    AUDIT_ZSET, NAME,
};

busbar_contract::store_door!(ValkeyStore, NAME, env!("CARGO_PKG_VERSION"), 64);

const SLICE_SEQ: &str = "busbar:slices";
const JOURNAL_STREAMS: &str = "busbar:journal:streams";

/// The record of one `op_id`.
fn op_key(op: OpId) -> String {
    format!("busbar:op:{}", hex(&op.0))
}

/// One cap's slot: its key and its dimension (`abi::store::DIM_*`).
fn cap_key(k: &CellKey<'_>) -> (String, u32) {
    let (dimension, class) = match k.dimension {
        Dimension::NanoUnits => (0, ""),
        Dimension::Requests => (1, ""),
        Dimension::Concurrency => (2, ""),
        Dimension::Class(c) => (3, c),
    };
    let pool = match k.pool {
        None => "-".to_string(),
        Some(p) => format!("p{}", hex(p.as_bytes())),
    };
    (
        format!(
            "busbar:cap:{}:{pool}:{dimension}:{}:{}",
            hex(k.bucket.as_bytes()),
            hex(class.as_bytes()),
            k.window_start
        ),
        dimension,
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

fn principal_sessions_key(principal: &str) -> String {
    format!("busbar:sessions:{}", hex(principal.as_bytes()))
}

/// The two keys of one schema's records: the ordered key set and the values.
fn records_keys(schema: &str) -> (String, String) {
    let p = format!("busbar:records:{}", hex(schema.as_bytes()));
    (format!("{p}:k"), format!("{p}:v"))
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

/// An answer that does not decode as its op's shape: the stored record is not this op's.
fn undecodable<E: Refusal>(answer: &str) -> E {
    E::backend(format!(
        "busbar:op holds an answer this op cannot read: {answer}"
    ))
}

/// A stored decimal field, `0` when absent.
fn num(v: Option<String>, what: &str) -> redis::RedisResult<u64> {
    match v {
        None => Ok(0),
        Some(s) => s.parse().map_err(|_| {
            redis::RedisError::from((
                redis::ErrorKind::Client,
                "corrupt store row",
                format!("{what} is not a u64: {s:?}"),
            ))
        }),
    }
}

/// One cap row: `(cap, config_gen, used)`.
type CapRow = (u64, u64, u64);

/// What one `op_id` write's effect decided under `WATCH`: its answer (the writes are queued on the
/// pipe), or the refusal it answers with nothing applied.
type Decided<E> = redis::RedisResult<Result<String, E>>;

impl ValkeyStore {
    /// Run one `op_id`-carrying write (module doc, DEDUPE): `WATCH` the op's record and `watch`,
    /// answer a recorded op from its record, else let `apply` read (its reads are watched) and
    /// queue its writes, then `EXEC` them with the op's record. An `EXEC` a concurrent writer
    /// aborted re-runs the whole step. No reconnect-retry: a lost `EXEC` reply may have committed.
    fn deduped<E: Refusal>(
        &self,
        op: OpId,
        body: &str,
        watch: &[String],
        mut apply: impl FnMut(&mut Connection, &mut Pipeline) -> Decided<E>,
    ) -> Result<String, E> {
        let opk = op_key(op);
        let mut keys = Vec::with_capacity(watch.len() + 1);
        keys.push(opk.clone());
        keys.extend(watch.iter().cloned());
        let ran = self.with_conn_no_retry(|c| {
            redis::transaction(c, &keys, |c, pipe| {
                let (b, a): (Option<Vec<u8>>, Option<String>) =
                    redis::cmd("HMGET").arg(&opk).arg("b").arg("a").query(c)?;
                if let Some(b) = b {
                    return Ok(Some(if b == body.as_bytes() {
                        Ok(a.unwrap_or_default())
                    } else {
                        Err(E::conflict())
                    }));
                }
                let answer = match apply(c, pipe)? {
                    Ok(a) => a,
                    Err(e) => return Ok(Some(Err(e))),
                };
                pipe.hset_multiple(&opk, &[("b", body), ("a", answer.as_str())])
                    .ignore()
                    .expire(&opk, OP_ID_RETENTION_SECS as i64)
                    .ignore();
                let committed: Option<()> = pipe.query(c)?;
                Ok(committed.map(|()| Ok(answer)))
            })
        });
        match ran {
            Ok(answer) => answer,
            Err(e) => Err(E::backend(e.0)),
        }
    }

    /// A deduped write whose answer is "done".
    fn done_op(
        &self,
        op: OpId,
        body: &str,
        watch: &[String],
        apply: impl FnMut(&mut Connection, &mut Pipeline) -> Decided<OpRefused>,
    ) -> OpResult<()> {
        self.deduped(op, body, watch, apply).map(drop)
    }

    /// Queue `cells`' usage adds (the floored-add script, as a plain `EVAL`) for one `op_id` write.
    fn usage_op(&self, op: OpId, body: &str, cells: &[(&str, u64, &UsageDelta)]) -> OpResult<()> {
        let adds: Vec<(String, Vec<(String, i64)>)> = cells
            .iter()
            .map(|(bucket, window, delta)| (usage_key(bucket, *window), usage_fields(delta)))
            .collect();
        self.done_op(op, body, &[], |_, pipe| {
            for (key, fields) in &adds {
                let eval = pipe.cmd("EVAL").arg(ADD_FLOORED_LUA).arg(1).arg(key);
                for (f, d) in fields {
                    eval.arg(f).arg(*d);
                }
                eval.ignore();
            }
            Ok(Ok(String::new()))
        })
    }

    /// Append `entries` to the audit chain for one `op_id` write: each `seq` must be empty (it is
    /// written) or hold the identical record (the write-through retrying; nothing written); a
    /// different record anywhere fails the whole op.
    fn audit_op(&self, op: OpId, body: &str, entries: &[AuditRecord]) -> OpResult<()> {
        let json: Vec<String> = entries
            .iter()
            .map(|e| serde_json::to_string(e).map_err(|e| format!("audit encode failed: {e}")))
            .collect::<Result<_, _>>()
            .map_err(OpRefused::Failed)?;
        self.done_op(op, body, &[AUDIT_ZSET.to_string()], |c, pipe| {
            // What this op already holds at a seq: the stored record, or one queued before it.
            let mut held: BTreeMap<u64, AuditRecord> = BTreeMap::new();
            for (entry, json) in entries.iter().zip(&json) {
                let stored = match held.get(&entry.seq) {
                    Some(r) => Some(r.clone()),
                    None => {
                        let score = clamp(entry.seq);
                        let at: Vec<String> = c.zrangebyscore(AUDIT_ZSET, score, score)?;
                        match at.first() {
                            Some(raw) => {
                                Some(serde_json::from_str::<AuditRecord>(raw).map_err(|e| {
                                    redis::RedisError::from((
                                        redis::ErrorKind::Client,
                                        "audit decode failed",
                                        e.to_string(),
                                    ))
                                })?)
                            }
                            None => None,
                        }
                    }
                };
                match stored {
                    Some(s) if s == *entry => {}
                    Some(s) => return Ok(Err(OpRefused::Failed(audit_fork(&s, entry)))),
                    None => {
                        pipe.zadd(AUDIT_ZSET, json, clamp(entry.seq)).ignore();
                    }
                }
                held.insert(entry.seq, entry.clone());
            }
            Ok(Ok(String::new()))
        })
    }

    /// The cap row of each key in `keys`: `(cap, config_gen, used)`, or `None` where no cap was
    /// pushed. Read on `c` (the caller has them watched).
    fn read_caps(
        c: &mut Connection,
        keys: &[String],
    ) -> redis::RedisResult<BTreeMap<String, Option<CapRow>>> {
        let mut out = BTreeMap::new();
        for k in keys {
            let (cap, gen, used): (Option<String>, Option<String>, Option<String>) =
                redis::cmd("HMGET")
                    .arg(k)
                    .arg("cap")
                    .arg("gen")
                    .arg("used")
                    .query(c)?;
            let row = match cap {
                None => None,
                Some(cap) => Some((
                    num(Some(cap), "a cap")?,
                    num(gen, "a config_gen")?,
                    num(used, "a drawn total")?,
                )),
            };
            out.insert(k.clone(), row);
        }
        Ok(out)
    }
}

/// `keys`, sorted and without repeats: a watch list.
fn distinct(keys: impl Iterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = keys.collect();
    v.sort();
    v.dedup();
    v
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
        self.usage_op(op, &body, &[(bucket, window_start, delta)])
    }

    fn add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()> {
        let body = format!("add_metering:{delta:?}");
        self.done_op(op, &body, &[], |_, pipe| {
            queue_metering(pipe, delta);
            Ok(Ok(String::new()))
        })
    }

    fn append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()> {
        let body = format!("append_audit:{entry:?}");
        self.audit_op(op, &body, std::slice::from_ref(entry))
    }

    fn append_plane_record_op(&self, op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()> {
        let body = format!("append_plane_record:{record:?}");
        crate::plane::append_op(self, &op_key(op), &body, record)
    }

    fn append_batch(&self, op: OpId, stream: &str, records: &[RecordBytes]) -> OpResult<Head> {
        let body = format!("append_batch:{stream:?}:{records:?}");
        let key = journal_key(stream);
        let answer =
            self.deduped::<OpRefused>(op, &body, std::slice::from_ref(&key), |c, pipe| {
                let len: u64 = c.llen(&key)?;
                if !records.is_empty() {
                    let values: Vec<&[u8]> = records.iter().map(RecordBytes::as_slice).collect();
                    pipe.rpush(&key, values).ignore();
                }
                pipe.sadd(JOURNAL_STREAMS, stream).ignore();
                Ok(Ok((len + records.len() as u64).to_string()))
            })?;
        match answer.parse::<u64>() {
            Ok(seq) => Ok(Head { seq, epoch: 0 }),
            Err(_) => Err(undecodable(&answer)),
        }
    }

    fn heads(&self) -> Result<Vec<(String, Head)>, String> {
        let mut streams: Vec<String> = self
            .with_conn(|c| c.smembers(JOURNAL_STREAMS))
            .map_err(|e| e.0)?;
        streams.sort();
        if streams.is_empty() {
            return Ok(Vec::new());
        }
        let lens: Vec<u64> = self
            .with_conn(|c| {
                let mut pipe = redis::pipe();
                for s in &streams {
                    pipe.llen(journal_key(s));
                }
                pipe.query(c)
            })
            .map_err(|e| e.0)?;
        Ok(streams
            .into_iter()
            .zip(lens)
            .map(|(s, seq)| (s, Head { seq, epoch: 0 }))
            .collect())
    }

    fn session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String> {
        let key = session_key(session);
        let id = session.to_string();
        self.with_conn(|c| {
            redis::transaction(c, &[key.as_str()], |c, pipe| {
                let old: Option<String> = c.hget(&key, "principal")?;
                if let Some(old) = old.filter(|o| o != principal) {
                    pipe.srem(principal_sessions_key(&old), &id).ignore();
                }
                pipe.hset_multiple(&key, &[("node", node), ("principal", principal)])
                    .ignore()
                    .sadd(principal_sessions_key(principal), &id)
                    .ignore();
                pipe.query(c)
            })
        })
        .map_err(|e| e.0)
    }

    fn session_remove(&self, session: u64) -> Result<(), String> {
        let key = session_key(session);
        let id = session.to_string();
        self.with_conn(|c| {
            redis::transaction(c, &[key.as_str()], |c, pipe| {
                let old: Option<String> = c.hget(&key, "principal")?;
                if let Some(old) = old {
                    pipe.srem(principal_sessions_key(&old), &id).ignore();
                }
                pipe.del(&key).ignore();
                pipe.query(c)
            })
        })
        .map_err(|e| e.0)
    }

    fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        let ids: Vec<u64> = self
            .with_conn(|c| c.smembers(principal_sessions_key(principal)))
            .map_err(|e| e.0)?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<(Option<String>, Option<String>)> = self
            .with_conn(|c| {
                let mut pipe = redis::pipe();
                pipe.atomic();
                for id in &ids {
                    pipe.cmd("HMGET")
                        .arg(session_key(*id))
                        .arg("node")
                        .arg("principal");
                }
                pipe.query(c)
            })
            .map_err(|e| e.0)?;
        let mut out: Vec<(u64, String)> = ids
            .into_iter()
            .zip(rows)
            .filter_map(|(id, (node, p))| (p.as_deref() == Some(principal)).then_some((id, node?)))
            .collect();
        out.sort();
        Ok(out)
    }

    fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let (k, v) = records_keys(schema);
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .zadd(&k, key, 0)
                .ignore()
                .hset(&v, key, value)
                .ignore()
                .query(c)
        })
        .map_err(|e| e.0)
    }

    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String> {
        let (_, v) = records_keys(schema);
        let got: Option<Vec<u8>> = self.with_conn(|c| c.hget(&v, key)).map_err(|e| e.0)?;
        got.map(record).transpose()
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
        let (k, v) = records_keys(schema);
        // A byte-ordered RANGE over the key set: `[prefix, the prefix's successor)`; a prefix with
        // no successor (empty, or every byte 0xFF) has no upper bound.
        let min: Vec<u8> = if prefix.is_empty() {
            b"-".to_vec()
        } else {
            [b"[".as_slice(), prefix].concat()
        };
        let max: Vec<u8> = match prefix_end(prefix) {
            Some(end) => [b"(".as_slice(), end.as_slice()].concat(),
            None => b"+".to_vec(),
        };
        let keys: Vec<Vec<u8>> = self
            .with_conn(|c| {
                redis::cmd("ZRANGEBYLEX")
                    .arg(&k)
                    .arg(&min)
                    .arg(&max)
                    .arg("LIMIT")
                    .arg(0)
                    .arg(limit)
                    .query(c)
            })
            .map_err(|e| e.0)?;
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let values: Vec<Option<Vec<u8>>> = self
            .with_conn(|c| redis::cmd("HMGET").arg(&v).arg(&keys).query(c))
            .map_err(|e| e.0)?;
        keys.into_iter()
            .zip(values)
            .filter_map(|(key, value)| Some((key, value?)))
            .map(|(key, value)| Ok((key, record(value)?)))
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
        let slots: Vec<(String, u32)> = cells.iter().map(|c| cap_key(&c.key)).collect();
        let watch = distinct(slots.iter().map(|(k, _)| k.clone()));
        let answer = self.deduped(op, &body, &watch, |c, pipe| {
            let held = Self::read_caps(c, &watch)?;
            // The chain draw is all or nothing: test every cell against what the cells before it
            // in THIS draw add, and apply only when every cell passes.
            let mut drawn: BTreeMap<&str, u64> = BTreeMap::new();
            for (i, (cell, (key, dimension))) in cells.iter().zip(&slots).enumerate() {
                let Some(&Some((cap, _, used))) = held.get(key) else {
                    return Ok(Err(ReserveRefused::NoCap { cell: i as u32 }));
                };
                let used = used.saturating_add(drawn.get(key.as_str()).copied().unwrap_or(0));
                if exhausted(*dimension, used, cell.amount, cap) {
                    return Ok(Err(ReserveRefused::Exhausted { cell: i as u32 }));
                }
                *drawn.entry(key.as_str()).or_default() += cell.amount;
            }
            for (key, amount) in &drawn {
                let used = held[*key].map_or(0, |(_, _, used)| used);
                pipe.hset(*key, "used", used.saturating_add(*amount).to_string())
                    .ignore();
            }
            // Slice ids are taken outside the transaction: an aborted or refused draw leaves a gap,
            // never a reused id.
            let last: u64 = c.incr(SLICE_SEQ, cells.len() as u64)?;
            let first = last + 1 - cells.len() as u64;
            let mut granted = Vec::with_capacity(cells.len());
            for ((cell, (key, _)), id) in cells.iter().zip(&slots).zip(first..) {
                pipe.hset_multiple(
                    slice_key(id),
                    &[("cap", key.clone()), ("left", cell.amount.to_string())],
                )
                .ignore();
                granted.push((id, cell.amount, u64::MAX));
            }
            Ok(Ok(serde_json::to_string(&granted).unwrap_or_default()))
        })?;
        let rows: Vec<(u64, u64, u64)> =
            serde_json::from_str(&answer).map_err(|_| undecodable::<ReserveRefused>(&answer))?;
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
        let answer = self.deduped(op, &body, &watch, |c, pipe| {
            // Every named slice must be held, or the whole call is refused.
            let mut held: BTreeMap<u64, (String, u64)> = BTreeMap::new();
            for id in &ids {
                let (cap, left): (Option<String>, Option<String>) = redis::cmd("HMGET")
                    .arg(slice_key(*id))
                    .arg("cap")
                    .arg("left")
                    .query(c)?;
                let Some(cap) = cap else {
                    return Ok(Err(OpRefused::Failed(format!(
                        "slice_release: slice {id} is not held"
                    ))));
                };
                held.insert(*id, (cap, num(left, "a slice's holding")?));
            }
            // The slices' caps join the watch before they are read.
            let caps = distinct(held.values().map(|(cap, _)| cap.clone()));
            if !caps.is_empty() {
                redis::cmd("WATCH").arg(&caps).exec(c)?;
            }
            let rows = Self::read_caps(c, &caps)?;
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
                    pipe.hset(slice_key(*id), "left", left.to_string()).ignore();
                }
            }
            for (cap, back) in &by_cap {
                let used = rows
                    .get(cap)
                    .copied()
                    .flatten()
                    .map_or(0, |(_, _, used)| used);
                pipe.hset(cap, "used", used.saturating_sub(*back).to_string())
                    .ignore();
            }
            Ok(Ok(serde_json::to_string(&back_all).unwrap_or_default()))
        })?;
        let amounts: Vec<u64> =
            serde_json::from_str(&answer).map_err(|_| undecodable::<OpRefused>(&answer))?;
        released.extend(amounts);
        Ok(())
    }

    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        let body = format!("add_usage_batch:{cells:?}");
        let cells: Vec<(&str, u64, &UsageDelta)> =
            cells.iter().map(|(b, w, d)| (*b, *w, d)).collect();
        self.usage_op(op, &body, &cells)
    }

    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = format!("add_metering_batch:{deltas:?}");
        self.done_op(op, &body, &[], |_, pipe| {
            for d in deltas {
                queue_metering(pipe, d);
            }
            Ok(Ok(String::new()))
        })
    }

    fn append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()> {
        let body = format!("append_audit_batch:{entries:?}");
        // One transaction: a fork anywhere in the batch writes none of it.
        self.audit_op(op, &body, entries)
    }

    fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
        let body = format!("window_caps:{caps:?}");
        let keys: Vec<String> = caps.iter().map(|c| cap_key(&c.key).0).collect();
        let watch = distinct(keys.iter().cloned());
        self.deduped(op, &body, &watch, |c, pipe| {
            let stored = Self::read_caps(c, &watch)?;
            // Atomic per push: find the first conflict before applying any cap.
            let mut pushed: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
            for (index, (cap, key)) in caps.iter().zip(&keys).enumerate() {
                let prior = pushed.get(key.as_str()).copied().or_else(|| {
                    stored
                        .get(key)
                        .copied()
                        .flatten()
                        .map(|(cap, gen, _)| (cap, gen))
                });
                match prior {
                    Some((value, gen)) if gen == cap.config_gen && value != cap.cap => {
                        return Ok(Err(CapsRefused::CapConflict { index }));
                    }
                    Some((_, gen)) if gen >= cap.config_gen => {}
                    _ => {
                        pushed.insert(key.as_str(), (cap.cap, cap.config_gen));
                    }
                }
            }
            for (key, (cap, gen)) in pushed {
                pipe.hset_multiple(key, &[("cap", cap.to_string()), ("gen", gen.to_string())])
                    .ignore();
            }
            Ok(Ok(String::new()))
        })
        .map(drop)
    }
}

/// A stored record's bytes as a [`RecordBytes`].
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

#[cfg(test)]
#[path = "tests/slots_unit.rs"]
mod unit;
