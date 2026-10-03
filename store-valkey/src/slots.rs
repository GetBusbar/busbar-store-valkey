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
//!
//! ## Every slot is one op through the host's connector
//!
//! Each slot runs its body with the store SDK's `wire::drive`: one connection per op, dialled
//! through the host's connector on the op's ticket, every command a write and a read that may PEND
//! (the op answers PENDING and is resumed on the connector's wake), closed when the op answers. The
//! body is the blocking client's body, `async`.

use std::collections::BTreeMap;

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::wire::drive;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, Op, OpRefused, OpResult, ReserveRefused,
    Scanned, Step, StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::resp::{cmd, pipe, Conn, ErrorKind, RedisError, RedisResult};
use crate::{
    audit_fork, clamp, hex, queue_metering, usage_fields, usage_key, ValkeyStore, ADD_FLOORED_LUA,
    AUDIT_ZSET, NAME, NEEDS,
};

busbar_contract::store_door!(ValkeyStore, NAME, env!("CARGO_PKG_VERSION"), 64, needs: NEEDS);

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
fn num(v: Option<String>, what: &str) -> RedisResult<u64> {
    match v {
        None => Ok(0),
        Some(s) => s.parse().map_err(|_| {
            RedisError::from((
                ErrorKind::Client,
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
type Decided<E> = RedisResult<Result<String, E>>;

/// Pin an `op_id` write's effect (an async block) to its [`Decided`] shape.
fn decided<E, F: std::future::Future<Output = Decided<E>>>(f: F) -> F {
    f
}

/// RUN ONE `op_id`-CARRYING WRITE (module doc, DEDUPE) on `$c`: `WATCH` the op's record and
/// `$watch`, answer a recorded op from its record, else run the effect (its reads are watched; it
/// queues its writes on `$pipe`), then `EXEC` them with the op's record. An `EXEC` a concurrent
/// writer aborted re-runs the whole step. A lost `EXEC` reply is never retried (it may have
/// committed): the op fails, and its caller retries under the same `op_id`.
macro_rules! deduped {
    ($me:expr, $c:ident, $op:expr, $body:expr, $watch:expr, $E:ty, |$cc:ident, $pipe:ident| $apply:expr) => {{
        let opk = op_key($op);
        let body: &str = $body;
        let mut keys: Vec<String> = Vec::with_capacity($watch.len() + 1);
        keys.push(opk.clone());
        keys.extend($watch.iter().cloned());
        let ran: RedisResult<Result<String, $E>> = transaction!($c, &keys, |$c, tx| {
            let (b, a): (Option<Vec<u8>>, Option<String>) =
                cmd("HMGET").arg(&opk).arg("b").arg("a").query($c).await?;
            if let Some(b) = b {
                return Ok(Some(if b == body.as_bytes() {
                    Ok(a.unwrap_or_default())
                } else {
                    Err(<$E as Refusal>::conflict())
                }));
            }
            let effect: Decided<$E> = decided(async {
                let $pipe = &mut *tx;
                let $cc = &mut *$c;
                $apply
            })
            .await;
            let answer = match effect? {
                Ok(a) => a,
                Err(e) => return Ok(Some(Err(e))),
            };
            tx.hset_multiple(&opk, &[("b", body), ("a", answer.as_str())])
                .ignore()
                .expire(&opk, OP_ID_RETENTION_SECS as i64)
                .ignore();
            let committed: Option<()> = tx.query($c).await?;
            Ok(committed.map(|()| Ok(answer)))
        });
        match ran {
            Ok(answer) => answer,
            Err(e) => Err(<$E as Refusal>::backend($me.err(e, "command").0)),
        }
    }};
}

/// RUN `$body` AS ONE OP through the host's connector (module doc): `$me` is the store, `$c` the
/// op's connection; a connection that fails answers `$fail` of its error.
macro_rules! op {
    ($cx:expr, $store:expr, $fail:expr, |$me:ident, $c:ident| $body:expr) => {{
        let $me = $store.clone();
        drive($cx, move |w| {
            Box::pin(async move {
                let mut conn = match $me.conn(w).await {
                    Ok(c) => c,
                    Err(e) => return ($fail)(e),
                };
                let $c = &mut conn;
                $body
            })
        })
    }};
}

/// A failed connection as a `String` refusal.
fn text(e: RecordStoreError) -> String {
    e.0
}

impl ValkeyStore {
    /// Queue `adds`' usage adds (the floored-add script, as a plain `EVAL`) for one `op_id` write.
    async fn usage_op(
        &self,
        c: &mut Conn,
        op: OpId,
        body: &str,
        adds: &[(String, Vec<(String, i64)>)],
    ) -> OpResult<()> {
        let none: [String; 0] = [];
        deduped!(self, c, op, body, none, OpRefused, |c, pipe| {
            let _ = &c;
            for (key, fields) in adds {
                let eval = pipe.cmd("EVAL").arg(ADD_FLOORED_LUA).arg(1).arg(key);
                for (f, d) in fields {
                    eval.arg(f).arg(*d);
                }
                eval.ignore();
            }
            Ok(Ok(String::new()))
        })
        .map(drop)
    }

    /// Queue every metering delta of `deltas` for one `op_id` write.
    async fn metering_op(
        &self,
        c: &mut Conn,
        op: OpId,
        body: &str,
        deltas: &[MeteringDelta],
    ) -> OpResult<()> {
        let none: [String; 0] = [];
        deduped!(self, c, op, body, none, OpRefused, |c, pipe| {
            let _ = &c;
            for d in deltas {
                queue_metering(pipe, d);
            }
            Ok(Ok(String::new()))
        })
        .map(drop)
    }

    /// Append `entries` to the audit chain for one `op_id` write: each `seq` must be empty (it is
    /// written) or hold the identical record (the write-through retrying; nothing written); a
    /// different record anywhere fails the whole op.
    async fn audit_op(
        &self,
        c: &mut Conn,
        op: OpId,
        body: &str,
        entries: &[AuditRecord],
    ) -> OpResult<()> {
        let json: Vec<String> = entries
            .iter()
            .map(|e| serde_json::to_string(e).map_err(|e| format!("audit encode failed: {e}")))
            .collect::<Result<_, _>>()
            .map_err(OpRefused::Failed)?;
        let watch = [AUDIT_ZSET.to_string()];
        deduped!(self, c, op, body, watch, OpRefused, |c, pipe| {
            // What this op already holds at a seq: the stored record, or one queued before it.
            let mut held: BTreeMap<u64, AuditRecord> = BTreeMap::new();
            for (entry, json) in entries.iter().zip(&json) {
                let stored = match held.get(&entry.seq) {
                    Some(r) => Some(r.clone()),
                    None => {
                        let score = clamp(entry.seq);
                        let at: Vec<String> = c.zrangebyscore(AUDIT_ZSET, score, score).await?;
                        match at.first() {
                            Some(raw) => {
                                Some(serde_json::from_str::<AuditRecord>(raw).map_err(|e| {
                                    RedisError::from((
                                        ErrorKind::Client,
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
        .map(drop)
    }

    /// The cap row of each key in `keys`: `(cap, config_gen, used)`, or `None` where no cap was
    /// pushed. Read on `c` (the caller has them watched).
    async fn read_caps(
        c: &mut Conn,
        keys: &[String],
    ) -> RedisResult<BTreeMap<String, Option<CapRow>>> {
        let mut out = BTreeMap::new();
        for k in keys {
            let (cap, gen, used): (Option<String>, Option<String>, Option<String>) = cmd("HMGET")
                .arg(k)
                .arg("cap")
                .arg("gen")
                .arg("used")
                .query(c)
                .await?;
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

    async fn v3_append_batch(
        &self,
        c: &mut Conn,
        op: OpId,
        body: &str,
        stream: &str,
        records: &[RecordBytes],
    ) -> OpResult<Head> {
        let key = journal_key(stream);
        let watch = [key.clone()];
        let answer = deduped!(self, c, op, body, watch, OpRefused, |c, pipe| {
            let len: u64 = c.llen(&key).await?;
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

    async fn v3_heads(&self, c: &mut Conn) -> Result<Vec<(String, Head)>, String> {
        let mut streams: Vec<String> =
            with_conn!(self, |c| c.smembers(JOURNAL_STREAMS).await).map_err(|e| e.0)?;
        streams.sort();
        if streams.is_empty() {
            return Ok(Vec::new());
        }
        let lens: Vec<u64> = with_conn!(self, |c| {
            let mut pipe = pipe();
            for s in &streams {
                pipe.llen(journal_key(s));
            }
            pipe.query(c).await
        })
        .map_err(|e| e.0)?;
        Ok(streams
            .into_iter()
            .zip(lens)
            .map(|(s, seq)| (s, Head { seq, epoch: 0 }))
            .collect())
    }

    async fn v3_session_put(
        &self,
        c: &mut Conn,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Result<(), String> {
        let key = session_key(session);
        let id = session.to_string();
        with_conn!(self, |c| {
            transaction!(c, &[key.as_str()], |c, pipe| {
                let old: Option<String> = c.hget(&key, "principal").await?;
                if let Some(old) = old.filter(|o| o != principal) {
                    pipe.srem(principal_sessions_key(&old), &id).ignore();
                }
                pipe.hset_multiple(&key, &[("node", node), ("principal", principal)])
                    .ignore()
                    .sadd(principal_sessions_key(principal), &id)
                    .ignore();
                pipe.query(c).await
            })
        })
        .map_err(|e| e.0)
    }

    async fn v3_session_remove(&self, c: &mut Conn, session: u64) -> Result<(), String> {
        let key = session_key(session);
        let id = session.to_string();
        with_conn!(self, |c| {
            transaction!(c, &[key.as_str()], |c, pipe| {
                let old: Option<String> = c.hget(&key, "principal").await?;
                if let Some(old) = old {
                    pipe.srem(principal_sessions_key(&old), &id).ignore();
                }
                pipe.del(&key).ignore();
                pipe.query(c).await
            })
        })
        .map_err(|e| e.0)
    }

    async fn v3_sessions_for(
        &self,
        c: &mut Conn,
        principal: &str,
    ) -> Result<Vec<(u64, String)>, String> {
        let ids: Vec<u64> = with_conn!(self, |c| c
            .smembers(principal_sessions_key(principal))
            .await)
        .map_err(|e| e.0)?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<(Option<String>, Option<String>)> = with_conn!(self, |c| {
            let mut pipe = pipe();
            pipe.atomic();
            for id in &ids {
                pipe.cmd("HMGET")
                    .arg(session_key(*id))
                    .arg("node")
                    .arg("principal");
            }
            pipe.query(c).await
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

    async fn v3_record_put(
        &self,
        c: &mut Conn,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        let (k, v) = records_keys(schema);
        with_conn!(self, |c| {
            pipe()
                .atomic()
                .zadd(&k, key, 0)
                .ignore()
                .hset(&v, key, value)
                .ignore()
                .query(c)
                .await
        })
        .map_err(|e| e.0)
    }

    async fn v3_record_get(
        &self,
        c: &mut Conn,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        let (_, v) = records_keys(schema);
        let got: Option<Vec<u8>> = with_conn!(self, |c| c.hget(&v, key).await).map_err(|e| e.0)?;
        got.map(record).transpose()
    }

    async fn v3_record_scan(
        &self,
        c: &mut Conn,
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
        let keys: Vec<Vec<u8>> = with_conn!(self, |c| {
            cmd("ZRANGEBYLEX")
                .arg(&k)
                .arg(&min)
                .arg(&max)
                .arg("LIMIT")
                .arg(0)
                .arg(limit)
                .query(c)
                .await
        })
        .map_err(|e| e.0)?;
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let values: Vec<Option<Vec<u8>>> =
            with_conn!(self, |c| cmd("HMGET").arg(&v).arg(&keys).query(c).await)
                .map_err(|e| e.0)?;
        keys.into_iter()
            .zip(values)
            .filter_map(|(key, value)| Some((key, value?)))
            .map(|(key, value)| Ok((key, record(value)?)))
            .collect()
    }

    async fn v3_reserve(
        &self,
        c: &mut Conn,
        op: OpId,
        body: &str,
        slots: &[(String, u32)],
        amounts: &[u64],
    ) -> Result<Vec<Grant>, ReserveRefused> {
        let watch = distinct(slots.iter().map(|(k, _)| k.clone()));
        let answer = deduped!(self, c, op, body, watch, ReserveRefused, |c, pipe| {
            let held = Self::read_caps(c, &watch).await?;
            // The chain draw is all or nothing: test every cell against what the cells before it
            // in THIS draw add, and apply only when every cell passes.
            let mut drawn: BTreeMap<&str, u64> = BTreeMap::new();
            for (i, (amount, (key, dimension))) in amounts.iter().zip(slots).enumerate() {
                let Some(&Some((cap, _, used))) = held.get(key) else {
                    return Ok(Err(ReserveRefused::NoCap { cell: i as u32 }));
                };
                let used = used.saturating_add(drawn.get(key.as_str()).copied().unwrap_or(0));
                if exhausted(*dimension, used, *amount, cap) {
                    return Ok(Err(ReserveRefused::Exhausted { cell: i as u32 }));
                }
                *drawn.entry(key.as_str()).or_default() += *amount;
            }
            for (key, amount) in &drawn {
                let used = held[*key].map_or(0, |(_, _, used)| used);
                pipe.hset(*key, "used", used.saturating_add(*amount).to_string())
                    .ignore();
            }
            // Slice ids are taken outside the transaction: an aborted or refused draw leaves a gap,
            // never a reused id.
            let last: u64 = c.incr(SLICE_SEQ, amounts.len() as u64).await?;
            let first = last + 1 - amounts.len() as u64;
            let mut granted = Vec::with_capacity(amounts.len());
            for ((amount, (key, _)), id) in amounts.iter().zip(slots).zip(first..) {
                pipe.hset_multiple(
                    slice_key(id),
                    &[("cap", key.clone()), ("left", amount.to_string())],
                )
                .ignore();
                granted.push((id, *amount, u64::MAX));
            }
            Ok(Ok(serde_json::to_string(&granted).unwrap_or_default()))
        })?;
        let rows: Vec<(u64, u64, u64)> =
            serde_json::from_str(&answer).map_err(|_| undecodable::<ReserveRefused>(&answer))?;
        Ok(rows
            .into_iter()
            .map(|(slice_id, granted, valid_until_ms)| Grant {
                slice_id,
                granted,
                valid_until_ms,
            })
            .collect())
    }

    async fn v3_slice_release(
        &self,
        c: &mut Conn,
        op: OpId,
        body: &str,
        items: &[(u64, u64)],
    ) -> OpResult<Vec<u64>> {
        let mut ids: Vec<u64> = items.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        let watch: Vec<String> = ids.iter().map(|id| slice_key(*id)).collect();
        let answer = deduped!(self, c, op, body, watch, OpRefused, |c, pipe| {
            // Every named slice must be held, or the whole call is refused.
            let mut held: BTreeMap<u64, (String, u64)> = BTreeMap::new();
            for id in &ids {
                let (cap, left): (Option<String>, Option<String>) = cmd("HMGET")
                    .arg(slice_key(*id))
                    .arg("cap")
                    .arg("left")
                    .query(c)
                    .await?;
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
                cmd("WATCH").arg(&caps).exec(c).await?;
            }
            let rows = Self::read_caps(c, &caps).await?;
            // Clamp each item to what its slice has left: an item naming a slice an EARLIER item
            // of this call emptied takes back 0.
            let mut back_all = Vec::with_capacity(items.len());
            let mut by_cap: BTreeMap<String, u64> = BTreeMap::new();
            for (id, unspent) in items {
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
        serde_json::from_str(&answer).map_err(|_| undecodable::<OpRefused>(&answer))
    }

    async fn v3_window_caps(
        &self,
        c: &mut Conn,
        op: OpId,
        body: &str,
        keys: &[String],
        values: &[(u64, u64)],
    ) -> Result<(), CapsRefused> {
        let watch = distinct(keys.iter().cloned());
        deduped!(self, c, op, body, watch, CapsRefused, |c, pipe| {
            let stored = Self::read_caps(c, &watch).await?;
            // Atomic per push: find the first conflict before applying any cap.
            let mut pushed: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
            for (index, ((cap, config_gen), key)) in values.iter().zip(keys).enumerate() {
                let prior = pushed.get(key.as_str()).copied().or_else(|| {
                    stored
                        .get(key)
                        .copied()
                        .flatten()
                        .map(|(cap, gen, _)| (cap, gen))
                });
                match prior {
                    Some((value, gen)) if gen == *config_gen && value != *cap => {
                        return Ok(Err(CapsRefused::CapConflict { index }));
                    }
                    Some((_, gen)) if gen >= *config_gen => {}
                    _ => {
                        pushed.insert(key.as_str(), (*cap, *config_gen));
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

/// `keys`, sorted and without repeats: a watch list.
fn distinct(keys: impl Iterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = keys.collect();
    v.sort();
    v.dedup();
    v
}

/// The usage adds of `cells`, as the floored-add script's `(key, fields)`.
fn usage_adds<'a>(
    cells: impl Iterator<Item = (&'a str, u64, &'a UsageDelta)>,
) -> Vec<(String, Vec<(String, i64)>)> {
    cells
        .map(|(bucket, window, delta)| (usage_key(bucket, window), usage_fields(delta)))
        .collect()
}

impl StoreSlots for ValkeyStore {
    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    fn validate(settings: &[u8]) -> Result<(), String> {
        Self::from_settings(settings).map(drop)
    }

    fn open(settings: &[u8], _host: Option<Host>) -> Result<Self, String> {
        Self::from_settings(settings)
    }

    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        let me = self.clone();
        drive(cx, move |w| {
            Box::pin(async move {
                me.connect_step(w)
                    .await
                    .map_err(|e| crate::failed_to_connect(&e))
            })
        })
    }

    fn add_usage_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Step<OpResult<()>> {
        let body = format!("add_usage:{bucket:?}:{window_start}:{delta:?}");
        let adds = usage_adds(std::iter::once((bucket, window_start, delta)));
        op!(cx, self, |e| Err(OpRefused::Failed(text(e))), |me, c| me
            .usage_op(c, op, &body, &adds)
            .await)
    }

    fn add_metering_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        delta: &MeteringDelta,
    ) -> Step<OpResult<()>> {
        let body = format!("add_metering:{delta:?}");
        let deltas = vec![delta.clone()];
        op!(cx, self, |e| Err(OpRefused::Failed(text(e))), |me, c| me
            .metering_op(c, op, &body, &deltas)
            .await)
    }

    fn append_audit_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        entry: &AuditRecord,
    ) -> Step<OpResult<()>> {
        let body = format!("append_audit:{entry:?}");
        let entries = vec![entry.clone()];
        op!(cx, self, |e| Err(OpRefused::Failed(text(e))), |me, c| me
            .audit_op(c, op, &body, &entries)
            .await)
    }

    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        let body = format!("append_plane_record:{record:?}");
        let record = record.to_record();
        op!(cx, self, |e| Err(OpRefused::Failed(text(e))), |me, c| {
            crate::plane::append_op(&me, c, &op_key(op), &body, record.view()).await
        })
    }

    fn append_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> Step<OpResult<Head>> {
        let body = format!("append_batch:{stream:?}:{records:?}");
        let (stream, records) = (stream.to_string(), records.to_vec());
        op!(cx, self, |e| Err(OpRefused::Failed(text(e))), |me, c| me
            .v3_append_batch(c, op, &body, &stream, &records)
            .await)
    }

    fn heads(&self, cx: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>> {
        op!(cx, self, |e| Err(text(e)), |me, c| me.v3_heads(c).await)
    }

    fn session_put(
        &self,
        cx: &mut Op<'_>,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Step<Result<(), String>> {
        let (node, principal) = (node.to_string(), principal.to_string());
        op!(cx, self, |e| Err(text(e)), |me, c| me
            .v3_session_put(c, session, &node, &principal)
            .await)
    }

    fn session_remove(&self, cx: &mut Op<'_>, session: u64) -> Step<Result<(), String>> {
        op!(cx, self, |e| Err(text(e)), |me, c| me
            .v3_session_remove(c, session)
            .await)
    }

    fn sessions_for(
        &self,
        cx: &mut Op<'_>,
        principal: &str,
    ) -> Step<Result<Vec<(u64, String)>, String>> {
        let principal = principal.to_string();
        op!(cx, self, |e| Err(text(e)), |me, c| me
            .v3_sessions_for(c, &principal)
            .await)
    }

    fn record_put(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        let (schema, key, value) = (schema.to_string(), key.to_vec(), value.to_vec());
        op!(cx, self, |e| Err(text(e)), |me, c| me
            .v3_record_put(c, &schema, &key, &value)
            .await)
    }

    fn record_get(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>> {
        let (schema, key) = (schema.to_string(), key.to_vec());
        op!(cx, self, |e| Err(text(e)), |me, c| me
            .v3_record_get(c, &schema, &key)
            .await)
    }

    fn record_scan(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>> {
        let (schema, prefix) = (schema.to_string(), prefix.to_vec());
        op!(cx, self, |e| Err(text(e)), |me, c| me
            .v3_record_scan(c, &schema, &prefix, limit)
            .await)
    }

    fn reserve<'c>(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        let cells: Vec<Cell<'_>> = cells.collect();
        let body = format!("reserve:{epoch}:{cells:?}");
        let slots: Vec<(String, u32)> = cells.iter().map(|c| cap_key(&c.key)).collect();
        let amounts: Vec<u64> = cells.iter().map(|c| c.amount).collect();
        let step = op!(cx, self, |_| Err(ReserveRefused::Unavailable), |me, c| me
            .v3_reserve(c, op, &body, &slots, &amounts)
            .await);
        match step {
            Step::Ready(Ok(g)) => {
                grants.extend(g);
                Step::Ready(Ok(()))
            }
            Step::Ready(Err(e)) => Step::Ready(Err(e)),
            Step::Pending { wake_at_ns } => Step::Pending { wake_at_ns },
        }
    }

    fn slice_release(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        let items: Vec<(u64, u64)> = items.collect();
        let body = format!("slice_release:{epoch}:{items:?}");
        let step = op!(cx, self, |e| Err(OpRefused::Failed(text(e))), |me, c| me
            .v3_slice_release(c, op, &body, &items)
            .await);
        match step {
            Step::Ready(Ok(back)) => {
                released.extend(back);
                Step::Ready(Ok(()))
            }
            Step::Ready(Err(e)) => Step::Ready(Err(e)),
            Step::Pending { wake_at_ns } => Step::Pending { wake_at_ns },
        }
    }

    fn add_usage_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        let body = format!("add_usage_batch:{cells:?}");
        let adds = usage_adds(cells.iter().map(|(b, w, d)| (*b, *w, d)));
        op!(cx, self, |e| Err(OpRefused::Failed(text(e))), |me, c| me
            .usage_op(c, op, &body, &adds)
            .await)
    }

    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        let body = format!("add_metering_batch:{deltas:?}");
        let deltas = deltas.to_vec();
        op!(cx, self, |e| Err(OpRefused::Failed(text(e))), |me, c| me
            .metering_op(c, op, &body, &deltas)
            .await)
    }

    fn append_audit_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        entries: &[AuditRecord],
    ) -> Step<OpResult<()>> {
        let body = format!("append_audit_batch:{entries:?}");
        let entries = entries.to_vec();
        // One transaction: a fork anywhere in the batch writes none of it.
        op!(cx, self, |e| Err(OpRefused::Failed(text(e))), |me, c| me
            .audit_op(c, op, &body, &entries)
            .await)
    }

    fn window_caps(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        caps: &[Cap<'_>],
    ) -> Step<Result<(), CapsRefused>> {
        let body = format!("window_caps:{caps:?}");
        let keys: Vec<String> = caps.iter().map(|c| cap_key(&c.key).0).collect();
        let values: Vec<(u64, u64)> = caps.iter().map(|c| (c.cap, c.config_gen)).collect();
        op!(cx, self, |e| Err(CapsRefused::Failed(text(e))), |me, c| me
            .v3_window_caps(c, op, &body, &keys, &values)
            .await)
    }

    // ── the 1.5.5 op set: each body is the store's own (`lib.rs`), run as one op ──────────────

    fn put_key(&self, cx: &mut Op<'_>, key: &VirtualKey) -> Step<RecordStoreResult<()>> {
        let key = key.clone();
        op!(cx, self, Err, |me, c| me.put_key(c, &key).await)
    }

    fn get_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<Option<VirtualKey>>> {
        let id = id.to_string();
        op!(cx, self, Err, |me, c| me.get_key(c, &id).await)
    }

    fn list_keys(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        op!(cx, self, Err, |me, c| me.list_keys(c).await)
    }

    fn delete_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        let id = id.to_string();
        op!(cx, self, Err, |me, c| me.delete_key(c, &id).await)
    }

    fn scrub_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        let id = id.to_string();
        op!(cx, self, Err, |me, c| me.scrub_key(c, &id).await)
    }

    fn list_keys_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        op!(cx, self, Err, |me, c| me.list_keys_since(c, since).await)
    }

    fn get_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>> {
        let bucket_id = bucket_id.to_string();
        op!(cx, self, Err, |me, c| me
            .get_usage(c, &bucket_id, window_start)
            .await)
    }

    fn put_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>> {
        let (bucket_id, ledger) = (bucket_id.to_string(), ledger.clone());
        op!(cx, self, Err, |me, c| me
            .put_usage(c, &bucket_id, window_start, &ledger)
            .await)
    }

    fn list_metering(
        &self,
        cx: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
        op!(cx, self, Err, |me, c| me.list_metering(c, bucket).await)
    }

    /// Left at the 1.5.5 trait's `Ok(0)` (module doc, DATA GROWTH): no connection is made.
    fn purge_windows_before(&self, _: &mut Op<'_>, _: u64) -> Step<RecordStoreResult<u64>> {
        Step::Ready(Ok(0))
    }

    /// Left at the 1.5.5 trait's `Ok(0)` (module doc, DATA GROWTH): no connection is made.
    fn purge_metering_before(&self, _: &mut Op<'_>, _: &str) -> Step<RecordStoreResult<u64>> {
        Step::Ready(Ok(0))
    }

    fn put_credential(
        &self,
        cx: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        let secret = secret.clone();
        op!(cx, self, Err, |me, c| me.put_credential(c, &secret).await)
    }

    fn put_key_with_credential(
        &self,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        let (key, secret) = (key.clone(), secret.clone());
        op!(cx, self, Err, |me, c| me
            .put_key_with_credential(c, &key, &secret)
            .await)
    }

    fn list_credentials(
        &self,
        cx: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
        let key_id = key_id.to_string();
        op!(cx, self, Err, |me, c| me.list_credentials(c, &key_id).await)
    }

    fn lookup_credential_secret(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        public_id: &str,
    ) -> Step<RecordStoreResult<Option<CredentialSecret>>> {
        let (kind, public_id) = (kind.to_string(), public_id.to_string());
        op!(cx, self, Err, |me, c| me
            .lookup_credential_secret(c, &kind, &public_id)
            .await)
    }

    fn revoke_credential(
        &self,
        cx: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (id, reason) = (id.to_string(), reason.to_string());
        op!(cx, self, Err, |me, c| me
            .revoke_credential(c, &id, &reason)
            .await)
    }

    fn list_credentials_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
        op!(cx, self, Err, |me, c| me
            .list_credentials_since(c, since)
            .await)
    }

    fn list_audit(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        op!(cx, self, Err, |me, c| me.list_audit(c).await)
    }

    fn add_denylist(
        &self,
        cx: &mut Op<'_>,
        sub: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (sub, reason) = (sub.to_string(), reason.to_string());
        op!(cx, self, Err, |me, c| me
            .add_denylist(c, &sub, &reason)
            .await)
    }

    fn list_denylist(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        op!(cx, self, Err, |me, c| me.list_denylist(c).await)
    }

    fn list_audit_tail(
        &self,
        cx: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        op!(cx, self, Err, |me, c| me.list_audit_tail(c, limit).await)
    }

    fn upsert_plane_record(
        &self,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        let record = record.to_record();
        op!(cx, self, Err, |me, c| me
            .upsert_plane_record(c, record.view())
            .await)
    }

    fn get_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
        let (kind, id) = (kind.to_string(), id.to_string());
        op!(cx, self, Err, |me, c| me
            .get_plane_record(c, &kind, &id)
            .await)
    }

    fn list_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
        let (kind, selector) = (kind.to_string(), selector.to_static());
        op!(cx, self, Err, |me, c| me
            .list_plane_records(c, &kind, &selector)
            .await)
    }

    fn list_plane_record_parents(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>> {
        let kind = kind.to_string();
        op!(cx, self, Err, |me, c| me
            .list_plane_record_parents(c, &kind)
            .await)
    }

    fn purge_plane_records_before(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>> {
        let kind = kind.to_string();
        op!(cx, self, Err, |me, c| me
            .purge_plane_records_before(c, &kind, before)
            .await)
    }

    fn delete_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (kind, id) = (kind.to_string(), id.to_string());
        op!(cx, self, Err, |me, c| me
            .delete_plane_record(c, &kind, &id)
            .await)
    }

    fn redeem_plane_token(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        let (kind, token) = (kind.to_string(), token.to_string());
        op!(cx, self, Err, |me, c| me
            .redeem_plane_token(c, &kind, &token, expires_at, now)
            .await)
    }

    fn plane_token_live(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        let (kind, token) = (kind.to_string(), token.to_string());
        op!(cx, self, Err, |me, c| me
            .plane_token_live(c, &kind, &token, expires_at, now)
            .await)
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
