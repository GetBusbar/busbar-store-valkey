// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE V3 DOOR over [`ValkeyStore`]: `store_door!` and the slots the store v3 table adds to
//! the 1.5.5 op set ([`StoreSlots`]): the `op_id`-carrying writes, the journal, sessions, the
//! kernel's records, the money slots and `window_caps`.
//!
//! ## Layout (schema v8, `crate::SCHEMA_VERSION`: the v7 keys plus the epoch, `until` and the index)
//!
//! - `busbar:op:<hex op_id>`            HASH `b` = the op's value fields, `a` = its answer; expires
//!   [`OP_ID_RETENTION_SECS`] after it is written (S4).
//! - `busbar:cap:<slot>`                HASH `cap`, `gen` (the `config_gen`), `used` (drawn), each a
//!   decimal `u64`. `<slot>` is `<hex bucket>:<pool>:<dimension>:<hex class>:<window_start>`, the
//!   pool `-` for every pool or `p<hex pool>`: hex has no `:`, so two slots never share a key.
//! - `busbar:slice:<id>`                HASH `cap` (its slot's key), `left` (what it still holds),
//!   `until` (its `valid_until_ms`). Deleted when the slice closes (its `left` reaches 0, any release
//!   on window 0, or its expiry reclaimed); a closed id is told from a never-granted one by
//!   `busbar:slices`.
//! - `busbar:open:<slot>`               ZSET of the slot's open slice ids, each scored by its `until`:
//!   the index the expiry reclaim reads (`ZRANGEBYSCORE -inf now`), so no SCAN on the hot path.
//! - `busbar:epoch`                     STRING, the fleet's ONE epoch (decimal `u64`; absent reads 0).
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
//! EPOCH AND SLICE LIFE (`abi::store::money`, rules (a)-(c); this store is shared by a fleet): the
//! fleet's ONE epoch is `busbar:epoch`. A `reserve` presenting a higher epoch raises it in its own
//! `EXEC`, atomically with its draw; one presenting a lower epoch is `StaleEpoch`, applies nothing
//! and records nothing under its `op_id`; nothing lowers it, and it survives a restart. The epoch key
//! is WATCHed by every `reserve`, so a raise aborts every draw of the old epoch still in flight (it
//! re-runs and is refused), and a draw of the old epoch that commits first is ordered before the
//! raise. Every slice is granted `valid_until_ms = now + SLICE_TTL_MS` on the SERVER's clock
//! (`TIME`: one clock for the fleet, not each node's), a concurrency gauge's slice included. A
//! `reserve` returns the unreturned part of the expired slices of its slots (from each slot's
//! `busbar:open:` index) to their windows' headroom before it tests them, and a `slice_release`
//! does the same for its slices' slots first, so an expired slice answers 0 to a release (its money
//! already went back at expiry) and a node that crashed holding a slice strands nothing past one TTL.
//! A `slice_release` always applies, whatever the epoch. The heads (`append_batch`, `heads`) state
//! epoch 0, as busbar-store-postgres's do: the journal is not fenced by the money epoch. Do not run
//! a v7 build against a v8 namespace: a v7 build refuses nothing newer than itself, and its slices
//! carry no `until` and no index entry, so they never expire (a v8 build refuses a newer marker).
//!
//! The money arithmetic is exact `u64` in Rust, never in Lua (whose numbers are doubles): the cap
//! rows are read under `WATCH` and written back whole.
//!
//! ## Every slot is one op through the host's connector
//!
//! Each slot runs its body with the store SDK's `wire::drive_kept` on the store's ONE kept
//! connection (1.5.5's one mutex-guarded connection): drawn when the op starts (dialled through the
//! host's connector on the op's ticket when there is none), every command a write and a read that
//! may PEND (the op answers PENDING and is resumed on the connector's wake), handed back when the op
//! answers. The body is the blocking client's body, `async`.

use std::collections::{BTreeMap, BTreeSet};

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::wire::drive_kept;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, Op, OpRefused, OpResult, ReserveRefused,
    Scanned, Step, StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS, SLICE_TTL_MS};
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
/// The fleet's ONE epoch (module doc, EPOCH AND SLICE LIFE).
const EPOCH_KEY: &str = "busbar:epoch";
/// Where a slot's key starts: `busbar:cap:<slot>`.
const CAP_PREFIX: &str = "busbar:cap:";
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

/// The open-slice index of the slot whose cap key is `cap`: `busbar:open:<slot>`.
fn open_key(cap: &str) -> String {
    format!(
        "busbar:open:{}",
        cap.strip_prefix(CAP_PREFIX).unwrap_or(cap)
    )
}

/// The server's clock in ms (`TIME`): the fleet's one clock.
async fn server_now_ms(c: &mut Conn) -> RedisResult<u64> {
    let (secs, micros): (String, String) = cmd("TIME").query(c).await?;
    let secs = num(Some(secs), "TIME's seconds")?;
    let micros = num(Some(micros), "TIME's microseconds")?;
    Ok(secs.saturating_mul(1000).saturating_add(micros / 1000))
}

/// The v7 -> v8 stamp of ONE slice hash (`KEYS[1]`): a slice still open with no `until` gets
/// `ARGV[1]` and joins its slot's open-slice index as id `ARGV[2]`. A slice already stamped keeps its
/// `until`, and a key that is no longer a slice (closed meanwhile) is left absent, so the stamp is
/// idempotent and never resurrects a closed slice. `busbar:cap:` is 11 bytes.
const STAMP_LUA: &str = r#"
local cap = redis.call('HGET', KEYS[1], 'cap')
if not cap then return 0 end
if redis.call('HEXISTS', KEYS[1], 'until') == 1 then return 0 end
redis.call('HSET', KEYS[1], 'until', ARGV[1])
redis.call('ZADD', 'busbar:open:' .. string.sub(cap, 12), ARGV[1], ARGV[2])
return 1
"#;

/// Create the fleet epoch at 0 where there is none (`SET NX`: an epoch already raised stays).
pub(crate) async fn create_epoch(me: &ValkeyStore, c: &mut Conn) -> RecordStoreResult<()> {
    with_conn!(me, |c| cmd("SET")
        .arg(EPOCH_KEY)
        .arg("0")
        .arg("NX")
        .query::<Option<String>>(c)
        .await)
    .map(drop)
}

/// THE v7 -> v8 STEP (`crate::SCHEMA_VERSION`): the epoch created at 0, and every slice a v7 build
/// left open stamped to expire one `SLICE_TTL_MS` from the server's clock and indexed for reclaim.
/// The SCAN runs once, at the upgrade, never on the hot path. Idempotent (see [`STAMP_LUA`]), so a
/// crash re-runs it and two nodes first-booting at once land in the same place.
pub(crate) async fn stamp_open_slices(me: &ValkeyStore, c: &mut Conn) -> RecordStoreResult<()> {
    create_epoch(me, c).await?;
    let until = with_conn!(me, |c| server_now_ms(c).await)?.saturating_add(SLICE_TTL_MS);
    let keys: Vec<String> = with_conn!(me, |c| {
        c.scan_match::<_, String>("busbar:slice:*")
            .await?
            .collect::<Result<Vec<String>, _>>()
    })?;
    for key in keys {
        let Some(id) = key
            .strip_prefix("busbar:slice:")
            .and_then(|id| id.parse::<u64>().ok())
        else {
            continue;
        };
        with_conn!(me, |c| cmd("EVAL")
            .arg(STAMP_LUA)
            .arg(1)
            .arg(&key)
            .arg(until.to_string())
            .arg(id.to_string())
            .query::<i64>(c)
            .await)?;
    }
    Ok(())
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
    fn backend(text: String) -> Self {
        // The ABI carries no text for Unavailable: the reason goes to the plugin's log.
        tracing::warn!("busbar-store-valkey: reserve unavailable: {text}");
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

/// RUN `$body` AS ONE OP through the host's connector (module doc) on the store's kept connection:
/// `$me` is the store, `$c` the op's connection; a connection that fails answers `$fail` of its
/// error. A connection the body left with a `WATCH` in force is not kept.
macro_rules! op {
    ($cx:expr, $store:expr, $fail:expr, |$me:ident, $c:ident| $body:expr) => {{
        let $me = $store.clone();
        let pool = $me.pool().clone();
        drive_kept($cx, &pool, move |w| {
            Box::pin(async move {
                let mut conn = match $me.conn(w, "reconnect").await {
                    Ok(c) => c,
                    Err(e) => return ($fail)(e),
                };
                let answer = {
                    let $c = &mut conn;
                    $body
                };
                conn.settle();
                answer
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

    /// SLICE LIFE (c): queue the reclaim of every slice of the slots `caps` that has expired by
    /// `now` (its `until <= now`), from each slot's open-slice index: the slice hash is deleted, its
    /// index entry removed, and its unreturned `left` taken off its slot's `used` in `rows`. The
    /// caller has `caps` and their indexes watched; the expired slice keys are watched here before
    /// they are read. Answers the reclaimed ids and the slots whose `used` changed (the caller
    /// writes those).
    async fn reclaim(
        c: &mut Conn,
        pipe: &mut crate::resp::Pipeline,
        caps: &[String],
        now: u64,
        rows: &mut BTreeMap<String, Option<CapRow>>,
    ) -> RedisResult<(BTreeSet<u64>, BTreeSet<String>)> {
        let mut reclaimed = BTreeSet::new();
        let mut dirty = BTreeSet::new();
        for cap in caps {
            let index = open_key(cap);
            let ids: Vec<String> = c.zrangebyscore(&index, "-inf", now).await?;
            if ids.is_empty() {
                continue;
            }
            let ids: Vec<u64> = ids
                .into_iter()
                .map(|id| num(Some(id), "an open slice id"))
                .collect::<RedisResult<_>>()?;
            let keys: Vec<String> = ids.iter().map(|id| slice_key(*id)).collect();
            cmd("WATCH").arg(&keys).exec(c).await?;
            for (id, key) in ids.into_iter().zip(keys) {
                let (held, left): (Option<String>, Option<String>) = cmd("HMGET")
                    .arg(&key)
                    .arg("cap")
                    .arg("left")
                    .query(c)
                    .await?;
                pipe.cmd("ZREM").arg(&index).arg(id).ignore();
                if held.is_none() {
                    // An index entry whose slice already closed: only the entry goes.
                    continue;
                }
                let left = num(left, "a slice's holding")?;
                pipe.del(&key).ignore();
                if let Some(Some((_, _, used))) = rows.get_mut(cap) {
                    *used = used.saturating_sub(left);
                    dirty.insert(cap.clone());
                }
                reclaimed.insert(id);
            }
        }
        Ok((reclaimed, dirty))
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
        epoch: u64,
        slots: &[(String, u32)],
        amounts: &[u64],
    ) -> Result<Vec<Grant>, ReserveRefused> {
        let caps = distinct(slots.iter().map(|(k, _)| k.clone()));
        // The epoch, the slots and their open-slice indexes are watched: a raise, a draw, a
        // release or a reclaim of any of them aborts this step and it re-runs on fresh state.
        let mut watch = distinct(caps.iter().flat_map(|k| [k.clone(), open_key(k)]));
        watch.push(EPOCH_KEY.to_string());
        let answer = deduped!(self, c, op, body, watch, ReserveRefused, |c, pipe| {
            // THE EPOCH FENCE (rules (a), (b)): a stale epoch applies and records nothing.
            let stored: Option<String> = c.get(EPOCH_KEY).await?;
            let stored = num(stored, "the fleet epoch")?;
            if stored > epoch {
                return Ok(Err(ReserveRefused::StaleEpoch));
            }
            let now = server_now_ms(c).await?;
            let valid_until = now.saturating_add(SLICE_TTL_MS);
            let mut held = Self::read_caps(c, &caps).await?;
            // Slice life (c): the expired slices' unreturned part goes back to the headroom
            // before the cells are tested.
            let (_, dirty) = Self::reclaim(c, pipe, &caps, now, &mut held).await?;
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
            let changed: BTreeSet<&str> = drawn
                .keys()
                .copied()
                .chain(dirty.iter().map(String::as_str))
                .collect();
            for key in changed {
                let used = held[key].map_or(0, |(_, _, used)| used);
                let add = drawn.get(key).copied().unwrap_or(0);
                pipe.hset(key, "used", used.saturating_add(add).to_string())
                    .ignore();
            }
            if epoch > stored {
                pipe.set(EPOCH_KEY, epoch.to_string()).ignore();
            }
            // Slice ids are taken outside the transaction: an aborted or refused draw leaves a gap,
            // never a reused id.
            let last: u64 = c.incr(SLICE_SEQ, amounts.len() as u64).await?;
            let first = last + 1 - amounts.len() as u64;
            let mut granted = Vec::with_capacity(amounts.len());
            for ((amount, (key, _)), id) in amounts.iter().zip(slots).zip(first..) {
                pipe.hset_multiple(
                    slice_key(id),
                    &[
                        ("cap", key.clone()),
                        ("left", amount.to_string()),
                        ("until", valid_until.to_string()),
                    ],
                )
                .ignore();
                pipe.zadd(open_key(key), id, valid_until).ignore();
                granted.push((id, *amount, valid_until));
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
            // Every named slice must have been granted, or the whole call is refused. A slice with
            // no hash is either closed (its hash is deleted at close: it was handed out, so its id
            // is within the counter) or never granted. The counter is a plain GET, not WATCHed
            // (every reserve INCRs it), and read at most once per step. Accepted weakness: an id in
            // a gap left by an aborted or lost draw (never handed to anyone) answers 0 rather than
            // Failed; only a buggy caller could name one, and 0 moves no money.
            let mut held: BTreeMap<u64, (String, u64)> = BTreeMap::new();
            let mut closed: BTreeSet<u64> = BTreeSet::new();
            let mut counter: Option<u64> = None;
            for id in &ids {
                let (cap, left): (Option<String>, Option<String>) = cmd("HMGET")
                    .arg(slice_key(*id))
                    .arg("cap")
                    .arg("left")
                    .query(c)
                    .await?;
                let Some(cap) = cap else {
                    let last = match counter {
                        Some(last) => last,
                        None => {
                            let got: Option<String> = cmd("GET").arg(SLICE_SEQ).query(c).await?;
                            let last = num(got, "the slice counter")?;
                            counter = Some(last);
                            last
                        }
                    };
                    if *id >= 1 && *id <= last {
                        closed.insert(*id);
                        continue;
                    }
                    return Ok(Err(OpRefused::Failed(format!(
                        "slice_release: slice {id} was never granted"
                    ))));
                };
                held.insert(*id, (cap, num(left, "a slice's holding")?));
            }
            // The slices' caps and their open-slice indexes join the watch before they are read.
            let caps = distinct(held.values().map(|(cap, _)| cap.clone()));
            if !caps.is_empty() {
                let watch: Vec<String> =
                    caps.iter().flat_map(|k| [k.clone(), open_key(k)]).collect();
                cmd("WATCH").arg(&watch).exec(c).await?;
            }
            let mut rows = Self::read_caps(c, &caps).await?;
            // Slice life (c) first: the expired slices of these slots are reclaimed as a reserve
            // would, so a release of an expired slice answers 0 (its money went back at expiry).
            let dirty = if caps.is_empty() {
                BTreeSet::new()
            } else {
                let now = server_now_ms(c).await?;
                let (reclaimed, dirty) = Self::reclaim(c, pipe, &caps, now, &mut rows).await?;
                for id in reclaimed {
                    if held.remove(&id).is_some() {
                        closed.insert(id);
                    }
                }
                dirty
            };
            // Clamp each item to what its slice has left: an item naming a slice an EARLIER item
            // of this call emptied takes back 0.
            let mut back_all = Vec::with_capacity(items.len());
            let mut by_cap: BTreeMap<String, u64> = BTreeMap::new();
            let mut closed_on_zero: BTreeSet<u64> = BTreeSet::new();
            for (id, unspent) in items {
                if closed.contains(id) {
                    back_all.push(0);
                    continue;
                }
                let (cap, left) = held.get_mut(id).expect("every item's slice is held");
                let back = (*unspent).min(*left);
                *left -= back;
                // A release on window 0 is final (`abi::store` slice life (e)): window 0 never
                // rolls, so a slice on it has no window close to end it. It closes at its first
                // release; the spent rest stays counted against the cap. The slot key ends in
                // `:<window_start>`.
                if cap.rsplit(':').next() == Some("0") {
                    *left = 0;
                    closed_on_zero.insert(*id);
                }
                *by_cap.entry(cap.clone()).or_default() += back;
                back_all.push(back);
            }
            for (id, (cap, left)) in &held {
                // A slice that closed (window 0 at its first release, a rolling window at 0) is
                // deleted.
                if closed_on_zero.contains(id) || *left == 0 {
                    pipe.del(slice_key(*id)).ignore();
                    pipe.cmd("ZREM").arg(open_key(cap)).arg(*id).ignore();
                } else {
                    pipe.hset(slice_key(*id), "left", left.to_string()).ignore();
                }
            }
            let changed: BTreeSet<&String> = by_cap.keys().chain(&dirty).collect();
            for cap in changed {
                let used = rows
                    .get(cap)
                    .copied()
                    .flatten()
                    .map_or(0, |(_, _, used)| used);
                let back = by_cap.get(cap).copied().unwrap_or(0);
                pipe.hset(cap, "used", used.saturating_sub(back).to_string())
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
        let pool = me.pool().clone();
        drive_kept(cx, &pool, move |w| {
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
        let unavailable = |e: RecordStoreError| {
            tracing::warn!("busbar-store-valkey: reserve unavailable: {}", e.0);
            Err(ReserveRefused::Unavailable)
        };
        let step = op!(cx, self, unavailable, |me, c| me
            .v3_reserve(c, op, &body, epoch, &slots, &amounts)
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

    fn purge_windows_before(&self, cx: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        op!(cx, self, Err, |me, c| me
            .purge_windows_before(c, before)
            .await)
    }

    fn purge_metering_before(&self, cx: &mut Op<'_>, bucket: &str) -> Step<RecordStoreResult<u64>> {
        let bucket = bucket.to_string();
        op!(cx, self, Err, |me, c| me
            .purge_metering_before(c, &bucket)
            .await)
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

    fn purge_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
        retention: busbar_contract::records::Retention,
    ) -> Step<RecordStoreResult<u64>> {
        match retention {
            busbar_contract::records::Retention::Age => {
                StoreSlots::purge_plane_records_before(self, cx, kind, before)
            }
            busbar_contract::records::Retention::TerminalOnly => Step::Ready(Ok(0)),
        }
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
