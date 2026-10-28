// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE V3 DOOR over [`ValkeyStore`]: `store_door!` and the slots the store v3 table adds to
//! the 1.5.5 op set ([`StoreSlots`]): the `op_id`-carrying writes (the usage and metering batches
//! and the plane-record append) and the kernel's records. The store keeps ledger counts and
//! records, not money: busbar derives money from the counts and its rate card.
//!
//! ## Layout (schema v9, `crate::SCHEMA_VERSION`)
//!
//! - `busbar:op:<hex op_id>`            HASH `b` = the op's value fields, `a` = its answer; expires
//!   [`OP_ID_RETENTION_SECS`] after it is written (S4).
//! - `busbar:records:<hex schema>:k`    ZSET of keys, every score 0, so `ZRANGEBYLEX` reads them in
//!   byte order; `busbar:records:<hex schema>:v` HASH key -> value.
//!
//! ## Dedupe (`abi::store` S1-S4), durable and atomic
//!
//! Every `op_id` write checks the op's record, applies its effect and writes the record in ONE
//! atomic step, the Valkey equivalent of the SQL stores' one transaction:
//!
//! - the usage and metering batches read nothing, so they watch only the op's record under an
//!   optimistic `WATCH`/`MULTI`/`EXEC` ([`deduped!`]); a concurrent writer of it aborts the `EXEC`
//!   and the whole step re-runs against fresh state. The usage add is the floored-add script
//!   queued as a plain `EVAL`.
//! - `append_plane_record` under an `op_id` is one server-side script ([`crate::plane`]), so the
//!   kind's records are never watched (see that module's doc for why).
//!
//! A replay with the same value fields applies nothing and answers the recorded answer; different
//! value fields are a conflict and apply nothing; a refused or failed op writes nothing, its
//! record included (S3).
//!
//! //! ## Every slot is one op through the host's connector
//!
//! Each slot runs its body with the store SDK's `wire::drive_kept` on the store's ONE kept
//! connection (1.5.5's one mutex-guarded connection): drawn when the op starts (dialled through the
//! host's connector on the op's ticket when there is none), every command a write and a read that
//! may PEND (the op answers PENDING and is resumed on the connector's wake), handed back when the op
//! answers. The body is the blocking client's body, `async`.

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::wire::drive_kept;
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::resp::{cmd, pipe, Conn, RedisResult};
use crate::{
    hex, queue_metering, usage_fields, usage_key, ValkeyStore, ADD_FLOORED_LUA, NAME, NEEDS,
};

/// The settings paths this store declares may hold a secret reference (`secret_refs`): `url`, the
/// one setting that carries the connection's credentials (`user:password@host`);
/// `connect_timeout_ms` is not a secret. busbar resolves a reference only where the Statement
/// declares one and refuses it anywhere else (G14: each plugin declares its secret fields), so a
/// 1.5.5 config's `url: {env: …}` keeps booting.
const SECRET_REFS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str("url")];

busbar_contract::store_door!(
    ValkeyStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    64,
    needs: NEEDS,
    secret_refs: SECRET_REFS
);

/// The record of one `op_id`.
fn op_key(op: OpId) -> String {
    format!("busbar:op:{}", hex(&op.0))
}

/// The two keys of one schema's records: the ordered key set and the values.
fn records_keys(schema: &str) -> (String, String) {
    let p = format!("busbar:records:{}", hex(schema.as_bytes()));
    (format!("{p}:k"), format!("{p}:v"))
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
