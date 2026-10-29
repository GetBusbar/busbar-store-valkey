// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 door over [`ValkeyStore`]: `store_door!` and the slots the store v3 table adds to
//! the base op set ([`StoreSlots`]): the `op_id`-carrying writes (the usage and metering batches
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
//!   optimistic `WATCH`/`MULTI`/`EXEC` (`deduped`); a concurrent writer of it aborts the `EXEC`
//!   and the whole step re-runs against fresh state. The usage add is the floored-add script
//!   queued as a plain `EVAL`.
//! - `append_plane_record` under an `op_id` is one server-side script ([`crate::plane`]), so the
//!   kind's records are never watched (see that module's doc for why).
//!
//! A replay with the same value fields applies nothing and answers the recorded answer; different
//! value fields are a conflict and apply nothing; a refused or failed op writes nothing, its
//! record included (S3).
//!
//! ## Every slot is one op through the host's connector
//!
//! Each slot runs its body with the store SDK's `wire::drive_kept` on the store's ONE kept
//! connection: drawn when the op starts (dialled through the
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

use crate::resp::{cmd, pipe, Conn, Pipeline, RedisResult};
use crate::{
    hex, plane, queue_metering, usage_fields, usage_key, ValkeyStore, ADD_FLOORED_LUA, NAME, NEEDS,
};

/// THE REFERENCE-CAPABLE, NOT-SECRET SETTINGS FIELDS (busbar lead ruling item 7a), stated in the
/// Statement's extensions under the contract's `EXT_REFERENCE_FIELDS` key: a `{env:}`/`{file:}`/
/// `{module:}` reference written at `url` is resolved by the kernel IN PLACE to its string (a 1.5.5
/// config's `url: {env: VAR}` keeps booting), and a literal url passes as written (never refused
/// as a secret literal). The value is not a secret: it is never lent.
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

busbar_contract::store_door!(
    ValkeyStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    64,
    needs: NEEDS,
    extensions: EXTENSIONS
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

/// Slots whose body is `$body(&store, conn, args..)` run as one op ([`op!`]): each argument
/// the body needs past the call is owned first (`=> to_owned` and the like) and lent back to it.
macro_rules! ops {
    ($($name:ident($($arg:ident: $ty:ty $(=> $own:ident)?),*) -> $out:ty = $body:path;)*) => {$(
        fn $name(&self, cx: &mut Op<'_>, $($arg: $ty),*) -> Step<RecordStoreResult<$out>> {
            $(let $arg = ops!(@own $arg $($own)?);)*
            op!(cx, self, Err, |me, c| $body(&me, c, $(ops!(@lend $arg $($own)?)),*).await)
        }
    )*};
    (@own $a:ident) => { $a };
    (@own $a:ident $own:ident) => { $a.$own() };
    (@lend $a:ident) => { $a };
    (@lend $a:ident $own:ident) => { &$a };
}

impl ValkeyStore {
    /// RUN ONE `op_id`-CARRYING WRITE (module doc, DEDUPE) on `c`: `WATCH` the op's record; a
    /// recorded op answers from it (a replay, or a conflict on different value fields); else `queue`
    /// puts the effect on the atomic pipeline, `EXEC`ed with the op's record. An `EXEC` a concurrent
    /// writer aborted re-runs the whole step. A lost `EXEC` reply is never retried (it may have
    /// committed): the op fails, and its caller retries under the same `op_id`.
    async fn deduped(
        &self,
        c: &mut Conn,
        op: OpId,
        body: &str,
        queue: impl Fn(&mut Pipeline),
    ) -> OpResult<()> {
        let opk = op_key(op);
        let ran: RedisResult<OpResult<()>> = transaction!(c, &[opk.as_str()], |c, tx| {
            let recorded: Option<Vec<u8>> = cmd("HGET").arg(&opk).arg("b").query(c).await?;
            if let Some(b) = recorded {
                return Ok(Some(if b == body.as_bytes() {
                    Ok(())
                } else {
                    Err(OpRefused::Conflict)
                }));
            }
            queue(tx);
            tx.hset_multiple(&opk, &[("b", body), ("a", "")])
                .ignore()
                .expire(&opk, OP_ID_RETENTION_SECS as i64)
                .ignore();
            let committed: Option<()> = tx.query(c).await?;
            Ok(committed.map(Ok))
        });
        ran.unwrap_or_else(|e| Err(OpRefused::Failed(self.err(e, "command").0)))
    }

    /// `record_put` (slot 40): an upsert on `(schema, key)`. An EMPTY value removes the row:
    /// it is the host's strike, so the key leaves both the ordered key set and the values,
    /// `record_get` then answers `None` and `record_scan` never returns it.
    /// Removing a row that is not there is `Ok`.
    async fn v3_record_put(
        &self,
        c: &mut Conn,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        let (k, v) = records_keys(schema);
        if value.is_empty() {
            return with_conn!(self, |c| {
                pipe()
                    .atomic()
                    .cmd("ZREM")
                    .arg(&k)
                    .arg(key)
                    .ignore()
                    .cmd("HDEL")
                    .arg(&v)
                    .arg(key)
                    .ignore()
                    .query(c)
                    .await
            })
            .map_err(|e| e.0);
        }
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
                    .map_err(|e| format!("valkey plugin: failed to connect: {}", e.0))
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
        op!(
            cx,
            self,
            |e: RecordStoreError| Err(OpRefused::Failed(e.0)),
            |me, c| crate::plane::append_op(&me, c, &op_key(op), &body, record.view()).await
        )
    }

    fn record_put(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        let (schema, key, value) = (schema.to_string(), key.to_vec(), value.to_vec());
        op!(cx, self, |e: RecordStoreError| Err(e.0), |me, c| me
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
        op!(cx, self, |e: RecordStoreError| Err(e.0), |me, c| me
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
        op!(cx, self, |e: RecordStoreError| Err(e.0), |me, c| me
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
        op!(
            cx,
            self,
            |e: RecordStoreError| Err(OpRefused::Failed(e.0)),
            |me, c| {
                me.deduped(c, op, &body, |pipe| {
                    for (key, fields) in &adds {
                        let eval = pipe.cmd("EVAL").arg(ADD_FLOORED_LUA).arg(1).arg(key);
                        for (f, d) in fields {
                            eval.arg(f).arg(*d);
                        }
                        eval.ignore();
                    }
                })
                .await
            }
        )
    }

    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        let body = format!("add_metering_batch:{deltas:?}");
        let deltas = deltas.to_vec();
        op!(
            cx,
            self,
            |e: RecordStoreError| Err(OpRefused::Failed(e.0)),
            |me, c| {
                me.deduped(c, op, &body, |pipe| {
                    deltas.iter().for_each(|d| queue_metering(pipe, d))
                })
                .await
            }
        )
    }

    // The base op set and the plane verbs: each body is the store's own, run as one op.
    ops! {
        put_key(key: &VirtualKey => clone) -> () = ValkeyStore::put_key;
        get_key(id: &str => to_owned) -> Option<VirtualKey> = ValkeyStore::get_key;
        list_keys() -> Vec<VirtualKey> = ValkeyStore::list_keys;
        delete_key(id: &str => to_owned) -> () = ValkeyStore::delete_key;
        list_keys_since(since: u64) -> Vec<VirtualKey> = ValkeyStore::list_keys_since;
        get_usage(bucket_id: &str => to_owned, window_start: u64) -> UsageLedger
            = ValkeyStore::get_usage;
        put_usage(bucket_id: &str => to_owned, window_start: u64, ledger: &UsageLedger => clone)
            -> () = ValkeyStore::put_usage;
        list_metering(bucket: u64) -> Vec<MeteringRow> = ValkeyStore::list_metering;
        put_credential(secret: &CredentialSecret => clone) -> () = ValkeyStore::put_credential;
        put_key_with_credential(key: &VirtualKey => clone, secret: &CredentialSecret => clone)
            -> () = ValkeyStore::put_key_with_credential;
        list_credentials(key_id: &str => to_owned) -> Vec<CredentialMeta>
            = ValkeyStore::list_credentials;
        revoke_credential(id: &str => to_owned, reason: &str => to_owned) -> ()
            = ValkeyStore::revoke_credential;
        list_credentials_since(since: u64) -> Vec<CredentialSecret>
            = ValkeyStore::list_credentials_since;
        list_audit() -> Vec<AuditRecord> = ValkeyStore::list_audit;
        add_denylist(sub: &str => to_owned, reason: &str => to_owned) -> ()
            = ValkeyStore::add_denylist;
        list_denylist() -> Vec<String> = ValkeyStore::list_denylist;
        list_audit_tail(limit: u64) -> Vec<AuditRecord> = ValkeyStore::list_audit_tail;
        get_plane_record(kind: &str => to_owned, id: &str => to_owned) -> Option<Vec<u8>>
            = plane::get;
        list_plane_records(kind: &str => to_owned, selector: &PlaneSelector<'_> => to_static)
            -> Vec<Vec<u8>> = plane::list;
        list_plane_record_parents(kind: &str => to_owned) -> Vec<String> = plane::parents;
        purge_plane_records_before(kind: &str => to_owned, before: u64) -> u64
            = plane::purge_before;
        delete_plane_record(kind: &str => to_owned, id: &str => to_owned) -> () = plane::delete;
        redeem_plane_token(kind: &str => to_owned, token: &str => to_owned, expires_at: u64, now: u64)
            -> bool = plane::redeem_token;
        plane_token_live(kind: &str => to_owned, token: &str => to_owned, expires_at: u64, now: u64)
            -> bool = plane::token_live;
    }

    fn upsert_plane_record(
        &self,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        let record = record.to_record();
        op!(cx, self, Err, |me, c| plane::upsert(&me, c, record.view())
            .await)
    }

    fn purge_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
        retention: busbar_contract::records::Retention,
    ) -> Step<RecordStoreResult<u64>> {
        let kind = kind.to_string();
        let terminal_only = retention == busbar_contract::records::Retention::TerminalOnly;
        op!(cx, self, Err, |me, c| plane::purge(
            &me,
            c,
            &kind,
            before,
            terminal_only
        )
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
