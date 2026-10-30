// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 door over [`ValkeyStore`]: `store_door!` and the slots the store v3 table adds to
//! the base op set ([`StoreSlots`]): the `op_id`-carrying writes (the usage and metering batches
//! and the plane-record append) and the kernel's records. The store keeps ledger counts and
//! records, not money: busbar derives money from the counts and its rate card.
//!
//! ## Layout (schema v9, `crate::SCHEMA_VERSION`)
//!
//! - `busbar:op:<hex op_id>`            HASH `b` = the op's body ([`Dedupe`]); expires
//!   [`OP_ID_RETENTION_SECS`] after it is written (S4).
//! - `busbar:records:<hex schema>:k`    ZSET of keys, every score 0, so `ZRANGEBYLEX` reads them in
//!   byte order; `busbar:records:<hex schema>:v` HASH key -> value.
//!
//! ## Dedupe (`abi::store` S1-S4), durable and atomic
//!
//! Every `op_id` write is ONE server-side script: it returns the body recorded under the op's id
//! and applies nothing, or applies the effect and records the op's body. [`Dedupe::answer`] reads
//! the returned body: a replay answers done, a different op's body a conflict (S1-S3).
//! `append_plane_record`'s script is [`crate::plane`]'s.
//!
//! ## Every slot is one op through the host's connector
//!
//! Each slot runs its body with the store SDK's `wire::drive_kept` on the store's ONE kept
//! connection: drawn when the op starts (dialled through the
//! host's connector on the op's ticket when there is none), every command a write and a read that
//! may PEND (the op answers PENDING and is resumed on the connector's wake), handed back when the op
//! answers. The body is the blocking client's body, `async`.

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::column::{clamp, prefix_end};
use busbar_contract::abi::sdk::store::dedupe::Dedupe;
use busbar_contract::abi::sdk::store::wire::drive_kept;
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::resp::{cmd, pipe, Conn, Script, ScriptInvocation};
use crate::{
    hex, metering_row, metering_set, plane, usage_fields, usage_key, ValkeyStore,
    METERING_UNIT_PREFIX, NAME, NEEDS,
};

// `url` is reference-capable, not secret: a `{env:}`/`{file:}`/`{module:}` reference resolves in
// place (a 1.5.5 `url: {env: VAR}` keeps booting) and a literal passes as written.
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

/// The start of an `op_id` write's script: `KEYS[1]` is the op's record; a recorded body is
/// returned and nothing applies.
const LUA_SEEN: &str = r"
local prior = redis.call('HGET', KEYS[1], 'b')
if prior then
    return prior
end
local failed
";

/// The end of an `op_id` write's script: record the body (`ARGV[1]`) for `ARGV[2]` seconds. A
/// failed command fails the op but leaves the rest applied and the op recorded, so a retry replays
/// instead of applying twice.
const LUA_RECORD: &str = r"
redis.call('HSET', KEYS[1], 'b', ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[2])
if failed then
    return redis.error_reply(type(failed) == 'table' and failed.err or tostring(failed))
end
return false
";

/// `add_usage_batch`: per cell `KEYS[k]` = its usage hash; `ARGV` from 3 = per cell `n`, then `n`
/// `field, delta` pairs. ADD-THEN-FLOOR: each field is `HINCRBY`'d and, below 0, pinned to 0; a
/// counter a v6 build left negative (its unfloored HINCRBY) reads as the 0 it always reported. The
/// add stays an integer HINCRBY (Lua numbers are doubles and would round counters past 2^53).
static USAGE_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_SEEN}
        local function add_floored(key, from, n)
            for i = from, from + 2 * n - 2, 2 do
                local cur = redis.call('HGET', key, ARGV[i])
                if cur and tonumber(cur) < 0 then
                    redis.call('HSET', key, ARGV[i], 0)
                end
                if redis.call('HINCRBY', key, ARGV[i], ARGV[i + 1]) < 0 then
                    redis.call('HSET', key, ARGV[i], 0)
                end
            end
        end
        local a = 3
        for k = 2, #KEYS do
            local n = tonumber(ARGV[a])
            local ok, e = pcall(add_floored, KEYS[k], a + 1, n)
            if not ok and not failed then
                failed = e
            end
            a = a + 1 + 2 * n
        end
        {LUA_RECORD}"
    ))
});

/// `add_metering_batch`: per delta `KEYS[k], KEYS[k + 1]` = its bucket's set and its row; `ARGV`
/// from 3 = per delta the six counters, `n`, `n` `unit field, count` pairs, then `key_id`, `model`,
/// `provider`, `priced_from_ms`, `key_group_at_use`, `pricing_version`. The row joins its set,
/// every count is an `HINCRBY`, the attribution snapshot is first-write-wins (`HSETNX`).
static METERING_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_SEEN}
        local function run(...)
            local r = redis.pcall(...)
            if type(r) == 'table' and r.err and not failed then
                failed = r
            end
        end
        local counters = {{'tokens_input', 'tokens_output', 'tokens_cache_read',
                          'tokens_cache_write', 'requests', 'billable_requests'}}
        local a = 3
        for k = 2, #KEYS, 2 do
            local row = KEYS[k + 1]
            run('SADD', KEYS[k], row)
            for i, f in ipairs(counters) do
                run('HINCRBY', row, f, ARGV[a + i - 1])
            end
            local n = tonumber(ARGV[a + 6])
            a = a + 7
            for _ = 1, n do
                run('HINCRBY', row, ARGV[a], ARGV[a + 1])
                a = a + 2
            end
            run('HSET', row, 'key_id', ARGV[a], 'model', ARGV[a + 1], 'provider', ARGV[a + 2])
            run('HSET', row, 'priced_from_ms', ARGV[a + 3])
            run('HSETNX', row, 'key_group_at_use', ARGV[a + 4])
            run('HSETNX', row, 'pricing_version', ARGV[a + 5])
            a = a + 6
        end
        {LUA_RECORD}"
    ))
});

/// An `op_id` write's script call over the op's record, with the body `d` records.
fn op_call(script: &'static Script, op: OpId, d: &Dedupe<'_>) -> ScriptInvocation<'static> {
    let mut inv = script.key(op_key(op));
    inv.arg(&d.body()[..]).arg(OP_ID_RETENTION_SECS);
    inv
}

impl ValkeyStore {
    /// Run an `op_id` write's script once (a lost reply may have applied): the body it found.
    fn deduped(
        &self,
        cx: &mut Op<'_>,
        inv: ScriptInvocation<'static>,
    ) -> Step<OpResult<Option<Vec<u8>>>> {
        op!(
            cx,
            self,
            |e: RecordStoreError| Err(OpRefused::Failed(e.0)),
            |me, c| with_conn_no_retry!(me, |c| inv.invoke(c).await)
                .map_err(|e| OpRefused::Failed(e.0))
        )
    }
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
        let d = Dedupe::append(record);
        let body = d.body().to_vec();
        let record = record.to_record();
        op!(
            cx,
            self,
            |e: RecordStoreError| Err(OpRefused::Failed(e.0)),
            |me, c| crate::plane::append_op(&me, c, &op_key(op), &body, record.view()).await
        )
        .map(|found| d.answer(found))
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
        let d = Dedupe::usage(cells);
        let mut inv = op_call(&USAGE_OP, op, &d);
        for (bucket, window, delta) in cells {
            let fields = usage_fields(delta);
            inv.key(usage_key(bucket, *window)).arg(fields.len());
            for (f, n) in &fields {
                inv.arg(f).arg(*n);
            }
        }
        self.deduped(cx, inv).map(|found| d.answer(found))
    }

    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        let d = Dedupe::metering(deltas);
        let mut inv = op_call(&METERING_OP, op, &d);
        for m in deltas {
            inv.key(metering_set(m.bucket)).key(metering_row(
                m.bucket,
                &m.key_id,
                &m.model,
                &m.provider,
                m.priced_from_ms,
            ));
            for n in [
                m.tokens_input,
                m.tokens_output,
                m.tokens_cache_read,
                m.tokens_cache_write,
                m.requests,
                m.billable_requests,
            ] {
                inv.arg(clamp(n));
            }
            inv.arg(m.usage_units.len());
            for (class, n) in &m.usage_units {
                inv.arg(format!("{METERING_UNIT_PREFIX}{class}"))
                    .arg(clamp(*n));
            }
            inv.arg(&m.key_id)
                .arg(&m.model)
                .arg(&m.provider)
                .arg(m.priced_from_ms)
                .arg(&m.key_group_at_use)
                .arg(&m.pricing_version);
        }
        self.deduped(cx, inv).map(|found| d.answer(found))
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

#[cfg(test)]
#[path = "tests/slots_unit.rs"]
mod unit;
