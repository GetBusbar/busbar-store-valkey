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
//! Each slot runs its body with the store SDK's `wire::drive_kept` on one of the store's kept
//! connections: drawn when the op starts (dialled through the host's connector on the op's ticket
//! when none is idle), every command a write and a read that
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

use crate::resp::{pipe, Conn, Script, ScriptInvocation, Value};
use crate::{
    hex, metering_row, metering_set, plane, usage_fields, usage_key, ValkeyStore,
    METERING_UNIT_PREFIX, NAME, NEEDS,
};

// `url` is reference-capable, not secret: a `{env:}`/`{file:}`/`{module:}` reference resolves in
// place (a 1.5.5 `url: {env: VAR}` keeps booting) and a literal passes as written.
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

/// Ops admitted at once: each kept connection serves one, and up to seven more wait on it.
const MAX_INFLIGHT: u32 = 8 * crate::KEPT_CONNECTIONS as u32;

busbar_contract::store_door!(
    ValkeyStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    MAX_INFLIGHT,
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
        let mut inv = SCAN_OP.key(&k);
        inv.key(&v).arg(&min).arg(&max).arg(limit);
        let flat: Vec<Option<Vec<u8>>> =
            with_conn!(self, |c| inv.invoke(c).await).map_err(|e| e.0)?;
        flat.chunks(2)
            .filter_map(|kv| Some((kv.first()?.clone()?, kv.get(1)?.clone()?)))
            .map(|(key, value)| Ok((key, record(value)?)))
            .collect()
    }
}

/// A page of `record_scan`: `KEYS = key set, values`; `ARGV = min, max, limit`. One script, so a
/// strike between the key range and the values cannot shorten the page. Returns `key, value` pairs
/// flat (a key whose value is gone answers nil, and is dropped by the caller).
static SCAN_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(
        r"
        local keys = redis.call('ZRANGEBYLEX', KEYS[1], ARGV[1], ARGV[2], 'LIMIT', 0, ARGV[3])
        local out = {}
        for i = 1, #keys, 1000 do
            local j = math.min(i + 999, #keys)
            local vals = redis.call('HMGET', KEYS[2], unpack(keys, i, j))
            for n = i, j do
                out[#out + 1] = keys[n]
                out[#out + 1] = vals[n - i + 1]
            end
        end
        return out",
    )
});

/// The start of an `op_id` write's script: `KEYS[1]` is the op's record; a recorded body is
/// returned and nothing applies. Then the helpers the two scripts share.
const LUA_SEEN: &str = r"
local prior = redis.call('HGET', KEYS[1], 'b')
if prior then
    return prior
end
local MAX = '9223372036854775807'
local function bad_key(key, want)
    local t = redis.call('TYPE', key)
    t = type(t) == 'table' and t.ok or t
    if t ~= 'none' and t ~= want then
        return key .. ' is not a ' .. want
    end
end
local function bad_field(key, field)
    if redis.call('HGET', key, field) and not pcall(redis.call, 'HINCRBY', key, field, 0) then
        return key .. ' field ' .. field .. ' is not an integer'
    end
end
local function add_pinned(key, field, delta)
    local ok, v = pcall(redis.call, 'HINCRBY', key, field, delta)
    if ok then
        return v
    end
    if string.find(type(v) == 'table' and v.err or tostring(v), 'overflow', 1, true) then
        redis.call('HSET', key, field, MAX)
        return nil
    end
    error(v)
end
";

/// The end of an `op_id` write's script: record the body (`ARGV[1]`) for `ARGV[2]` seconds. It
/// runs only after every cell is applied, so a recorded op is a fully applied one. The script
/// answers a refusal as `{'refused', text}` before anything is written.
const LUA_RECORD: &str = r"
redis.call('HSET', KEYS[1], 'b', ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[2])
return false
";

/// `add_usage_batch`: per cell `KEYS[k]` = its usage hash; `ARGV` from 3 = per cell `n`, then `n`
/// `field, delta` pairs. VALIDATE, THEN APPLY: every key must be a hash (or absent) and every
/// field it adds to absent or an integer, else the batch is refused with nothing written or
/// recorded; the apply then cannot fail. ADD-THEN-FLOOR: each field is `HINCRBY`'d and, below 0,
/// pinned to 0; a counter a v6 build left negative reads as the 0 it always reported. An add past
/// `i64::MAX` pins there. The add stays an integer `HINCRBY` (Lua numbers are doubles and would
/// round counters past 2^53), and the overflow is read off its error, which is exact.
static USAGE_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_SEEN}
        local a = 3
        for k = 2, #KEYS do
            local n = tonumber(ARGV[a])
            local why = bad_key(KEYS[k], 'hash')
            for i = a + 1, a + 2 * n - 1, 2 do
                why = why or bad_field(KEYS[k], ARGV[i])
            end
            if why then
                return {{'refused', why}}
            end
            a = a + 1 + 2 * n
        end
        a = 3
        for k = 2, #KEYS do
            local n = tonumber(ARGV[a])
            for i = a + 1, a + 2 * n - 1, 2 do
                local cur = redis.call('HGET', KEYS[k], ARGV[i])
                if cur and tonumber(cur) < 0 then
                    redis.call('HSET', KEYS[k], ARGV[i], 0)
                end
                local v = add_pinned(KEYS[k], ARGV[i], ARGV[i + 1])
                if v and v < 0 then
                    redis.call('HSET', KEYS[k], ARGV[i], 0)
                end
            end
            a = a + 1 + 2 * n
        end
        {LUA_RECORD}"
    ))
});

/// `add_metering_batch`: per delta `KEYS[k], KEYS[k + 1]` = its bucket's set and its row; `ARGV`
/// from 3 = per delta the six counters, `n`, `n` `unit field, count` pairs, then `key_id`, `model`,
/// `provider`, `priced_from_ms`, `key_group_at_use`, `pricing_version`. The row joins its set,
/// every count is an `HINCRBY` pinned at `i64::MAX`, the attribution snapshot is first-write-wins
/// (`HSETNX`). Validate-then-apply as [`USAGE_OP`].
static METERING_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_SEEN}
        local counters = {{'tokens_input', 'tokens_output', 'tokens_cache_read',
                          'tokens_cache_write', 'requests', 'billable_requests'}}
        local function walk(count, finish)
            local a = 3
            for k = 2, #KEYS, 2 do
                local row = KEYS[k + 1]
                for i, f in ipairs(counters) do
                    count(KEYS[k], row, f, ARGV[a + i - 1])
                end
                local n = tonumber(ARGV[a + 6])
                a = a + 7
                for _ = 1, n do
                    count(KEYS[k], row, ARGV[a], ARGV[a + 1])
                    a = a + 2
                end
                finish(KEYS[k], row, a)
                a = a + 6
            end
        end
        local why
        walk(function(set, row, f)
            why = why or bad_key(set, 'set') or bad_key(row, 'hash') or bad_field(row, f)
        end, function() end)
        if why then
            return {{'refused', why}}
        end
        walk(function(_, row, f, n)
            add_pinned(row, f, n)
        end, function(set, row, a)
            redis.call('SADD', set, row)
            redis.call('HSET', row, 'key_id', ARGV[a], 'model', ARGV[a + 1], 'provider', ARGV[a + 2])
            redis.call('HSET', row, 'priced_from_ms', ARGV[a + 3])
            redis.call('HSETNX', row, 'key_group_at_use', ARGV[a + 4])
            redis.call('HSETNX', row, 'pricing_version', ARGV[a + 5])
        end)
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
    /// Run an `op_id` write's script once (a lost reply may have applied): the body it found, or
    /// its refusal (decided before anything was written).
    fn deduped(
        &self,
        cx: &mut Op<'_>,
        inv: ScriptInvocation<'static>,
    ) -> Step<OpResult<Option<Vec<u8>>>> {
        op!(
            cx,
            self,
            |e: RecordStoreError| Err(OpRefused::Failed(e.0)),
            |me, c| {
                let answer: Value = with_conn_no_retry!(me, |c| inv.invoke(c).await)
                    .map_err(|e| OpRefused::Failed(e.0))?;
                match answer {
                    Value::Data(prior) => Ok(Some(prior)),
                    Value::Nil => Ok(None),
                    Value::Array(r) => match r.as_slice() {
                        [_, Value::Data(why)] => Err(OpRefused::Refused(format!(
                            "valkey command: {}",
                            String::from_utf8_lossy(why)
                        ))),
                        _ => Err(OpRefused::Failed(
                            "valkey command: a malformed refusal".into(),
                        )),
                    },
                    other => Err(OpRefused::Failed(format!(
                        "valkey command: the script answered a {}",
                        other.shape()
                    ))),
                }
            }
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
