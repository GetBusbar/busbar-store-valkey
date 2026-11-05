// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 door over [`ValkeyStore`]: `store_door!` and the slots the store v3 table adds to
//! the base op set ([`StoreSlots`]): the `op_id`-carrying writes (the usage and metering batches
//! and the plane-record append) and the kernel's records. The store keeps ledger counts and
//! records, not money: busbar derives money from the counts and its rate card.
//!
//! ## Layout (schema v7, `crate::SCHEMA_VERSION`)
//!
//! - `busbar:op:<hex op_id>`            HASH `b` = the op's body ([`Dedupe`]); expires
//!   [`OP_ID_RETENTION_SECS`] after it is written (S4).
//! - `busbar:records:<hex schema>:k`    ZSET of keys, every score 0, so `ZRANGEBYLEX` reads them in
//!   byte order; `busbar:records:<hex schema>:v` HASH key -> value.
//!
//! ## Dedupe (`abi::store` S1-S4), durable and atomic
//!
//! Usage, metering and append `op_id` writes use ONE server-side script: it returns the body recorded under the op's id
//! and applies nothing, or applies the effect and records the op's body. [`Dedupe::answer`] reads
//! the returned body: a replay answers done, a different op's body a conflict (S1-S3).
//! `append_plane_record`'s script is [`crate::plane`]'s. Conditional records WATCH every schema
//! hash/index and the receipt. Usage corrections WATCH the live key, day index, metering hashes,
//! usage hashes and receipt. Both commit one MULTI/EXEC; condition conflicts write nothing, and
//! lost EXEC answers require exact id/body replay within the existing receipt lifetime.
//!
//! ## Every slot is one op through the host's connector
//!
//! Each slot runs its body with the store SDK's `wire::drive_kept` on one of the store's kept
//! connections: drawn when the op starts (dialled through the host's connector on the op's ticket
//! when none is idle), every command a write and a read that
//! may PEND (the op answers PENDING and is resumed on the connector's wake), handed back when the op
//! answers. The body is the blocking client's body, `async`.

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::column::{clamp, prefix_end, storable_i64};
use busbar_contract::abi::sdk::store::dedupe::Dedupe;
use busbar_contract::abi::sdk::store::wire::drive_kept;
use busbar_contract::abi::sdk::store::{conditional, correction};
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::resp::{cmd, pipe, Conn, RedisError, RedisResult, Script, ScriptInvocation, Value};
use crate::{
    attributed_metering_row, hex, metering_set, plane, usage_fields, usage_key, SecureOwned,
    ValkeyStore, METERING_UNIT_PREFIX, NAME, NEEDS,
};

#[path = "correction.rs"]
mod correction_backend;

busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
    (busbar_contract::abi::sdk::store::rewrap::INTENT, b"1"),
    (conditional::CAPABILITY, b"1"),
    ("busbar.store.count-scale", b"6"),
    (correction::CAPABILITY, correction::CAPABILITY_VALUE),
]);

/// Ops admitted at once: each kept connection serves one, and up to seven more wait on it.
const MAX_INFLIGHT: u32 = 8 * crate::KEPT_CONNECTIONS as u32;

/// The settings accepted by this plugin's lifecycle parser.
const SETTINGS_SCHEMA: busbar_contract::abi::mechanism::call::Blob =
    busbar_contract::abi::mechanism::call::Blob::json(include_bytes!("settings.schema.json"));

busbar_contract::store_door!(
    ValkeyStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    MAX_INFLIGHT,
    needs: NEEDS,
    extensions: EXTENSIONS,
    settings_schema: SETTINGS_SCHEMA
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
                let mut conn = match $me.conn(w, Some("reconnect")).await {
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
    /// Compare one watched pre-state, then write the rows and their applied-only receipt in a
    /// single EXEC. Only a definitive WATCH abort retries here. A transport error never dials
    /// again inside this operation: its caller must reconcile the same op id and fingerprint.
    async fn v3_record_transaction(
        &self,
        c: &mut Conn,
        request: &conditional::Request,
    ) -> OpResult<conditional::Decision> {
        use busbar_contract::abi::sdk::store::dedupe::Seen;
        use conditional::{Decision, Expected, Mutation};

        let receipt = op_key(request.op_id);
        let dedupe = Dedupe::record_transaction(request);
        let mut schemas = std::collections::BTreeMap::new();
        for predicate in &request.predicates {
            schemas
                .entry(predicate.schema.as_str())
                .or_insert_with(|| records_keys(&predicate.schema));
        }
        for mutation in &request.mutations {
            let (schema, _) = mutation.address();
            schemas
                .entry(schema)
                .or_insert_with(|| records_keys(schema));
        }
        let mut watched = vec![receipt.as_str()];
        for (keys, values) in schemas.values() {
            watched.extend([keys.as_str(), values.as_str()]);
        }

        for _ in 0..crate::resp::MAX_TRANSACTION_ATTEMPTS {
            if let Err(error) = crate::resp::cmd("WATCH").arg(&watched).exec(c).await {
                return Err(if error.is_crossslot() {
                    OpRefused::Refused(
                        "record transaction requires keys on one Valkey node; cross-slot keys are unsupported".into(),
                    )
                } else {
                    OpRefused::Failed(self.err(error, "record transaction WATCH").0)
                });
            }
            let mut submitted = false;
            let attempted = crate::resp::rr(async {
                let kind: String = crate::resp::cmd("TYPE").arg(&receipt).query(c).await?;
                if kind != "none" && kind != "hash" {
                    return Ok(Some(Err(OpRefused::Refused(
                        "record transaction receipt has the wrong type".into(),
                    ))));
                }
                let prior: Option<Vec<u8>> = c.hget(&receipt, "b").await?;
                match dedupe.seen(prior.as_deref()) {
                    Seen::Replay => return Ok(Some(Ok(Decision::Applied))),
                    Seen::Conflict => return Ok(Some(Err(OpRefused::Conflict))),
                    Seen::New => {}
                }

                for (keys, values) in schemas.values() {
                    for (key, expected) in [(keys, "zset"), (values, "hash")] {
                        let kind: String = crate::resp::cmd("TYPE").arg(key).query(c).await?;
                        if kind != "none" && kind != expected {
                            return Ok(Some(Err(OpRefused::Refused(
                                "record transaction schema storage has the wrong type".into(),
                            ))));
                        }
                    }
                }
                for predicate in &request.predicates {
                    let (_, values) = &schemas[predicate.schema.as_str()];
                    let actual: Option<Vec<u8>> = c.hget(values, &predicate.key).await?;
                    let matches = match &predicate.expected {
                        Expected::Absent => actual.is_none(),
                        Expected::Bytes(bytes) => actual.as_ref() == Some(bytes),
                    };
                    if !matches {
                        let mut validation = pipe();
                        validation.atomic().cmd("PING").ignore();
                        return validation
                            .query::<Option<()>>(c)
                            .await
                            .map(|stable| stable.map(|()| Ok(Decision::ConditionConflict)));
                    }
                }
                let mut transaction = pipe();
                transaction.atomic();
                for mutation in &request.mutations {
                    let (schema, key) = mutation.address();
                    let (keys, values) = &schemas[schema];
                    match mutation {
                        Mutation::Put { value, .. } => {
                            transaction
                                .hset(values, key, value)
                                .ignore()
                                .zadd(keys, key, 0)
                                .ignore();
                        }
                        Mutation::Delete { .. } => {
                            transaction
                                .cmd("HDEL")
                                .arg(values)
                                .arg(key)
                                .ignore()
                                .cmd("ZREM")
                                .arg(keys)
                                .arg(key)
                                .ignore();
                        }
                        Mutation::DeleteRange {
                            prefix,
                            exact_key_length,
                            ..
                        } => {
                            let length = usize::try_from(*exact_key_length).map_err(|_| {
                                crate::resp::RedisError::refused(
                                    "record range key length is not representable",
                                )
                            })?;

                            let members = range_members(c, keys, values, prefix, length).await?;
                            for member in members.into_iter().filter(|member| {
                                member.len() == length && member.starts_with(prefix)
                            }) {
                                transaction
                                    .cmd("HDEL")
                                    .arg(values)
                                    .arg(&member)
                                    .ignore()
                                    .cmd("ZREM")
                                    .arg(keys)
                                    .arg(&member)
                                    .ignore();
                            }
                        }
                    }
                }
                transaction
                    .hset(&receipt, "b", &dedupe.body()[..])
                    .ignore()
                    .cmd("EXPIRE")
                    .arg(&receipt)
                    .arg(OP_ID_RETENTION_SECS)
                    .ignore();
                submitted = true;
                transaction
                    .query::<Option<()>>(c)
                    .await
                    .map(|committed| committed.map(|()| Ok(Decision::Applied)))
            })
            .await;
            match attempted {
                Ok(None) => continue,
                Ok(Some(answer)) => {
                    if c.watching() {
                        crate::resp::cmd("UNWATCH").exec(c).await.map_err(|error| {
                            OpRefused::Failed(self.err(error, "record transaction UNWATCH").0)
                        })?;
                    }
                    return answer;
                }
                Err(error) => {
                    if !error.is_connection_error() && c.watching() {
                        let _ = crate::resp::cmd("UNWATCH").exec(c).await;
                    }
                    return Err(if error.is_refusal() || !submitted {
                        OpRefused::Refused(self.err(error, "record transaction before EXEC").0)
                    } else {
                        OpRefused::Failed(
                            self.err(
                                error,
                                "record transaction outcome unknown; replay exact id and body",
                            )
                            .0,
                        )
                    });
                }
            }
        }
        Err(OpRefused::Failed(
            "record transaction contention exhausted; replay the same id and body".into(),
        ))
    }

    /// `record_put` (slot 26): an upsert on `(schema, key)`. An EMPTY value removes the row:
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
        scan_pairs(flat)
    }
}

/// A page of `record_scan`: `KEYS = key set, values`; `ARGV = min, max, limit`. One script, so a
/// strike between the key range and the values cannot shorten the page. Returns `key, value` pairs
/// flat; an indexed key missing its value is corruption, refused rather than a false short page.
static SCAN_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(
        r"
        local keys = redis.call('ZRANGEBYLEX', KEYS[1], ARGV[1], ARGV[2], 'LIMIT', 0, ARGV[3])
        local out = {}
        for i = 1, #keys, 1000 do
            local j = math.min(i + 999, #keys)
            local vals = redis.call('HMGET', KEYS[2], unpack(keys, i, j))
            for n = i, j do
                if not vals[n - i + 1] then
                    return redis.error_reply('record_scan: an indexed record value is missing')
                end
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
local function is_i64(s)
    local neg = string.sub(s, 1, 1) == '-'
    local digits = neg and string.sub(s, 2) or s
    if not (string.match(digits, '^[1-9]%d*$') or (not neg and digits == '0')) then
        return false
    end
    local limit = neg and '9223372036854775808' or MAX
    if #digits ~= #limit then
        return #digits < #limit
    end
    return digits <= limit
end
local function bad_field(key, field)
    local v = redis.call('HGET', key, field)
    if v and not is_i64(v) then
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

/// Exact decimal arithmetic for unsigned usage counters. Only individual decimal digits enter
/// Lua arithmetic; whole counters never pass through Lua's floating-point number representation.
/// This matches `UsageLedger::apply_delta`: saturating unsigned addition and zero-floored refunds.
const LUA_USAGE_COUNTS: &str = r"
local USAGE_MAX = '18446744073709551615'
local RADIX = 10
local ZERO_BYTE = string.byte('0')
local function usage_cmp(a, b)
    if #a ~= #b then return #a < #b and -1 or 1 end
    if a == b then return 0 end
    return a < b and -1 or 1
end
local function is_usage_count(value)
    return (value == '0' or string.match(value, '^[1-9]%d*$'))
        and usage_cmp(value, USAGE_MAX) <= 0
end
local function usage_bad_field(key, field)
    local value = redis.call('HGET', key, field)
    if value and not is_usage_count(value)
        and not (string.sub(value, 1, 1) == '-' and is_i64(value)) then
        return key .. ' field ' .. field .. ' is not an unsigned usage counter'
    end
end
local function usage_add(a, b)
    local i, j, carry, out = #a, #b, 0, {}
    while i > 0 or j > 0 or carry > 0 do
        local left = i > 0 and string.byte(a, i) - ZERO_BYTE or 0
        local right = j > 0 and string.byte(b, j) - ZERO_BYTE or 0
        local sum = left + right + carry
        out[#out + 1] = string.char(ZERO_BYTE + sum % RADIX)
        carry = math.floor(sum / RADIX)
        i, j = i - 1, j - 1
    end
    local result = string.reverse(table.concat(out))
    return usage_cmp(result, USAGE_MAX) > 0 and USAGE_MAX or result
end
local function usage_sub(a, b)
    if usage_cmp(a, b) <= 0 then return '0' end
    local i, j, borrow, out = #a, #b, 0, {}
    while i > 0 do
        local right = j > 0 and string.byte(b, j) - ZERO_BYTE or 0
        local digit = string.byte(a, i) - ZERO_BYTE - right - borrow
        borrow = digit < 0 and 1 or 0
        if digit < 0 then digit = digit + RADIX end
        out[#out + 1] = string.char(ZERO_BYTE + digit)
        i, j = i - 1, j - 1
    end
    return (string.gsub(string.reverse(table.concat(out)), '^0+', ''))
end
local pending_quantities = {}
local function checked_quantity(key, field, delta)
    local fields = pending_quantities[key]
    if not fields then fields = {}; pending_quantities[key] = fields end
    local current = fields[field] or redis.call('HGET', key, field) or '0'
    if not is_usage_count(current) or usage_cmp(current, MAX) > 0 then
        return 'exact quantity is outside the scale-6 range'
    end
    local next
    if string.sub(delta, 1, 1) == '-' then
        next = usage_sub(current, string.sub(delta, 2))
    else
        next = usage_add(current, delta)
    end
    if usage_cmp(next, MAX) > 0 then return 'exact quantity aggregate overflow' end
    fields[field] = next
end
local function usage_apply(key, field, delta)
    local current = redis.call('HGET', key, field) or '0'
    if string.sub(current, 1, 1) == '-' then current = '0' end
    local next
    if string.sub(delta, 1, 1) == '-' then
        next = usage_sub(current, string.sub(delta, 2))
    else
        next = usage_add(current, delta)
    end
    redis.call('HSET', key, field, next)
end
";

/// `add_usage_batch`: per cell `KEYS[k]` = its usage hash; `ARGV` from 4 = per cell `n`, then `n`
/// `field, delta` pairs. ARGV[3] refuses fresh reserved-adjustment writes after receipt lookup.
/// Validate every target before applying; exact decimal arithmetic preserves the full u64 range.
static USAGE_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_SEEN}{LUA_USAGE_COUNTS}
        if ARGV[3] == '1' then
            return {{'refused', 'reserved adjustment rows require atomic usage correction'}}
        end
        local a = 4
        for k = 2, #KEYS do
            local n = tonumber(ARGV[a])
            local why = bad_key(KEYS[k], 'hash')
            for i = a + 1, a + 2 * n - 1, 2 do
                why = why or usage_bad_field(KEYS[k], ARGV[i])
                if ARGV[i] ~= 'requests' and ARGV[i] ~= 'billable_requests' then
                    why = why or checked_quantity(KEYS[k], ARGV[i], ARGV[i + 1])
                end
            end
            if why then
                return {{'refused', why}}
            end
            a = a + 1 + 2 * n
        end
        a = 4
        for k = 2, #KEYS do
            local n = tonumber(ARGV[a])
            for i = a + 1, a + 2 * n - 1, 2 do
                usage_apply(KEYS[k], ARGV[i], ARGV[i + 1])
            end
            a = a + 1 + 2 * n
        end
        {LUA_RECORD}"
    ))
});

/// `add_metering_batch`: per delta `KEYS[k], KEYS[k + 1]` = its bucket's set and its row; `ARGV`
/// from 3 = per delta the six counters, `n`, `n` `unit field, count` pairs, then `key_id`, `model`,
/// `provider`, `priced_from_ms`, `key_group_at_use`, `pricing_version`. The row joins its set,
/// every count is an `HINCRBY` pinned at `i64::MAX`, the attribution snapshot is in the row key
/// (including empty values). Validate-then-apply as [`USAGE_OP`].
static METERING_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_SEEN}{LUA_USAGE_COUNTS}
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
        walk(function(set, row, f, delta)
            why = why or bad_key(set, 'set') or bad_key(row, 'hash') or bad_field(row, f)
            if f ~= 'requests' and f ~= 'billable_requests' then
                why = why or checked_quantity(row, f, delta)
            end
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
            redis.call('HSET', row, 'key_group_at_use', ARGV[a + 4])
            redis.call('HSET', row, 'pricing_version', ARGV[a + 5])
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
                        [Value::Data(tag), Value::Data(why)] if tag.as_slice() == b"refused" => {
                            Err(OpRefused::Refused(
                                String::from_utf8_lossy(why).into_owned(),
                            ))
                        }
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
    const USAGE_CORRECTION: bool = true;

    fn apply_usage_correction(
        &self,
        cx: &mut Op<'_>,
        request: &correction::Request,
    ) -> Step<OpResult<correction::Decision>> {
        if let Err(error) = request.encode() {
            return Step::Ready(Err(OpRefused::Refused(error.into())));
        }
        let request = request.clone();
        op!(
            cx,
            self,
            |error: RecordStoreError| Err(OpRefused::Failed(error.0)),
            |me, c| me.v3_usage_correction(c, &request).await
        )
    }

    const RECORD_TRANSACTION: bool = true;

    fn record_transaction(
        &self,
        cx: &mut Op<'_>,
        request: &conditional::Request,
    ) -> Step<OpResult<conditional::Decision>> {
        if let Err(error) = request.validate() {
            return Step::Ready(Err(OpRefused::Refused(error.into())));
        }
        let request = request.clone();
        op!(
            cx,
            self,
            |error: RecordStoreError| Err(OpRefused::Failed(error.0)),
            |me, c| me.v3_record_transaction(c, &request).await
        )
    }

    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    fn validate(settings: &[u8]) -> Result<(), String> {
        Self::from_settings(settings).map(drop)
    }

    fn open_with_secrets(
        settings: &[u8],
        secrets: &[&[u8]],
        _host: Option<Host>,
    ) -> Result<Self, String> {
        Self::from_settings_lent(settings, secrets)
    }

    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        let me = self.clone();
        let pool = me.pool().clone();
        drive_kept(cx, &pool, move |w| {
            Box::pin(async move {
                me.connect_step(w)
                    .await
                    .map_err(|e| format!("valkey store: failed to connect: {}", e.0))
            })
        })
    }

    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        if let Err(e) = storable_i64("append_plane_record", "seq", record.seq) {
            return Step::Ready(Err(OpRefused::Refused(e.0)));
        }
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
        let mut normalized = cells.to_vec();
        for (_, _, delta) in &mut normalized {
            if let Err(error) = delta.normalize_scale6() {
                return Step::Ready(Err(OpRefused::Refused(error.to_string())));
            }
        }
        let cells = &normalized;
        let mut inv = op_call(&USAGE_OP, op, &d);

        inv.arg(
            if cells
                .iter()
                .any(|(bucket, _, _)| correction::reserved_bucket(bucket))
            {
                1
            } else {
                0
            },
        );
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
        for m in deltas {
            if let Err(e) = storable_i64("add_metering_batch", "priced_from_ms", m.priced_from_ms) {
                return Step::Ready(Err(OpRefused::Refused(e.0)));
            }
        }
        let d = Dedupe::metering(deltas);
        let mut normalized = deltas.to_vec();
        for delta in &mut normalized {
            if let Err(error) = delta.normalize_scale6() {
                return Step::Ready(Err(OpRefused::Refused(error.to_string())));
            }
        }
        let deltas = &normalized;
        let mut inv = op_call(&METERING_OP, op, &d);
        for m in deltas {
            inv.key(metering_set(m.bucket)).key(attributed_metering_row(
                m.bucket,
                &m.key_id,
                &m.model,
                &m.provider,
                m.priced_from_ms,
                &m.key_group_at_use,
                &m.pricing_version,
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
        purge_usage_before(before: u64) -> u64 = ValkeyStore::purge_usage_before;
        list_metering(bucket: u64) -> Vec<MeteringRow> = ValkeyStore::list_metering;
        put_credential(secret: &CredentialSecret => secure_owned) -> () = ValkeyStore::put_credential;
        rewrap_credential(expected: &CredentialSecret => secure_owned, replacement: &str => secure_owned)
            -> bool = ValkeyStore::rewrap_credential;
        put_key_with_credential(key: &VirtualKey => clone, secret: &CredentialSecret => secure_owned)
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
        if let Err(e) = storable_i64("upsert_plane_record", "seq", record.seq) {
            return Step::Ready(Err(e));
        }
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
        let terminal_only = matches!(retention, busbar_contract::records::Retention::TerminalOnly);
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

/// Decode the flat scan reply without copying owned key/value payloads or hiding corruption.
fn scan_pairs(flat: Vec<Option<Vec<u8>>>) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
    if !flat.len().is_multiple_of(2) {
        return Err("record_scan: odd-length reply".into());
    }
    let mut rows = Vec::with_capacity(flat.len() / 2);
    let mut values = flat.into_iter();
    while let (Some(key), Some(value)) = (values.next(), values.next()) {
        let key = key.ok_or("record_scan: missing key")?;
        let value = value.ok_or("record_scan: missing value")?;
        rows.push((key, record(value)?));
    }
    Ok(rows)
}

#[cfg(test)]
#[path = "tests/scan_pairs.rs"]
mod scan_pairs_tests;

type HashFields = Vec<(Vec<u8>, Vec<u8>)>;

/// Collect only matching names, including values whose ordered index is damaged.
async fn range_members(
    c: &mut Conn,
    keys: &str,
    values: &str,
    prefix: &[u8],
    length: usize,
) -> RedisResult<std::collections::BTreeSet<Vec<u8>>> {
    let min = [b"[".as_slice(), prefix].concat();
    let max =
        prefix_end(prefix).map_or_else(|| b"+".to_vec(), |end| [b"(".as_slice(), &end].concat());
    let indexed: Vec<Vec<u8>> = cmd("ZRANGEBYLEX")
        .arg(keys)
        .arg(min)
        .arg(max)
        .query(c)
        .await?;
    let mut members: std::collections::BTreeSet<_> = indexed
        .into_iter()
        .filter(|key| key.len() == length)
        .collect();
    let mut bytes = members
        .iter()
        .fold(0usize, |n, key| n.saturating_add(key.len()));
    let mut pattern = Vec::new();
    for byte in prefix {
        if b"*?[]\\".contains(byte) {
            pattern.push(b'\\');
        }
        pattern.push(*byte);
    }
    pattern.push(b'*');
    let mut cursor = String::from("0");
    for _ in 0..crate::resp::MAX_SCAN_PAGES {
        let (next, fields): (String, HashFields) = cmd("HSCAN")
            .arg(values)
            .arg(&cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(1000)
            .query(c)
            .await?;
        for (key, _) in fields {
            if key.len() == length && key.starts_with(prefix) && !members.contains(&key) {
                bytes = bytes.saturating_add(key.len());
                if bytes > crate::resp::MAX_REPLY_BYTES
                    || members.len() >= crate::resp::MAX_REPLY_ELEMENTS as usize
                {
                    return Err(RedisError::refused(
                        "record range exceeds the collected-key limit",
                    ));
                }
                members.insert(key);
            }
        }
        if next == "0" {
            return Ok(members);
        }
        cursor = next;
    }
    Err(RedisError::refused(
        "record range SCAN exceeded the page limit",
    ))
}

#[cfg(test)]
#[path = "settings_schema_tests.rs"]
mod settings_schema_tests;
