// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **The plane-record keyspace.** The eight kind-tagged verbs over an opaque

use crate::resp::{pipe, Conn, Script, ScriptInvocation, Value};
use crate::{hex, ValkeyStore};
use busbar_contract::abi::sdk::store::column::clamp;
use busbar_contract::abi::sdk::store::fork;
use busbar_contract::abi::sdk::store::{OpRefused, OpResult};
use busbar_contract::abi::store::OP_ID_RETENTION_SECS;
use busbar_contract::records::{
    PlaneDisposition, PlaneRecordRef, PlaneSelector, RecordStoreError, RecordStoreResult,
};

/// Reserved kernel ticket records carry their absolute expiry in ts (governance::tickets).
const TICKET_RECORD_KIND: &str = "ticket";

/// The kind a purge of which CASCADES: a purged `task` takes its `task_event` chain with it, and only
pub(crate) const CASCADING_KIND: &str = "task";
/// The child kind a [`CASCADING_KIND`] purge takes with it.
const CASCADED_KIND: &str = "task_event";

/// The key prefix every key of `kind` shares.
fn kind_prefix(kind: &str) -> String {
    format!("busbar:plane:{}:", hex(kind.as_bytes()))
}

/// The keys of one kind.
struct Keys {
    rec: String,
    body: String,
    byts: String,
    pcount: String,
    /// `idx:` — an identity's index key is this plus the hex identity.
    idx_prefix: String,
}

impl Keys {
    fn of(kind: &str) -> Self {
        let p = kind_prefix(kind);
        Keys {
            rec: format!("{p}rec"),
            body: format!("{p}body"),
            byts: format!("{p}byts"),
            pcount: format!("{p}pcount"),
            idx_prefix: format!("{p}idx:"),
        }
    }

    fn idx(&self, identity: &str) -> String {
        format!("{}{}", self.idx_prefix, hex(identity.as_bytes()))
    }
}

/// A record's position field `F` — see the module doc.
fn field(seq: u64, identity: &str) -> String {
    format!("{seq}:{identity}")
}

/// `(seq, identity)` out of a position field, the inverse of [`field`].
fn parse_field(f: &str) -> Option<(u64, &str)> {
    let (seq, identity) = f.split_once(':')?;
    Some((seq.parse().ok()?, identity))
}

/// An APPENDED record's identity: a chain position is `(parent, seq)`; a top-level record is its
fn identity<'a>(record: &PlaneRecordRef<'a>) -> &'a str {
    record.parent.unwrap_or(record.id)
}

/// The typed sidecar — everything about a record except its body, as ONE deterministic string.
fn sidecar(record: &PlaneRecordRef<'_>) -> RecordStoreResult<String> {
    #[derive(serde::Serialize)]
    struct Sidecar<'a> {
        id: &'a str,
        parent: Option<&'a str>,
        seq: u64,
        ts: u64,
    }
    let json = serde_json::to_string(&Sidecar {
        id: record.id,
        parent: record.parent,
        seq: record.seq,
        ts: record.ts,
    })
    .map_err(|e| RecordStoreError(format!("plane record sidecar encode: {e}")))?;
    let parented = if record.parent.is_some() {
        PARENTED
    } else {
        '0'
    };
    let disposition = match record.disposition {
        PlaneDisposition::Terminal => TERMINAL,
        PlaneDisposition::Active => ACTIVE,
    };
    Ok(format!("{parented}{disposition}{json}"))
}

/// The sidecar's first flag: the record names a parent.
const PARENTED: char = '1';
/// The sidecar's second flag: the record is terminal / active (the Lua reads `'t'` at position 2).
const TERMINAL: char = 't';
const ACTIVE: char = 'a';
/// The sidecar's flag characters precede its JSON.
const FLAGS: usize = 2;

/// Whether a sidecar's disposition flag says the record is still active.
fn is_active(side: &str) -> bool {
    side.chars().nth(1) == Some(ACTIVE)
}

/// The parent a sidecar names. A non-parented row is distinct from a corrupt sidecar.
fn parent_of(side: &str) -> RecordStoreResult<Option<String>> {
    #[derive(serde::Deserialize)]
    struct Named {
        parent: Option<String>,
    }
    let bad = || RecordStoreError("list_plane_records: a stored sidecar does not decode".into());
    if !matches!(side.get(..FLAGS), Some("0a" | "0t" | "1a" | "1t")) {
        return Err(bad());
    }
    let named: Named =
        serde_json::from_str(side.get(FLAGS..).ok_or_else(bad)?).map_err(|_| bad())?;
    if side.starts_with(PARENTED) != named.parent.is_some() {
        return Err(bad());
    }
    Ok(named.parent)
}

/// Shared Lua: a record's PARENT LINK. A record that names a parent is counted under that parent in
const LUA_LINK: &str = r"
local function tohex(s)
    return (string.gsub(s, '.', function(c) return string.format('%02x', string.byte(c)) end))
end
local function parent_of(side)
    if string.sub(side, 1, 1) ~= '1' then
        return ''
    end
    return cjson.decode(string.sub(side, 3)).parent
end
local function unlink(pcount, idx, prefix, f, side)
    local p = parent_of(side)
    if p == '' then
        return
    end
    if redis.call('HINCRBY', pcount, p, -1) <= 0 then
        redis.call('HDEL', pcount, p)
    end
    local pidx = prefix .. tohex(p)
    if pidx ~= idx then
        redis.call('ZREM', pidx, f)
    end
end
";

/// Shared Lua: `write(rec, body, byts, idx, pcount, F, sidecar, body, ts, seq, parent, prefix)` —
const LUA_WRITE: &str = r"
local function require_type(key, want)
    local t = redis.call('TYPE', key)
    t = type(t) == 'table' and t.ok or t
    if t ~= 'none' and t ~= want then
        error(key .. ' is not a ' .. want)
    end
end
local function checked_parent(side)
    local ok, value = pcall(cjson.decode, string.sub(side, 3))
    local flag = string.sub(side, 1, 1)
    local disposition = string.sub(side, 2, 2)
    if not ok or type(value) ~= 'table'
        or (disposition ~= 'a' and disposition ~= 't') then
        error('invalid plane sidecar')
    end
    if flag == '0' and value.parent == cjson.null then
        return ''
    end
    if flag == '1' and type(value.parent) == 'string' then
        return value.parent
    end
    error('invalid plane sidecar parent')
end
local function check_count(key, parent, delta)
    if parent == '' then return end
    local v = redis.call('HGET', key, parent)
    if not v then return end
    local neg = string.sub(v, 1, 1) == '-'
    local digits = neg and string.sub(v, 2) or v
    local limit = neg and '9223372036854775808' or '9223372036854775807'
    if not (string.match(digits, '^[1-9]%d*$') or (not neg and digits == '0'))
        or #digits > #limit or (#digits == #limit and digits > limit) then
        error('plane parent count is not an integer')
    end
    if (delta == -1 and v == '-9223372036854775808')
        or (delta == 1 and v == '9223372036854775807') then
        error('plane parent count would overflow')
    end
end
local function write(rec, body, byts, idx, pcount, f, side, b, ts, seq, parent, prefix)
    -- Scripts do not roll back on error: validate every target before unlinking or writing.
    require_type(rec, 'hash')
    require_type(body, 'hash')
    require_type(byts, 'zset')
    require_type(idx, 'zset')
    require_type(pcount, 'hash')
    if checked_parent(side) ~= parent then error('plane parent mismatch') end
    if not tonumber(ts) or not tonumber(seq) then error('invalid plane score') end
    local old = redis.call('HGET', rec, f)
    local old_parent = old and checked_parent(old) or ''
    if old_parent ~= '' then
        require_type(prefix .. tohex(old_parent), 'zset')
        check_count(pcount, old_parent, -1)
    end
    if parent ~= '' then
        require_type(prefix .. tohex(parent), 'zset')
        -- Replacing the same parent's link decrements it before incrementing it.
        check_count(pcount, parent, old_parent == parent and 0 or 1)
    end
    if old then
        unlink(pcount, idx, prefix, f, old)
    end
    redis.call('HSET', rec, f, side)
    redis.call('HSET', body, f, b)
    redis.call('ZADD', byts, ts, f)
    redis.call('ZADD', idx, seq, f)
    if parent ~= '' then
        redis.call('HINCRBY', pcount, parent, 1)
        local pidx = prefix .. tohex(parent)
        if pidx ~= idx then
            redis.call('ZADD', pidx, seq, f)
        end
    end
end
";

/// UPSERT: `KEYS = rec, body, byts, idx, pcount`; `ARGV = F, sidecar, body, ts, seq, parent,
static UPSERT: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_LINK}{LUA_WRITE}
        write(KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5],
              ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6], ARGV[7])
        return 0"
    ))
});

/// APPEND: as [`UPSERT`], but an occupied position is never overwritten — `0` = written or an
static APPEND: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_LINK}{LUA_WRITE}
        local old = redis.call('HGET', KEYS[1], ARGV[1])
        if old then
            if old == ARGV[2] and redis.call('HGET', KEYS[2], ARGV[1]) == ARGV[3] then
                return 0
            end
            return 1
        end
        write(KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5],
              ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6], ARGV[7])
        return 0"
    ))
});

/// APPEND UNDER AN `op_id` (`slots`): [`APPEND`], deduped on the op's record. `KEYS` as
static APPEND_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_LINK}{LUA_WRITE}
        local prior = redis.call('HGET', KEYS[6], 'b')
        if prior then
            return prior
        end
        local old = redis.call('HGET', KEYS[1], ARGV[1])
        if old then
            if old == ARGV[2] and redis.call('HGET', KEYS[2], ARGV[1]) == ARGV[3] then
                redis.call('HSET', KEYS[6], 'b', ARGV[8])
                redis.call('EXPIRE', KEYS[6], ARGV[9])
                return 0
            end
            return 1
        end
        write(KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5],
              ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6], ARGV[7])
        redis.call('HSET', KEYS[6], 'b', ARGV[8])
        redis.call('EXPIRE', KEYS[6], ARGV[9])
        return 0"
    ))
});

/// Shared Lua: `drop_identity(rec, body, byts, pcount, idx, ident, prefix)` — remove every record
const LUA_DROP_IDENTITY: &str = r"
local function drop_identity(rec, body, byts, pcount, idx, ident, prefix)
    local fs = redis.call('ZRANGE', idx, 0, -1)
    local n = 0
    for _, f in ipairs(fs) do
        local separator = string.find(f, ':', 1, true)
        if separator and string.sub(f, separator + 1) == ident then
            local side = redis.call('HGET', rec, f)
            if side then
                unlink(pcount, idx, prefix, f, side)
            end
            redis.call('HDEL', rec, f)
            redis.call('HDEL', body, f)
            redis.call('ZREM', byts, f)
            redis.call('ZREM', idx, f)
            n = n + 1
        end
    end
    return n
end
";

/// DELETE one identity: `KEYS = rec, body, byts, pcount, idx`, then (cascade only) the same five of
static DELETE: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_LINK}{LUA_DROP_IDENTITY}
        local n = drop_identity(KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5], ARGV[1], ARGV[2])
        if ARGV[3] ~= '' then
            drop_identity(KEYS[6], KEYS[7], KEYS[8], KEYS[9], KEYS[10], ARGV[1], ARGV[3])
        end
        return n"
    ))
});

/// PURGE, one batch: `KEYS = rec, body, byts, pcount` of the kind, then (cascade only) `rec, body,
static PURGE: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_LINK}{LUA_DROP_IDENTITY}
        local before = ARGV[1]
        if ARGV[7] == '{TICKET_RECORD_KIND}' then
            local stamp = {SHARED_TIME_COMMAND}
            local now = stamp[1]
            if not now or not string.match(now, '^%d+$') then error('ticket server clock is not an unsigned epoch') end
            if #now < #before or (#now == #before and now < before) then before = now end
        end
        local removed = 0
        local kept = 0
        local cands = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', before,
                                 'LIMIT', ARGV[5], ARGV[6])
        for _, f in ipairs(cands) do
            local side = redis.call('HGET', KEYS[1], f)
            local ts = side and string.match(side, ',\"ts\":(%d+)}}$')
            if not side then
                redis.call('ZREM', KEYS[3], f)
            elseif ts and string.find(f, ':', 1, true)
                and (#ts < #before or (#ts == #before and ts < before))
                and (ARGV[2] ~= '1' or string.sub(side, 2, 2) == 't') then
                local ident = string.sub(f, string.find(f, ':', 1, true) + 1)
                local idx = ARGV[3] .. tohex(ident)
                redis.call('HDEL', KEYS[1], f)
                redis.call('HDEL', KEYS[2], f)
                redis.call('ZREM', KEYS[3], f)
                redis.call('ZREM', idx, f)
                unlink(KEYS[4], idx, ARGV[3], f, side)
                removed = removed + 1
                if ARGV[4] ~= '' then
                    drop_identity(KEYS[5], KEYS[6], KEYS[7], KEYS[8], ARGV[4] .. tohex(ident),
                                  ident, ARGV[4])
                end
            else
                kept = kept + 1
            end
        end
        return {{removed, kept, #cands}}"
    ))
});

/// A write script's call for `record`: `KEYS = rec, body, byts, idx, pcount`; `ARGV = F, sidecar,
fn write_call<'s>(
    script: &'s Script,
    record: &PlaneRecordRef<'_>,
    ident: &str,
) -> RecordStoreResult<ScriptInvocation<'s>> {
    let keys = Keys::of(record.kind);
    let mut inv = script.key(&keys.rec);
    inv.key(&keys.body)
        .key(&keys.byts)
        .key(keys.idx(ident))
        .key(&keys.pcount)
        .arg(field(record.seq, ident))
        .arg(sidecar(record)?)
        .arg(record.body)
        .arg(clamp(record.ts))
        .arg(clamp(record.seq))
        .arg(record.parent.unwrap_or(""))
        .arg(&keys.idx_prefix);
    Ok(inv)
}

/// Put `record` at `ident`'s position with `script` ([`UPSERT`] or [`APPEND`]); the script's reply.
async fn put(
    store: &ValkeyStore,
    c: &mut Conn,
    script: &Script,
    record: PlaneRecordRef<'_>,
    ident: &str,
) -> RecordStoreResult<i64> {
    let inv = write_call(script, &record, ident)?;
    with_conn_no_retry!(store, |c| inv.invoke(c).await)
}

/// The `seq` an upserted record is stored at: the contract upserts by `(kind, id)` and reads there.
const UPSERT_SEQ: u64 = 0;

/// `upsert_plane_record`: UPSERT BY `(kind, id)`, parent or not — a second write for one id
pub(crate) async fn upsert(
    store: &ValkeyStore,
    c: &mut Conn,
    record: PlaneRecordRef<'_>,
) -> RecordStoreResult<()> {
    let record = PlaneRecordRef {
        seq: UPSERT_SEQ,
        ..record
    };
    put(store, c, &UPSERT, record, record.id).await.map(|_| ())
}

/// `append_plane_record` under an `op_id` ([`APPEND_OP`]): `op_key` is the op's record, `body` its
pub(crate) async fn append_op(
    store: &ValkeyStore,
    c: &mut Conn,
    op_key: &str,
    body: &[u8],
    record: PlaneRecordRef<'_>,
) -> OpResult<Option<Vec<u8>>> {
    let mut inv =
        write_call(&APPEND_OP, &record, identity(&record)).map_err(|e| OpRefused::Failed(e.0))?;
    inv.key(op_key).arg(body).arg(OP_ID_RETENTION_SECS);
    let answer: Value =
        with_conn_no_retry!(store, |c| inv.invoke(c).await).map_err(|e| OpRefused::Failed(e.0))?;
    match answer {
        Value::Data(prior) => Ok(Some(prior)),
        Value::Int(0) => Ok(None),
        Value::Int(1) => Err(OpRefused::Failed(
            fork::chain_fork(record.kind, identity(&record), record.seq).0,
        )),
        other => Err(OpRefused::Failed(format!(
            "valkey command: the append script answered a {}",
            other.shape()
        ))),
    }
}

/// Append `record` only if its position is EMPTY; an occupied one (identical or not) is left as it
pub(crate) async fn append_if_absent(
    store: &ValkeyStore,
    c: &mut Conn,
    record: PlaneRecordRef<'_>,
) -> RecordStoreResult<bool> {
    put(store, c, &APPEND, record, identity(&record))
        .await
        .map(|forked| forked == 1)
}

/// `get_plane_record`: an upserted record lives at `(id, 0)`. No caller-scoping filter, deliberately:
pub(crate) async fn get(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    id: &str,
) -> RecordStoreResult<Option<Vec<u8>>> {
    let keys = Keys::of(kind);
    with_conn!(store, |c| c.hget(&keys.body, field(UPSERT_SEQ, id)).await)
}

/// One chain listing's read: the positions, then each one's sidecar and body (absent if gone).
type ChainRead = (Vec<String>, Vec<Option<String>>, Vec<Option<Vec<u8>>>);

/// `list_plane_records`. UNFILTERED beyond the selector, terminal rows included: the boot rehydrate
pub(crate) async fn list(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    selector: &PlaneSelector<'_>,
) -> RecordStoreResult<Vec<Vec<u8>>> {
    let keys = Keys::of(kind);
    let mut rows: Vec<(u64, String, Vec<u8>)> = match selector {
        PlaneSelector::All => {
            let all: Vec<(String, Vec<u8>)> = with_conn!(store, |c| c.hgetall(&keys.body).await)?;
            all.into_iter()
                .map(|(f, body)| {
                    let (seq, ident) = parse_field(&f).ok_or_else(|| {
                        RecordStoreError(
                            "list_plane_records: a stored position does not parse".into(),
                        )
                    })?;
                    Ok((seq, ident.to_string(), body))
                })
                .collect::<RecordStoreResult<Vec<_>>>()?
        }
        PlaneSelector::Parent(parent) => {
            let idx = keys.idx(parent);

            let (fs, sides, bodies): ChainRead = with_conn!(store, |c| {
                let fs: Vec<String> = c.zrange(&idx, 0, -1).await?;
                if fs.is_empty() {
                    return Ok((fs, Vec::new(), Vec::new()));
                }
                let (sides, bodies): (Vec<Option<String>>, Vec<Option<Vec<u8>>>) =
                        // Explicit HMGET: `resp::Conn::hget` sends HGET, which takes exactly one
                        // field; reading a list of fields needs HMGET.
                        pipe()
                            .atomic()
                            .cmd("HMGET")
                            .arg(&keys.rec)
                            .arg(&fs)
                            .cmd("HMGET")
                            .arg(&keys.body)
                            .arg(&fs)
                            .query(c).await?;
                Ok((fs, sides, bodies))
            })?;
            let mut rows = Vec::new();
            for ((f, side), body) in fs.into_iter().zip(sides).zip(bodies) {
                let (side, body) = match (side, body) {
                    (None, None) => continue,
                    (Some(side), Some(body)) => (side, body),
                    _ => {
                        return Err(RecordStoreError(
                            "list_plane_records: a stored row is missing its sidecar or body"
                                .into(),
                        ))
                    }
                };
                let (seq, ident) = parse_field(&f).ok_or_else(|| {
                    RecordStoreError("list_plane_records: a stored position does not parse".into())
                })?;

                if parent_of(&side)?.as_deref() == Some(&**parent) {
                    rows.push((seq, ident.to_string(), body));
                }
            }
            rows
        }
    };
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(rows.into_iter().map(|(_, _, body)| body).collect())
}

/// `list_plane_record_parents`: the boot enumeration — every parent holding at least one record of
pub(crate) async fn parents(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
) -> RecordStoreResult<Vec<String>> {
    let keys = Keys::of(kind);
    let counts: Vec<(String, i64)> = with_conn!(store, |c| c.hgetall(&keys.pcount).await)?;
    let mut out: Vec<String> = counts
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(p, _)| p)
        .collect();
    out.sort();
    Ok(out)
}

/// `purge_plane_records_before`, the age-only entry: `task` has always dropped only its TERMINAL
pub(crate) async fn purge_before(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    before: u64,
) -> RecordStoreResult<u64> {
    purge(store, c, kind, before, kind == CASCADING_KIND).await
}

/// Candidates one purge script call examines, so no call holds the server for a whole backlog.
const PURGE_BATCH: usize = 1000;

/// `purge_plane_records`: STRICTLY older than the cutoff, and the count actually performed. WHICH
pub(crate) async fn purge(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    before: u64,
    terminal_only: bool,
) -> RecordStoreResult<u64> {
    let keys = Keys::of(kind);
    let cascade = (kind == CASCADING_KIND).then(|| Keys::of(CASCADED_KIND));
    let terminal_only = if terminal_only { "1" } else { "0" };
    let mut removed = 0u64;
    let mut offset = 0u64;
    loop {
        let answer: Vec<i64> = with_conn_no_retry!(store, |c| {
            let mut inv = PURGE.key(&keys.rec);
            inv.key(&keys.body).key(&keys.byts).key(&keys.pcount);
            match &cascade {
                Some(k) => {
                    inv.key(&k.rec).key(&k.body).key(&k.byts).key(&k.pcount);
                }
                None => {
                    // Unused placeholders keep the script's KEYS positions fixed.
                    inv.key(&keys.rec)
                        .key(&keys.body)
                        .key(&keys.byts)
                        .key(&keys.pcount);
                }
            }
            inv.arg(before)
                .arg(terminal_only)
                .arg(&keys.idx_prefix)
                .arg(cascade.as_ref().map_or("", |k| k.idx_prefix.as_str()))
                .arg(offset)
                .arg(PURGE_BATCH)
                .arg(kind)
                .invoke(c)
                .await
        })?;
        let [gone, kept, seen] = answer[..] else {
            return Err(RecordStoreError(format!(
                "valkey command: the purge script answered {answer:?}"
            )));
        };
        removed += gone.max(0) as u64;
        offset += kept.max(0) as u64;
        if seen < PURGE_BATCH as i64 {
            return Ok(removed);
        }
    }
}

/// `delete_plane_record`: every `seq` under the identity goes, so a delete can never leave part of a
pub(crate) async fn delete(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    id: &str,
) -> RecordStoreResult<()> {
    let keys = Keys::of(kind);
    let idx = keys.idx(id);
    let cascade = (kind == CASCADING_KIND).then(|| Keys::of(CASCADED_KIND));
    with_conn_no_retry!(store, |c| {
        let mut inv = DELETE.key(&keys.rec);
        inv.key(&keys.body)
            .key(&keys.byts)
            .key(&keys.pcount)
            .key(&idx);
        if let Some(k) = &cascade {
            inv.key(&k.rec)
                .key(&k.body)
                .key(&k.byts)
                .key(&k.pcount)
                .key(k.idx(id));
        }
        inv.arg(id)
            .arg(&keys.idx_prefix)
            .arg(cascade.as_ref().map_or("", |k| k.idx_prefix.as_str()))
            .invoke::<i64>(c)
            .await
    })
    .map(|_| ())
}

/// Token receipt namespace; both encoded components exclude delimiter collisions.
pub(crate) const TOKEN_PATTERN: &str = "busbar:plane:*:tok:*";

/// The ledger key of one redeemed token of `kind`.
pub(crate) fn token_key(kind: &str, token: &str) -> String {
    format!("{}tok:{}", kind_prefix(kind), hex(token.as_bytes()))
}

/// The longest life a redeemed-token entry is given an expiry for: the server refuses an `EX` that
const MAX_TOKEN_TTL_SECS: u64 = 315_360_000;

const SHARED_TIME_COMMAND: &str = "redis.call('TIME')";

/// Token decisions compare canonical unsigned decimal strings, exact past 2^53.
fn token_expiry_script(body: &str) -> Script {
    Script::new(&format!(
        r"
        local function decimal(value)
            if not value or not string.match(value, '^%d+$') then return nil end
            local canonical = string.gsub(value, '^0+', '')
            return canonical == '' and '0' or canonical
        end
        local function before(a, b)
            if #a ~= #b then return #a < #b end
            return a < b
        end
        local function add(a, b)
            local i, j, carry, out = #a, #b, 0, ''
            while i > 0 or j > 0 or carry > 0 do
                local x = i > 0 and tonumber(string.sub(a, i, i)) or 0
                local y = j > 0 and tonumber(string.sub(b, j, j)) or 0
                local sum = x + y + carry
                out = tostring(sum % 10) .. out
                carry = math.floor(sum / 10)
                i, j = i - 1, j - 1
            end
            return out
        end
        local stamp = {SHARED_TIME_COMMAND}
        local now = decimal(stamp[1])
        if not now then error('token server clock is not an unsigned epoch') end
        local cleanup_limit = add(now, '{MAX_TOKEN_TTL_SECS}')
        local function set_token(key, expires, absent_only)
            local cleanup = add(expires, '1')
            local bounded = not before(cleanup_limit, cleanup)
            if absent_only then
                if bounded then return redis.call('SET', key, expires, 'NX', 'EXAT', cleanup) end
                return redis.call('SET', key, expires, 'NX')
            end
            if bounded then return redis.call('SET', key, expires, 'EXAT', cleanup) end
            return redis.call('SET', key, expires)
        end
        {body}
    "
    ))
}

/// Move a v6 receipt atomically. Its old relative TTL never shortens the absolute grant expiry.
pub(crate) static MIGRATE_SPENT_TOKEN: std::sync::LazyLock<Script> = std::sync::LazyLock::new(
    || {
        token_expiry_script(&format!(
            r"
        local value = redis.call('GET', KEYS[1])
        if not value then return 0 end
        local expires = decimal(value)
        if not expires then
            local life = redis.call('TTL', KEYS[1])
            if life >= 0 and life <= {MAX_TOKEN_TTL_SECS} then expires = add(now, tostring(math.max(life, 1)))
            else expires = '{permanent}' end
        end
        set_token(KEYS[2], expires, true)
        redis.call('DEL', KEYS[1])
        return 1
    ",
            permanent = i64::MAX
        ))
    },
);
/// Non-consuming preflight for the reserved ticket record: its terminal deadline must match.
static TICKET_LIVE: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    token_expiry_script(&format!(
        r#"
        local expires = ARGV[2]
        if before(expires, now) then return 0 end
        local side = redis.call('HGET', KEYS[1], ARGV[1])
        if not side or string.sub(side, {FLAGS}, {FLAGS}) ~= '{TERMINAL}' then return 0 end
        local valid, record = pcall(cjson.decode, string.sub(side, {FLAGS} + 1))
        if not valid or type(record) ~= 'table' then return 0 end
        local ts = string.match(side, ',"ts":(%d+)}}$')
        return ts == expires and 1 or 0
    "#
    ))
});

static REDEEM: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    token_expiry_script(
        r"
        local expires = ARGV[1]
        if before(expires, now) then return 0 end
        local cur = redis.call('GET', KEYS[1])
        if cur then
            local canonical = decimal(cur)
            if not canonical or not before(canonical, now) then return 0 end
        end
        set_token(KEYS[1], expires, false)
        return 1
    ",
    )
});

/// `redeem_plane_token`: the test and set, as ONE script the server orders against every other
pub(crate) async fn redeem_token(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    token: &str,
    expires_at: u64,
    _now: u64,
) -> RecordStoreResult<bool> {
    let key = token_key(kind, token);
    let redeemed: i64 =
        with_conn_no_retry!(store, |c| REDEEM.key(&key).arg(expires_at).invoke(c).await)?;
    Ok(redeemed == 1)
}

/// `plane_token_live`: MULTI-USE and SPENDS NOTHING — a plain read of the `(kind, token)` upserted
pub(crate) async fn token_live(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    token: &str,
    expires_at: u64,
    now: u64,
) -> RecordStoreResult<bool> {
    if kind == TICKET_RECORD_KIND {
        let keys = Keys::of(kind);
        let live: i64 = with_conn!(store, |c| TICKET_LIVE
            .key(&keys.rec)
            .arg(field(UPSERT_SEQ, token))
            .arg(expires_at)
            .invoke(c)
            .await)?;
        return Ok(live == 1);
    }
    if now > expires_at {
        return Ok(false);
    }
    let keys = Keys::of(kind);
    let side: Option<String> =
        with_conn!(store, |c| c.hget(&keys.rec, field(UPSERT_SEQ, token)).await)?;
    Ok(side.is_some_and(|s| is_active(&s)))
}

/// Repair cleanup left by caller-clock writers without changing their stored expiry value.
pub(crate) static REPAIR_TOKEN_EXPIRY: std::sync::LazyLock<Script> =
    std::sync::LazyLock::new(|| {
        token_expiry_script(
            r"
        local value = redis.call('GET', KEYS[1])
        if not value then return 0 end
        local expires = decimal(value)
        if not expires then
            redis.call('PERSIST', KEYS[1])
            return 0
        end
        local cleanup = add(expires, '1')
        if before(cleanup_limit, cleanup) then
            redis.call('PERSIST', KEYS[1])
        else
            redis.call('EXPIREAT', KEYS[1], cleanup)
        end
        return 1
    ",
        )
    });

#[cfg(test)]
#[path = "tests/plane_unit.rs"]
mod unit;
