// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PLANE-RECORD KEYSPACE (busbar 1.6.0).** The eight kind-tagged verbs over an opaque
//! [`PlaneRecord`](busbar_contract::records::PlaneRecord), plus [`RecordStore::plane_token_live`](busbar_contract::records::RecordStore).
//!
//! ## Layout
//!
//! Every key carries the record KIND as lower-case hex (`K`), so no kind — whatever characters a
//! plane declares it with — can make one kind's key render as another's. Inside a kind, a record's
//! POSITION is `(identity, seq)`, where `identity` is its `parent` when it has one (a chain child: a
//! `task_event`'s task, a `call`'s principal) and its own `id` otherwise (an upserted top-level
//! record: a `task`, a `demotion`). The position is the hash field `F = "<seq>:<identity>"`: `seq` is
//! digits, so the first `:` always ends it and any identity round-trips.
//!
//! - `busbar:plane:K:rec`    HASH  `F` → the typed SIDECAR (see [`sidecar`]); never the body.
//! - `busbar:plane:K:body`   HASH  `F` → the opaque body, verbatim bytes. The store never decodes it.
//! - `busbar:plane:K:byts`   ZSET  `F` scored by `ts` — the retention index `purge` reads.
//! - `busbar:plane:K:idx:I`  ZSET  `F` scored by `seq`, one per identity (`I` = hex identity) — what
//!   a parent's chain listing and an identity's delete read, so neither scans the kind.
//! - `busbar:plane:K:pcount` HASH  identity → how many of its records carry a `parent` — the boot
//!   enumeration of parents (`list_plane_record_parents`), kept exact by every write and removal.
//! - `busbar:plane:K:tok:T`  STRING, `SET NX EX` — one redeemed single-use token (`T` = hex token).
//!
//! ## Why every write is a script
//!
//! Each verb reads the position it is about to write (a replayed append must be told apart from a
//! fork; an overwrite must take its predecessor's index entries with it) and then writes several
//! keys. A client-side read-then-`MULTI` would need a `WATCH` on the kind's whole `rec` hash, so every
//! concurrent writer of a kind — every principal's call log on a busy node, every node of a fleet —
//! would abort every other one. The server runs a script atomically instead: the read and the writes
//! are one step no other client can land between, with no retry loop. The scripts name keys they
//! derive from their arguments, which a standalone or replicated Valkey runs as written; this store
//! does not support Valkey Cluster (its multi-key transactions never did either).
//!
//! ZSET scores are IEEE doubles. They only ever FILTER (retention candidates) or pre-order a
//! listing; every listing is re-sorted by the exact `seq` parsed out of `F`, so a `seq` past 2^53
//! still orders correctly.

use crate::resp::{cmd, pipe, Conn, Script};
use crate::{clamp, hex, ValkeyStore};
use busbar_contract::abi::sdk::store::{OpRefused, OpResult};
use busbar_contract::abi::store::OP_ID_RETENTION_SECS;
use busbar_contract::records::{
    PlaneDisposition, PlaneRecordRef, PlaneSelector, RecordStoreError, RecordStoreResult,
};

/// The kind a purge of which CASCADES: a purged `task` takes its `task_event` chain with it, and only
/// its own. Nothing else ever removes a task's events, so leaving them would keep chains whose task
/// no longer exists forever — outliving the retention decision just made about them. (store-sqlite,
/// store-postgres and store-mysql settle it the same way, and the v6 typed purge here did too.)
const CASCADING_KIND: &str = "task";
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

/// A chain position is `(parent, seq)`; a top-level record is its own `id` at `seq`.
fn identity<'a>(record: &PlaneRecordRef<'a>) -> &'a str {
    record.parent.unwrap_or(record.id)
}

/// THE TYPED SIDECAR — everything about a record except its body, as ONE deterministic string.
///
/// Two leading flag characters the scripts read without decoding anything: `1`/`0` whether the
/// record has a `parent` (what [`Keys::pcount`] counts), then `t`/`a` its disposition (what a
/// terminal-only purge reads). Then the JSON of `{id, parent, seq, ts}` — every field that identifies
/// or orders the record. Deterministic, so a byte comparison of two sidecars is a comparison of the
/// records they describe (the append fork check).
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
    let parented = if record.parent.is_some() { '1' } else { '0' };
    let disposition = match record.disposition {
        PlaneDisposition::Terminal => 't',
        PlaneDisposition::Active => 'a',
    };
    Ok(format!("{parented}{disposition}{json}"))
}

/// Shared Lua: `write(rec, body, byts, idx, pcount, F, sidecar, body, ts, seq, identity)` — put the
/// record at `F`, replacing whatever was there and keeping `pcount` exact across the replacement.
const LUA_WRITE: &str = r"
local function write(rec, body, byts, idx, pcount, f, side, b, ts, seq, ident)
    local old = redis.call('HGET', rec, f)
    if old and string.sub(old, 1, 1) == '1' then
        if redis.call('HINCRBY', pcount, ident, -1) <= 0 then
            redis.call('HDEL', pcount, ident)
        end
    end
    redis.call('HSET', rec, f, side)
    redis.call('HSET', body, f, b)
    redis.call('ZADD', byts, ts, f)
    redis.call('ZADD', idx, seq, f)
    if string.sub(side, 1, 1) == '1' then
        redis.call('HINCRBY', pcount, ident, 1)
    end
end
";

/// UPSERT: `KEYS = rec, body, byts, idx, pcount`; `ARGV = F, sidecar, body, ts, seq, identity`.
static UPSERT: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_WRITE}
        write(KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5],
              ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6])
        return 0"
    ))
});

/// APPEND: as [`UPSERT`], but an occupied position is never overwritten — `0` = written or an
/// identical replay (no write), `1` = a DIFFERENT record already holds the position (a fork).
static APPEND: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_WRITE}
        local old = redis.call('HGET', KEYS[1], ARGV[1])
        if old then
            if old == ARGV[2] and redis.call('HGET', KEYS[2], ARGV[1]) == ARGV[3] then
                return 0
            end
            return 1
        end
        write(KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5],
              ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6])
        return 0"
    ))
});

/// APPEND UNDER AN `op_id` (`slots`): [`APPEND`], deduped on the op's record. `KEYS` as
/// [`APPEND`], then `KEYS[6]` = the op's record (a hash: `b` = the op's value fields, `a` = its
/// answer); `ARGV` as [`APPEND`], then `ARGV[7]` = the op's value fields, `ARGV[8]` = the record's
/// lifetime in seconds. Returns `0` = written, or nothing to write (the op replayed, or the
/// identical record already at the position); `1` = a fork; `2` = the op id was used with different
/// value fields. Only a write records the op, in the same script, so the record and the write are
/// one step: neither is ever seen without the other.
static APPEND_OP: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_WRITE}
        local prior = redis.call('HGET', KEYS[6], 'b')
        if prior then
            if prior == ARGV[7] then
                return 0
            end
            return 2
        end
        local old = redis.call('HGET', KEYS[1], ARGV[1])
        if old then
            if old == ARGV[2] and redis.call('HGET', KEYS[2], ARGV[1]) == ARGV[3] then
                return 0
            end
            return 1
        end
        write(KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5],
              ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6])
        redis.call('HSET', KEYS[6], 'b', ARGV[7], 'a', '')
        redis.call('EXPIRE', KEYS[6], ARGV[8])
        return 0"
    ))
});

/// Shared Lua: `drop_identity(rec, body, byts, pcount, idx, ident)` — remove every record at one
/// identity (every `seq`), its index and its parent count.
const LUA_DROP_IDENTITY: &str = r"
local function drop_identity(rec, body, byts, pcount, idx, ident)
    local fs = redis.call('ZRANGE', idx, 0, -1)
    for _, f in ipairs(fs) do
        redis.call('HDEL', rec, f)
        redis.call('HDEL', body, f)
        redis.call('ZREM', byts, f)
    end
    redis.call('DEL', idx)
    redis.call('HDEL', pcount, ident)
    return #fs
end
";

/// DELETE one identity: `KEYS = rec, body, byts, pcount, idx`; `ARGV = identity`.
static DELETE: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_DROP_IDENTITY}
        return drop_identity(KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5], ARGV[1])"
    ))
});

/// PURGE: `KEYS = rec, body, byts, pcount` of the kind, then (cascade only) `rec, body, byts,
/// pcount` of the cascaded kind; `ARGV = before, terminal_only ('1'|'0'), idx_prefix,
/// cascade_idx_prefix ('' = no cascade)`. Returns how many records OF THE KIND went.
static PURGE: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(&format!(
        "{LUA_DROP_IDENTITY}
        local function tohex(s)
            return (string.gsub(s, '.', function(c) return string.format('%02x', string.byte(c)) end))
        end
        local removed = 0
        local cands = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', '(' .. ARGV[1])
        for _, f in ipairs(cands) do
            local side = redis.call('HGET', KEYS[1], f)
            if not side then
                redis.call('ZREM', KEYS[3], f)
            elseif ARGV[2] ~= '1' or string.sub(side, 2, 2) == 't' then
                local ident = string.sub(f, string.find(f, ':', 1, true) + 1)
                local idx = ARGV[3] .. tohex(ident)
                redis.call('HDEL', KEYS[1], f)
                redis.call('HDEL', KEYS[2], f)
                redis.call('ZREM', KEYS[3], f)
                redis.call('ZREM', idx, f)
                if string.sub(side, 1, 1) == '1' then
                    if redis.call('HINCRBY', KEYS[4], ident, -1) <= 0 then
                        redis.call('HDEL', KEYS[4], ident)
                    end
                end
                removed = removed + 1
                if ARGV[4] ~= '' then
                    drop_identity(KEYS[5], KEYS[6], KEYS[7], KEYS[8], ARGV[4] .. tohex(ident), ident)
                end
            end
        end
        return removed"
    ))
});

// Every plane write runs ONCE on the op's connection, never replayed: a dropped reply on a write is
// not a lost read (the script may well have run), and a blind replay of an upsert is harmless but of
// a purge would under-report its count and of a first append would read its own write back as an
// identical replay. The failure surfaces instead.

/// Put `record` at its position with `script` ([`UPSERT`] or [`APPEND`]); the script's reply.
async fn put(
    store: &ValkeyStore,
    c: &mut Conn,
    script: &Script,
    record: PlaneRecordRef<'_>,
) -> RecordStoreResult<i64> {
    let keys = Keys::of(record.kind);
    let ident = identity(&record);
    let f = field(record.seq, ident);
    let side = sidecar(&record)?;
    let idx = keys.idx(ident);
    with_conn!(store, |c| {
        script
            .key(&keys.rec)
            .key(&keys.body)
            .key(&keys.byts)
            .key(&idx)
            .key(&keys.pcount)
            .arg(&f)
            .arg(&side)
            .arg(record.body)
            .arg(clamp(record.ts))
            .arg(clamp(record.seq))
            .arg(ident)
            .invoke(c)
            .await
    })
}

/// `upsert_plane_record`: UPSERT BY position — a second write for one record replaces it, never
/// stands a rival beside it.
pub(crate) async fn upsert(
    store: &ValkeyStore,
    c: &mut Conn,
    record: PlaneRecordRef<'_>,
) -> RecordStoreResult<()> {
    put(store, c, &UPSERT, record).await.map(|_| ())
}

/// The fork refusal: names the position and nothing else — never stored (or caller) content.
fn fork(record: &PlaneRecordRef<'_>) -> RecordStoreError {
    RecordStoreError(format!(
        "append_plane_record: kind '{}' already holds a different record at sequence {} of \
         this chain; the chain has forked",
        record.kind, record.seq
    ))
}

/// `append_plane_record` under an `op_id` ([`APPEND_OP`]): `op_key` is the op's record, `body` its
/// value fields. A replay or the identical record is `Ok` with nothing written; a different record
/// at the position is the fork the append script refuses; the op id used with different value fields is a
/// conflict.
pub(crate) async fn append_op(
    store: &ValkeyStore,
    c: &mut Conn,
    op_key: &str,
    body: &str,
    record: PlaneRecordRef<'_>,
) -> OpResult<()> {
    let keys = Keys::of(record.kind);
    let ident = identity(&record);
    let f = field(record.seq, ident);
    let side = sidecar(&record).map_err(|e| OpRefused::Failed(e.0))?;
    let idx = keys.idx(ident);
    let answer: i64 = with_conn!(store, |c| {
        APPEND_OP
            .key(&keys.rec)
            .key(&keys.body)
            .key(&keys.byts)
            .key(&idx)
            .key(&keys.pcount)
            .key(op_key)
            .arg(&f)
            .arg(&side)
            .arg(record.body)
            .arg(clamp(record.ts))
            .arg(clamp(record.seq))
            .arg(ident)
            .arg(body)
            .arg(OP_ID_RETENTION_SECS)
            .invoke(c)
            .await
    })
    .map_err(|e| OpRefused::Failed(e.0))?;
    match answer {
        0 => Ok(()),
        1 => Err(OpRefused::Failed(fork(&record).0)),
        _ => Err(OpRefused::Conflict),
    }
}

/// Append `record` only if its position is EMPTY; an occupied one (identical or not) is left as it
/// is. The v6 → v7 migration's write: a record already in the plane keyspace is newer than any v6 row
/// could be, and is never overwritten by one.
pub(crate) async fn append_if_absent(
    store: &ValkeyStore,
    c: &mut Conn,
    record: PlaneRecordRef<'_>,
) -> RecordStoreResult<()> {
    put(store, c, &APPEND, record).await.map(|_| ())
}

/// `get_plane_record`: an upserted record lives at `(id, 0)`. No caller-scoping filter, deliberately:
/// an authorization check in the backend is one an unauthorized reader bypasses by configuring a
/// different backend, so the contract keeps it engine-side.
pub(crate) async fn get(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    id: &str,
) -> RecordStoreResult<Option<Vec<u8>>> {
    let keys = Keys::of(kind);
    with_conn!(store, |c| c.hget(&keys.body, field(0, id)).await)
}

/// One chain listing's read: the positions, then each one's sidecar and body (absent if gone).
type ChainRead = (Vec<String>, Vec<Option<String>>, Vec<Option<Vec<u8>>>);

/// `list_plane_records`. UNFILTERED beyond the selector, terminal rows included: the boot rehydrate
/// wants the active rows, retention the terminal ones and a scoped listing one principal's, and a
/// store that pre-filtered for any one of those would break the other two. Oldest-first by `seq`
/// (then identity, for `All`), the order a chain verifier reads a parent's records in.
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
                .filter_map(|(f, body)| {
                    let (seq, ident) = parse_field(&f)?;
                    Some((seq, ident.to_string(), body))
                })
                .collect()
        }
        PlaneSelector::Parent(parent) => {
            let idx = keys.idx(parent);
            // The sidecars and the bodies are read in ONE atomic step, so a concurrent write can
            // never pair one record's sidecar with another's body; a position the index named but a
            // concurrent delete removed in between reads back absent and is skipped.
            let (fs, sides, bodies): ChainRead = with_conn!(store, |c| {
                let fs: Vec<String> = c.zrange(&idx, 0, -1).await?;
                if fs.is_empty() {
                    return Ok((fs, Vec::new(), Vec::new()));
                }
                let (sides, bodies): (Vec<Option<String>>, Vec<Option<Vec<u8>>>) =
                        // Explicit HMGET: redis-rs's `hget` sends a one-element list as a
                        // scalar HGET, whose reply would not decode as a list.
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
            fs.into_iter()
                .zip(sides)
                .zip(bodies)
                .filter_map(|((f, side), body)| {
                    // Only the records whose `parent` IS this parent: an upserted top-level record
                    // whose own id equals the parent's shares the identity, and is not a child.
                    let side = side?;
                    if !side.starts_with('1') {
                        return None;
                    }
                    let (seq, ident) = parse_field(&f)?;
                    Some((seq, ident.to_string(), body?))
                })
                .collect()
        }
    };
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(rows.into_iter().map(|(_, _, body)| body).collect())
}

/// `list_plane_record_parents`: the boot enumeration — every parent holding at least one record of
/// the kind, exactly once, sorted.
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

/// `purge_plane_records_before`: STRICTLY older than the cutoff, and the count actually performed.
/// WHICH rows go is the kind's own contract, read off the typed disposition, never out of the body:
/// `task` drops only TERMINAL rows (an interrupted task waiting on a human is exactly the row that
/// legitimately sits still longest) and takes each purged task's `task_event` chain with it; every
/// other kind drops every row older than `before`.
pub(crate) async fn purge_before(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    before: u64,
) -> RecordStoreResult<u64> {
    let keys = Keys::of(kind);
    let cascade = (kind == CASCADING_KIND).then(|| Keys::of(CASCADED_KIND));
    let terminal_only = if kind == CASCADING_KIND { "1" } else { "0" };
    let removed: i64 = with_conn!(store, |c| {
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
        inv.arg(clamp(before))
            .arg(terminal_only)
            .arg(&keys.idx_prefix)
            .arg(cascade.as_ref().map_or("", |k| k.idx_prefix.as_str()))
            .invoke(c)
            .await
    })?;
    Ok(removed.max(0) as u64)
}

/// `delete_plane_record`: every `seq` under the identity goes, so a delete can never leave part of a
/// chain behind. Deleting what is not there is a NO-OP, not an error: the engine clears on every
/// observation that agrees with an approval rather than tracking whether it had demoted.
pub(crate) async fn delete(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    id: &str,
) -> RecordStoreResult<()> {
    let keys = Keys::of(kind);
    let idx = keys.idx(id);
    with_conn!(store, |c| {
        DELETE
            .key(&keys.rec)
            .key(&keys.body)
            .key(&keys.byts)
            .key(&keys.pcount)
            .key(&idx)
            .arg(id)
            .invoke::<i64>(c)
            .await
    })
    .map(|_| ())
}

/// The ledger key of one redeemed token of `kind`.
pub(crate) fn token_key(kind: &str, token: &str) -> String {
    format!("{}tok:{}", kind_prefix(kind), hex(token.as_bytes()))
}

/// The longest a redeemed-token entry is kept: an entry whose expiry overflows the server's own
/// millisecond arithmetic is refused outright, and a grant with a decade of life left is one whose
/// ledger entry can be bounded without anyone noticing.
const MAX_TOKEN_TTL_SECS: u64 = 315_360_000; // ten years

/// `redeem_plane_token`: THE TEST AND SET, as ONE `SET NX EX` the server orders against every other
/// node's. It sets and reports OK, or it finds the key present and reports nil — and that reply IS the
/// answer, never a prior read. A `GET` followed by a `SET` would tell both halves of a race they were
/// first, and on this backend a fleet sharing one Valkey is the ORDINARY deployment.
///
/// TTL rather than a caller-run sweep: the entry expires with the grant it records, on the server —
/// which matters here more than on a SQL backend, since this store refuses to run on a server that
/// may evict (`noeviction`), so an unbounded keyspace would be an outage of the whole namespace.
/// `max(1)`: an already-lapsed grant (`expires_at <= now`) still gets a truthful test-and-set answer.
///
/// NO RECONNECT-RETRY: a dropped reply is not a lost read — the SET may have landed, and a blind retry
/// would find its own write and report `false`, refusing a grant this very call recorded. The error
/// surfaces instead, and the engine turns it into a REFUSED redemption; both answers are closed.
pub(crate) async fn redeem_token(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    token: &str,
    expires_at: u64,
    now: u64,
) -> RecordStoreResult<bool> {
    let ttl = expires_at.saturating_sub(now).clamp(1, MAX_TOKEN_TTL_SECS);
    let key = token_key(kind, token);
    let set: Option<String> = with_conn!(store, |c| {
        cmd("SET")
            .arg(&key)
            .arg(expires_at)
            .arg("NX")
            .arg("EX")
            .arg(ttl)
            .query(c)
            .await
    })?;
    Ok(set.is_some())
}

/// `plane_token_live`: MULTI-USE and SPENDS NOTHING — a plain read of the `(kind, token)` upserted
/// record. LIVE means all three: present, still Active, and `now` not past `expires_at`. A missing
/// record holds no capability, a terminal one names work that has finished, and a lapsed one is dead
/// even if nothing finished. Asking twice answers the same twice.
pub(crate) async fn token_live(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    token: &str,
    expires_at: u64,
    now: u64,
) -> RecordStoreResult<bool> {
    if now > expires_at {
        return Ok(false);
    }
    let keys = Keys::of(kind);
    let side: Option<String> = with_conn!(store, |c| c.hget(&keys.rec, field(0, token)).await)?;
    Ok(side.is_some_and(|s| s.as_bytes().get(1) == Some(&b'a')))
}

#[cfg(test)]
#[path = "tests/plane_unit.rs"]
mod unit;
