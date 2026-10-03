// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Valkey** backend for busbar's durable governance store — the
//! shared, multi-node `db` plugin over a KEY-VALUE data model. It serves the store v3 door
//! (`busbar_contract::abi::sdk::store`) over the HOST'S CONNECTOR, depending only on the
//! `busbar-contract` crate, never on the engine: it speaks RESP2 itself ([`resp`]) and holds no
//! socket, no TLS stack and no runtime of its own (ARCHITECT rulings 2026-10-03 on Q-L14-1 and
//! Q-L16-2).
//!
//! Valkey is what busbar ships and documents: the Linux-Foundation-governed, BSD-licensed store the
//! ecosystem standardized on. The only remnants of the pre-fork name in this crate are the `url://`
//! scheme strings operators already write (`redis://` / `rediss://`, with `valkey://` /
//! `valkeys://` read the same) and the upstream driver the TESTS use to verify Valkey independently.
//!
//! ## Schema v5 — the generic-credentials redesign
//!
//! `AwsCredential`/`aws_credentials` (a type/table that only ever held SigV4 credentials, discovered
//! mid-audit to be vendor-shaped rather than designed) is replaced by a kind-polymorphic
//! `CredentialMeta`/`CredentialSecret` — see `busbar_contract::records` for the full rationale.
//! `VirtualKey` gains `deleted_at` (tombstone, not hard-delete — see [`RecordStore::delete_key`]'s doc)
//! and `revision`
//! (a store-global monotonic counter for incremental hydration).
//!
//! - **virtual keys** — `busbar:key:<id>` holds the JSON [`VirtualKey`] (now carrying `deleted_at`/
//!   `revision`); `busbar:keys` indexes every id (`list_keys` is unfiltered — including tombstones,
//!   per the trait's own contract, since a hydrator must observe a tombstone to evict cached
//!   credentials); `busbar:keys:byrev` is a ZSET scored by revision, serving both "all keys" and
//!   "keys since N" (`list_keys_since`).
//! - **credentials** — `busbar:cred:<key_id>:<kind>:<slot>` holds the JSON [`CredentialSecret`]
//!   (meta + secret together; the METADATA-only view the admin/listing surface gets is produced by
//!   discarding `.secret` after decode, never by a separate on-disk shape — so there is no
//!   `SELECT *`-shaped bug possible here, only a decode-then-drop-field bug, which is far easier to
//!   audit). `slot` is `0` or `1`, baked into the key name, so `(key_id, kind, slot)` uniqueness is
//!   a structural property of the keyspace, not an application-level check to get wrong.
//!   `busbar:cred:pub:<kind>:<public_id>` enforces `UNIQUE(kind, public_id)` via `SETNX`.
//!   `busbar:cred:id:<cred_id>` resolves a credential by its own id (`revoke_credential`'s lookup).
//!   `busbar:cred:ids:<key_id>` is a SET of `"<kind>:<slot>"` members, bounding `delete_key`'s fan-out
//!   to a small `SMEMBERS` regardless of how many kinds exist. `busbar:creds:byrev` is the credential
//!   equivalent of `keys:byrev`.
//! - **token ledger** / **metering** / **audit** / **denylist** — unchanged in shape from the prior
//!   schema (see the write-behind/HINCRBY/ZSET reasoning below); metering gains `billable_requests`
//!   (HINCRBY, same as `requests`), `key_group_at_use`/`pricing_version` (`HSETNX` — first-write-wins,
//!   the attribution snapshot at first use of the bucket), and the `tokens_cache_creation` field is
//!   renamed `tokens_cache_write` (a naming-drift fix: identical concept, same as `TierTokens`).
//!
//! ## Schema v7 — busbar 1.6.0
//!
//! - **plane records** — busbar 1.6.0 replaced the protocol-named durable methods (`put_task`,
//!   `append_mcp_call`, `put_mcp_demotion`, `redeem_ask_state`, …) with eight kind-tagged verbs over an
//!   opaque [`PlaneRecord`](busbar_contract::records::PlaneRecord) plus [`RecordStore::plane_token_live`]. ONE keyspace per kind holds every
//!   kind's records (see [`plane`]); the store never decodes a body. The v6 typed task / task-event /
//!   demotion / spent-approval keyspaces are copied into it in place on connect ([`legacy`]).
//! - **usage** — the four reserved units keep their `m:<model>:<tier>` hash fields; every other
//!   (open) unit gets a `u:<hex unit>:<model>` field. `add_usage` floors each counter at 0 server-side.
//! - **metering** — `priced_from_ms` joins the row's identity (a rate-card edit splits the day's
//!   cell); open classes ride as `u:<class>` fields.
//! - **keys** — the contract's own wire carries `idp_subject`/`binding_mode`/`minted_by` and every
//!   scope kind in its own `allowed_{kind}s` field; a v6 row reads back unchanged.
//!
//! ## Atomicity
//!
//! Every multi-key write cascade runs as ONE atomic `MULTI`/`EXEC` pipeline
//! ([`Pipeline::atomic`]), or — where a write's correctness depends on a value read
//! immediately beforehand (credential slot occupancy, `delete_key`'s credential fan-out) — as an
//! optimistic `WATCH`/`MULTI`/`EXEC` transaction (`transaction!`, [`resp`]), so a concurrent mutation of
//! the watched key aborts and retries the whole read+build+EXEC cycle against fresh state rather than
//! racing. `delete_key`'s cascade (tombstone the key row, destroy every credential row + its
//! reverse-lookup pointers, drop the credential-id index) is the highest-stakes of these: a mid-
//! cascade failure must never leave a credential outliving the key it was destroyed for, mirroring
//! the crate's long-standing invariant, now generalized past SigV4 to every credential kind.
//!
//! ## Connections, TLS, reconnect
//!
//! Every op is ONE connection through the host's connector (the store SDK's `wire::drive`): the
//! host dials the URL's `host:port` for the store's one declared `tcp` need (egress class
//! operator-infrastructure), secures it for `rediss://` (the connector's TLS, the need's trust),
//! and the store sends `AUTH` / `SELECT` as the URL says, then its commands; each read that has
//! nothing yet PENDS on the op's ticket and is resumed on the connector's wake. The connection is
//! closed when the op answers. So the 1.5.5 one-shot reconnect-and-retry for idempotent reads is
//! subsumed (every op starts on a fresh connection), and a non-idempotent write is never replayed
//! (a lost reply fails the op; its caller retries under the same `op_id`). `open` parses the
//! settings only; its connect step (`StoreSlots::connect`) makes the first connection, migrates the
//! schema and checks `noeviction`, so an unreachable or misconfigured server still refuses the load
//! at boot in the store's own words. Error strings are scrubbed of the URL password.
//!
//! ## Data growth (documented, deliberate)
//!
//! Rows are written WITHOUT a TTL: usage windows, metering buckets, and audit entries accumulate
//! unboundedly by design — the store is the durable system of record. `purge_windows_before`/
//! `purge_metering_before` are left at the trait's `Ok(0)` default (no obligation to self-bound);
//! operators wanting bounded growth reap old `busbar:usage:*` keys on their own retention schedule.

#![forbid(unsafe_code)]

use busbar_contract::abi::sdk::store::wire::Wire;
use busbar_contract::records::MeteringDelta;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringRow, ModelTokens, PlaneRecordRef,
    PlaneSelector, RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
    RESERVED_UNITS,
};
use resp::{cmd, pipe, Conn, ErrorKind, Pipeline, RedisError, RedisResult};
use std::sync::Arc;
use std::time::Duration;

/// The RESP2 client over the host's connector (the store has no socket of its own).
#[macro_use]
mod resp;

/// `self.with_conn(|c| EXPR)` over the blocking client, now: `EXPR` on the op's one connection
/// `c`, its failure in the store's words (`valkey command: …`, the URL password scrubbed).
macro_rules! with_conn {
    ($me:expr, |$c:ident| $e:expr $(,)?) => {
        $me.ck($crate::resp::rr(async { $e }).await)
    };
}

/// Default connect timeout (`Client::open` + the initial `get_connection`): with no DSN-level
/// escape hatch (unlike postgres's libpq `connect_timeout`), a blackholed/firewalled host would
/// otherwise wedge engine boot indefinitely. `connect_with_timeout` lets a caller override this.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ── Key-space helpers (one namespace prefix so a Valkey shared with other apps never collides) ──
const KEY_PREFIX: &str = "busbar:key:";
const KEYS_INDEX: &str = "busbar:keys";
const KEYS_BYREV: &str = "busbar:keys:byrev";
const CRED_IDS_PREFIX: &str = "busbar:cred:ids:";
const CRED_PUB_PREFIX: &str = "busbar:cred:pub:";
const CRED_ID_PREFIX: &str = "busbar:cred:id:";
const CREDS_BYREV: &str = "busbar:creds:byrev";
const AUDIT_ZSET: &str = "busbar:audit";

// ── THE PLANE-RECORD KEYSPACE (1.6.0) ─────────────────────────────────────────────────────────
//
// Every kind a plane declares (`task`, `task_event`, `call`, `demotion`, …) is stored by the
// kind-neutral verbs in [`plane`]; the single-use token ledger the `redeem_plane_token` verb keeps is
// there too. The v6 typed keyspaces those verbs replaced (`busbar:task:*`, `busbar:tasks*`,
// `busbar:mcp:demotions`, `busbar:askstate:*`) are copied in on connect by [`legacy`]; the v6 MCP
// tool-call log (`busbar:mcp:*`) is left in place, unread (see `legacy`'s doc for why).
mod legacy;
pub mod plane;

/// The signed-token REVOCATION denylist (1.5.0). `busbar:denylist:<sub>` holds the operator reason
/// (a plain string), and `busbar:denylist` is a SET indexing every denied sub so `list_denylist` is
/// a SMEMBERS.
const DENYLIST_PREFIX: &str = "busbar:denylist:";
const DENYLIST_INDEX: &str = "busbar:denylist";
/// The store-global monotonic revision counter (INCR only). Stamped onto `VirtualKey`/`CredentialMeta`
/// rows at write time, driving `list_keys_since`/`list_credentials_since`'s incremental hydration.
const REVISION_KEY: &str = "busbar:revision";
/// The schema-version marker key (mirrors the SQLite `PRAGMA user_version`). v5 (1.5.0 dev) = the
/// generic-credentials redesign: `AwsCredential` -> kind-polymorphic `CredentialMeta`/`CredentialSecret`,
/// `VirtualKey` gains `deleted_at`/`revision`, `delete_key` becomes a tombstone, metering gains
/// `billable_requests`/`key_group_at_use`/`pricing_version` and renames `tokens_cache_creation` to
/// `tokens_cache_write`. A pre-v5 namespace is WIPED on connect (1.5.0 unreleased: bump, not migrate).
///
/// v6 closes a real billing bug in busbarAI core's `GovState::hydrate_budgets`: that function used
/// to infer "legacy pre-split row, needs `billable_requests` seeded from `requests`" from the value
/// shape `billable_requests == 0 && requests > 0` alone — but that exact shape is ALSO what a bucket
/// looks like after a legitimate full refund (`refund_bucket` decrements `billable_requests` but
/// never `requests`, by design), so a restart could silently re-bill correctly-refunded fees. Fixed
/// by removing the value-based guess from `hydrate_budgets` entirely and doing the one-time cutover
/// HERE instead, at a real schema-version boundary, which by construction happens exactly once ever
/// per store. v6 wipes any pre-v6 namespace the SAME way the v5 bump did (1.5.0 is STILL unreleased
/// as of this bump — no real customer has run any pre-v6 build in production, so there is no
/// genuinely-ambiguous refunded-vs-legacy data anywhere to lose). This is a ONE-TIME safe window: the
/// NEXT schema bump after 1.5.0 actually ships must NOT reuse this wipe-on-bump shortcut, since real
/// customer usage/billing history would exist by then and wiping it would itself be a real bug.
/// The durable MCP tool-call log, the durable A2A TASK STORE and the durable TRUST STATE (the MCP
/// demotion record and the spent-approval ledger) all landed WITHOUT bumping this, and that is a
/// deliberate decision rather than an oversight. Each is a PURELY ADDITIVE keyspace
/// (`busbar:mcp:*`, `busbar:task:*`/`busbar:tasks*`, `busbar:askstate:*`): nothing that already
/// exists changes shape, so
/// there is nothing for a migration to do, and a bump here does not mean "migrate" — `migrate()`
/// handles any `version < SCHEMA_VERSION` by SCANning `busbar:*` and DELETING EVERYTHING. Bumping to
/// mark an addition that needs no migration would therefore wipe every operator's virtual keys,
/// credentials, budgets, usage ledgers and audit records on next connect, which is the recorded
/// hazard on this file ("`migrate()` is a wipe, and its safety argument has expired": that wipe's own
/// justification is "1.5.0 is unreleased", and 1.5.0, 1.5.1 and 1.5.2 have all shipped). The version
/// marker moves again only when a migrate-in-place path exists to move it for.
///
/// v7 (busbar 1.6.0) is that path: the typed task / task-event / demotion / spent-approval keyspaces
/// are copied IN PLACE into the kind-neutral plane-record keyspace ([`legacy::migrate_v6_to_v7`]).
/// Nothing a v6 namespace holds is wiped: keys, credentials, usage, metering, audit and the denylist
/// read back unchanged under v7, and the v6 MCP call log stays where it is. Only a namespace OLDER
/// than v6 (a 1.5.0 development build, never released) still takes the wipe below.
const SCHEMA_KEY: &str = "busbar:schema";
const SCHEMA_VERSION: i64 = 7;
/// The last schema that is WIPED rather than migrated when found: anything below it predates the
/// first release. v6 and later are always migrated in place.
const FIRST_MIGRATED_SCHEMA: i64 = 6;

/// Internal sentinel: `delete_key`'s outer retry loop uses this to distinguish "credential
/// membership changed since our watch-set pre-read, restart with a fresh watch set" from a real
/// terminal error. `ErrorKind` has no built-in "retry me" variant, so this is carried in
/// the error message rather than the kind.
const DELETE_KEY_RETRY_SENTINEL: &str = "__internal_delete_key_retry__";

fn usage_key(bucket_id: &str, window_start: u64) -> String {
    format!("busbar:usage:{bucket_id}:{window_start}")
}

fn cred_row_key(key_id: &str, kind: &str, slot: u8) -> String {
    format!("busbar:cred:{key_id}:{kind}:{slot}")
}

fn cred_ids_key(key_id: &str) -> String {
    format!("{CRED_IDS_PREFIX}{key_id}")
}

fn cred_pub_key(kind: &str, public_id: &str) -> String {
    format!("{CRED_PUB_PREFIX}{kind}:{public_id}")
}

fn cred_id_key(cred_id: &str) -> String {
    format!("{CRED_ID_PREFIX}{cred_id}")
}

/// Escape Valkey glob metacharacters (`*`, `?`, `[`, `]`, and the escape character `\` itself)
/// in a value that must match LITERALLY inside a `SCAN MATCH` pattern. Without this, a virtual key id
/// containing one of these characters lets `delete_key`'s cleanup SCAN match keys belonging to OTHER
/// buckets/ids that merely share a glob-matching prefix.
fn escape_glob(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Hash field for one (model, unit) counter in a usage window. The four RESERVED units keep the v6
/// spelling `m:<model>:<tier>` (parsed with a RIGHT split on the tier, so a model name containing `:`
/// still round-trips, and a v6 row reads back unchanged). Every OTHER (open) unit is spelled
/// `u:<hex unit>:<model>`: an open unit name is caller-supplied and may itself contain `:`, and hex
/// has none, so the split is unambiguous whatever the model and unit are.
fn usage_field(model: &str, unit: &str) -> String {
    if RESERVED_UNITS.contains(&unit) {
        format!("m:{model}:{unit}")
    } else {
        format!("u:{}:{model}", hex(unit.as_bytes()))
    }
}

/// Parse a usage-window hash field back into `(model, unit)` — the inverse of [`usage_field`].
/// `None` for the two request counters and anything else that is not a unit field.
fn parse_usage_field(field: &str) -> Option<(String, String)> {
    if let Some(rest) = field.strip_prefix("m:") {
        let (model, tier) = rest.rsplit_once(':')?;
        return Some((model.to_string(), tier.to_string()));
    }
    let rest = field.strip_prefix("u:")?;
    let (unit_hex, model) = rest.split_once(':')?;
    let unit = String::from_utf8(unhex(unit_hex)?).ok()?;
    Some((model.to_string(), unit))
}

/// Lower-case hex of `bytes` — the collision-free spelling of a caller-supplied component inside a
/// key or field name (hex contains no separator character).
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The inverse of [`hex`]; `None` on anything that is not an even-length lower/upper-case hex string.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn metering_set(bucket: u64) -> String {
    format!("busbar:metering:{bucket}")
}
/// Escape `\` and the `|` join delimiter (in that order, so the escape character itself round-trips
/// unambiguously) in one `metering_row` component. Without this, two DISTINCT `(key_id, model,
/// provider)` triples can collide onto the identical joined string whenever a component contains a
/// literal `|` — e.g. `("k", "a|b", "p")` and `("k", "a", "b|p")` both join to `"k|a|b|p"` — merging
/// two logically separate metering rows' HINCRBY'd counters into one. Neither `key_id` (busbar-
/// generated) nor `model`/`provider` (operator-configured lane names, never restricted to a fixed
/// charset anywhere upstream) is guaranteed `|`-free, so this is not a theoretical concern.
fn escape_metering_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '|') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The hash key of one metering cell: `(bucket, key_id, model, provider, priced_from_ms)`.
///
/// `priced_from_ms` joins the identity (DECISIONS #79: a rate-card edit SPLITS the day's cell at the
/// edit, and each half prices at the card it was earned under). A cell whose price started at `0` —
/// the opening entry, and every row written before the field existed — keeps the v6 three-component
/// key, so a v6 cell and a v7 write of the same undated cell are one cell. A dated cell appends a
/// fourth `|<ms>` component. Each component is escaped before joining (see
/// `escape_metering_component`), so the join is injective: an escaped component never contains a bare
/// `|`, so a three-component key and a four-component key can never render the same, and two
/// different identities never share a row.
fn metering_row(
    bucket: u64,
    key_id: &str,
    model: &str,
    provider: &str,
    priced_from_ms: u64,
) -> String {
    let base = format!(
        "busbar:metering:{bucket}:{}|{}|{}",
        escape_metering_component(key_id),
        escape_metering_component(model),
        escape_metering_component(provider)
    );
    match priced_from_ms {
        0 => base,
        ms => format!("{base}|{ms}"),
    }
}

/// The metering-cell hash field an open (non-token) ledgered class accumulates under. Everything after
/// the fixed `u:` prefix is the class name, verbatim, so no class name can collide with a fixed field.
const METERING_UNIT_PREFIX: &str = "u:";

/// Clamp a `u64` into `i64` for Valkey integer ops (HINCRBY is signed) - a value above `i64::MAX` pins
/// to `i64::MAX`, never wraps. Mirrors the SQL backends.
fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a signed counter back as a `u64`, clamping a (corrupt / direct-DB) negative to 0 instead of
/// wrapping via `as` - mirrors the SQL backends' DI-3 posture.
fn read_u64(v: i64) -> u64 {
    v.max(0) as u64
}

/// Extract the PASSWORD component from a valkey URL (`redis://user:pass@host/...` or
/// `redis://:pass@host/...`), if any - the secret that must never appear in an error string.
fn url_password(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let userinfo = rest.rsplit_once('@').map(|(u, _)| u)?;
    let pass = match userinfo.split_once(':') {
        Some((_, p)) => p,
        None => return None, // user only, no password
    };
    (!pass.is_empty()).then(|| pass.to_string())
}

/// Percent-DECODE a URL component (`%40` -> `@`, `%25` -> `%`). A malformed escape is left verbatim.
/// Used so the scrub redacts BOTH the raw (as-written-in-URL) and decoded forms of the password -
/// the valkey driver may surface either in an error string.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Replace every occurrence of `secret` (in BOTH its raw and percent-decoded forms) in `msg` with
/// `<redacted>` - the password-in-error scrub.
fn scrub(msg: String, secret: Option<&str>) -> String {
    let Some(s) = secret.filter(|s| !s.is_empty()) else {
        return msg;
    };
    let mut out = msg;
    if out.contains(s) {
        out = out.replace(s, "<redacted>");
    }
    let decoded = percent_decode(s);
    if decoded != s && !decoded.is_empty() && out.contains(&decoded) {
        out = out.replace(&decoded, "<redacted>");
    }
    out
}

/// ADD-THEN-FLOOR over one hash: `ARGV` is `field, delta` pairs; each field is `HINCRBY`'d and, if
/// the result went below 0, pinned to 0. A counter a v6 build left negative (its unfloored HINCRBY)
/// is read as the 0 it always reported before the add, so the add lands on what readers saw. The add
/// itself stays an integer HINCRBY (Lua numbers are doubles; a read-add-write in Lua would round
/// counters past 2^53). One script, so the server runs every pair atomically — the
/// same guarantee the v6 `MULTI` pipeline gave, plus the per-counter floor the contract's
/// `UsageLedger::apply_delta` specifies.
///
/// The source is also queued as a plain `EVAL` inside an `op_id` write's `MULTI` (`slots`), where
/// an `EVALSHA` could miss a flushed script cache after the transaction had begun.
const ADD_FLOORED_LUA: &str = r"
        for i = 1, #ARGV, 2 do
            local cur = redis.call('HGET', KEYS[1], ARGV[i])
            if cur and tonumber(cur) < 0 then
                redis.call('HSET', KEYS[1], ARGV[i], 0)
            end
            local v = redis.call('HINCRBY', KEYS[1], ARGV[i], ARGV[i + 1])
            if v < 0 then
                redis.call('HSET', KEYS[1], ARGV[i], 0)
            end
        end
        return 0
        ";

/// What the store connects to, parsed once from its settings' URL.
#[derive(Debug, Clone)]
struct Target {
    /// `host:port`, the connection's target on the host's connector.
    addr: String,
    /// The host name (for connection security's name check).
    host: String,
    /// `rediss://` / `valkeys://`: secure the connection before its first byte.
    tls: bool,
    /// `AUTH` (`user`, `password`), when the URL carries a password.
    auth: Option<(Option<String>, String)>,
    /// `SELECT`, when the URL names a database other than 0.
    db: i64,
}

/// The upstream driver's refusal of a URL, word for word (the 1.5.5 boot refusal read so).
fn url_refused(why: &'static str) -> RedisError {
    RedisError::from((ErrorKind::InvalidClientConfig, why))
}

/// Parse a Valkey URL (`redis://[user[:password]@]host[:port][/db]`, `rediss://` for TLS; the
/// `valkey://` / `valkeys://` spellings too), as the upstream driver did.
fn parse_url(url: &str) -> RedisResult<Target> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| url_refused("Redis URL did not parse"))?;
    let tls =
        match scheme {
            "redis" | "valkey" => false,
            "rediss" | "valkeys" => true,
            "redis+unix" | "unix" | "valkey+unix" => return Err(RedisError::from((
                ErrorKind::InvalidClientConfig,
                "Redis URL did not parse",
                "a unix-socket URL is not reachable through the host's connector; use a TCP URL"
                    .to_string(),
            ))),
            _ => return Err(url_refused("Redis URL did not parse")),
        };
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, after) = v6
            .split_once(']')
            .ok_or_else(|| url_refused("Redis URL did not parse"))?;
        (format!("[{h}]"), after.strip_prefix(':'))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (hostport.to_string(), None),
        }
    };
    if host.is_empty() || host == "[]" {
        return Err(url_refused("Missing hostname"));
    }
    let port: u16 = match port {
        None | Some("") => 6379,
        Some(p) => p
            .parse()
            .map_err(|_| url_refused("Redis URL did not parse"))?,
    };
    let auth = match userinfo {
        None => None,
        Some(u) => {
            let (user, pass) = match u.split_once(':') {
                Some((user, pass)) => (user, Some(pass)),
                None => (u, None),
            };
            let user = (!user.is_empty()).then(|| percent_decode(user));
            pass.filter(|p| !p.is_empty())
                .map(|p| (user, percent_decode(p)))
        }
    };
    let db = match path.trim_matches('/') {
        "" => 0,
        d => d
            .parse::<i64>()
            .map_err(|_| url_refused("Invalid database number"))?,
    };
    Ok(Target {
        addr: format!("{host}:{port}"),
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
        tls,
        auth,
        db,
    })
}

/// Valkey `RecordStore` backend (durable, shared across a cluster), reached through the HOST'S
/// CONNECTOR: every op is one connection (dial, secure, `AUTH`, `SELECT`, its commands), closed when
/// the op answers; the store holds no socket, no TLS stack and no connection of its own between ops.
/// The 1.5.5 one-shot reconnect-and-retry for idempotent reads is subsumed: every op starts on a
/// fresh connection.
#[derive(Debug, Clone)]
pub struct ValkeyStore {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    target: Target,
    /// The URL password (if any), scrubbed out of every error string this crate emits.
    secret: Option<String>,
    /// `connect_timeout_ms` as the settings stated it (validated; the connector's need timeout and
    /// the op's deadline bound the dial).
    #[allow(dead_code)]
    connect_timeout: Duration,
}

/// The store's one outbound need: a `tcp` stream to the server the settings' URL names (the store
/// names the target at each connect), governed as operator infrastructure (private, loopback and
/// plaintext allowed). Its timeout bounds the dial (1.5.5's default connect timeout).
pub const NEEDS: &[busbar_contract::abi::host::conn::connector::Need] = {
    use busbar_contract::abi::host::conn::connector::{
        Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
    };
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
    const NONE: AbiStr = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    &[Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
        transport: busbar_contract::abi::sdk::door::abi_str("tcp"),
        auth: NONE,
        target_from: NONE,
        trust_from: NONE,
        details: Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: DEFAULT_CONNECT_TIMEOUT.as_millis() as u64,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    }]
};

/// The need index of [`NEEDS`]' one entry.
const NEED_TCP: u32 = 0;

impl ValkeyStore {
    /// The store for `url` (no connection is made here: every op connects through the host's
    /// connector), with [`DEFAULT_CONNECT_TIMEOUT`].
    ///
    /// # Errors
    /// A URL the store cannot read, in the upstream driver's words.
    pub fn new(url: &str) -> RecordStoreResult<Self> {
        Self::with_timeout(url, DEFAULT_CONNECT_TIMEOUT)
    }

    /// As [`Self::new`], stating the connect timeout.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn with_timeout(url: &str, timeout: Duration) -> RecordStoreResult<Self> {
        let secret = url_password(url);
        let target = parse_url(url).map_err(|e| {
            RecordStoreError(scrub(format!("valkey connect: {e}"), secret.as_deref()))
        })?;
        Ok(Self {
            inner: Arc::new(Inner {
                target,
                secret,
                connect_timeout: timeout,
            }),
        })
    }

    /// ONE OP'S CONNECTION over `wire`: dial the server through the host's connector, secure it for
    /// `rediss://`, `AUTH` and `SELECT` as the URL says.
    async fn conn(&self, wire: Wire) -> RecordStoreResult<Conn> {
        let t = &self.inner.target;
        let failed = |e: String| {
            RecordStoreError(scrub(
                format!("valkey connect: {e}"),
                self.inner.secret.as_deref(),
            ))
        };
        wire.connect(NEED_TCP, Some(&t.addr))
            .await
            .map_err(|e| failed(e.to_string()))?;
        if t.tls {
            wire.upgrade_secure(Some(&t.host))
                .await
                .map_err(|e| failed(e.to_string()))?;
        }
        let mut c = Conn::new(wire);
        if let Some((user, pass)) = &t.auth {
            let mut auth = cmd("AUTH");
            if let Some(u) = user {
                auth.arg(u);
            }
            auth.arg(pass)
                .exec(&mut c)
                .await
                .map_err(|e| failed(e.to_string()))?;
        }
        if t.db != 0 {
            cmd("SELECT")
                .arg(t.db)
                .exec(&mut c)
                .await
                .map_err(|e| failed(e.to_string()))?;
        }
        Ok(c)
    }

    /// `open`'s connect step: the first connection, the schema migration and the noeviction check,
    /// exactly as 1.5.5's connect ran them (its failures are the load's refusal).
    async fn connect_step(&self, wire: Wire) -> RecordStoreResult<()> {
        let mut c = self.conn(wire).await?;
        self.migrate(&mut c).await?;
        self.assert_noeviction(&mut c).await
    }

    /// A command result in the store's words.
    fn ck<T>(&self, r: RedisResult<T>) -> RecordStoreResult<T> {
        r.map_err(|e| self.err(e, "command"))
    }

    /// STARTUP ASSERTION, non-negotiable: `maxmemory-policy` must be `noeviction`. Under any eviction
    /// policy, Valkey can silently evict a denylist entry (un-revoking a compromised key) or a
    /// metering row (destroying billing evidence) under memory pressure, with zero error anywhere in
    /// the request path — the loss is invisible until someone goes looking for data that should be
    /// there. Refuse to start rather than risk it. If `CONFIG GET` itself is disabled by an ACL
    /// (a legitimate hardened deployment), we cannot verify the policy either way — fail loud with a
    /// distinct message rather than silently assuming it's safe.
    async fn assert_noeviction(&self, c: &mut Conn) -> RecordStoreResult<()> {
        let pairs: Vec<(String, String)> = with_conn!(self, |c| {
            cmd("CONFIG")
                .arg("GET")
                .arg("maxmemory-policy")
                .query(c)
                .await
        })?;
        let policy = pairs
            .iter()
            .find(|(k, _)| k == "maxmemory-policy")
            .map(|(_, v)| v.as_str());
        match policy {
            Some("noeviction") => Ok(()),
            Some(other) => Err(RecordStoreError(format!(
                "valkey maxmemory-policy is '{other}', not 'noeviction': an eviction policy \
                 can silently drop a denylist entry (un-revoking a key) or a metering row \
                 (destroying billing evidence) under memory pressure with no error anywhere. \
                 Refusing to start. Run `CONFIG SET maxmemory-policy noeviction` (and persist it in \
                 the server's own config, since CONFIG SET does not survive a restart) before \
                 pointing busbar at this instance."
            ))),
            None => Err(RecordStoreError(
                "valkey CONFIG GET maxmemory-policy returned no value — either this server \
                 restricts CONFIG GET via ACL, or something unexpected happened. Refusing to start: \
                 cannot verify the noeviction invariant governance data durability depends on."
                    .to_string(),
            )),
        }
    }

    /// SCHEMA MIGRATION (currently v7; see `SCHEMA_VERSION`'s own doc for what each version did).
    /// A fresh namespace is simply marked; one already at the current version passes through
    /// untouched; a v6 namespace is upgraded IN PLACE ([`legacy::migrate_v6_to_v7`], idempotent, the
    /// marker written last so a crash mid-upgrade re-runs it on the next connect); a namespace older
    /// than v6 (a never-released 1.5.0 development build) is wiped and re-marked, as it always was.
    async fn migrate(&self, c: &mut Conn) -> RecordStoreResult<()> {
        let marker: Option<i64> = with_conn!(self, |c| c.get::<_, Option<i64>>(SCHEMA_KEY).await)?;
        let version = marker.unwrap_or(0);
        if version >= SCHEMA_VERSION {
            return Ok(());
        }
        if version >= FIRST_MIGRATED_SCHEMA {
            legacy::migrate_v6_to_v7(self, c).await?;
            return with_conn!(self, |c| c
                .set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION)
                .await);
        }
        let existing: Vec<String> = with_conn!(self, |c| {
            c.scan_match::<_, String>("busbar:*")
                .await?
                .collect::<Result<Vec<String>, _>>()
        })?;
        if existing.is_empty() {
            return with_conn!(self, |c| c
                .set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION)
                .await);
        }
        // A busbar:* namespace older than v6 (marker present-but-older, or a pre-marker legacy
        // namespace) is wiped: it was written by an unreleased 1.5.0 development build, so there is
        // no released data to preserve across this specific boundary.
        with_conn!(self, |c| {
            let mut pipe = pipe();
            pipe.atomic();
            for k in &existing {
                pipe.del(k).ignore();
            }
            pipe.query::<()>(c).await
        })?;
        with_conn!(self, |c| c
            .set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION)
            .await)
    }

    fn err(&self, e: RedisError, ctx: &str) -> RecordStoreError {
        RecordStoreError(scrub(
            format!("valkey {ctx}: {e}"),
            self.inner.secret.as_deref(),
        ))
    }

    /// Allocate the next revision — a plain `INCR`. Called once per key/credential mutation, inside
    /// whatever pipe/transaction performs the write, so the stamped value and the write are never
    /// observed apart.
    async fn next_revision(&self, c: &mut Conn) -> RedisResult<u64> {
        let v: i64 = c.incr(REVISION_KEY, 1).await?;
        Ok(v.max(0) as u64)
    }
}

/// `put_credential`'s owner precondition, read inside its WATCHed transaction: the key row named by
/// `key_id` must exist and must not be tombstoned. An unparseable owner row is refused too — a
/// credential cannot be attached to a key whose liveness cannot be established.
async fn owner_is_live(c: &mut Conn, key_row: &str, key_id: &str) -> RedisResult<()> {
    let raw: Option<String> = c.get(key_row).await?;
    let refuse = |why: String| {
        Err(RedisError::from((
            ErrorKind::Client,
            "put_credential refused",
            why,
        )))
    };
    let Some(raw) = raw else {
        return refuse(format!(
            "put_credential: key '{key_id}' does not exist; a credential must hang off a real key"
        ));
    };
    match key_from_json(&raw) {
        Ok(k) if k.deleted_at.is_none() => Ok(()),
        Ok(_) => refuse(format!(
            "put_credential: key '{key_id}' is tombstoned; its credentials were revoked with it \
             and are never reissued"
        )),
        Err(_) => refuse(format!(
            "put_credential: key '{key_id}' does not decode; refusing to attach a credential to it"
        )),
    }
}

fn key_from_json(raw: &str) -> RecordStoreResult<VirtualKey> {
    serde_json::from_str(raw).map_err(|e| RecordStoreError(format!("key decode failed: {e}")))
}
fn cred_to_json(cred: &CredentialSecret) -> RecordStoreResult<String> {
    serde_json::to_string(cred)
        .map_err(|e| RecordStoreError(format!("credential encode failed: {e}")))
}
fn cred_from_json(raw: &str) -> RecordStoreResult<CredentialSecret> {
    serde_json::from_str(raw)
        .map_err(|e| RecordStoreError(format!("credential decode failed: {e}")))
}

/// Parse a `"<key_id>:<kind>:<slot>"` pointer value back into its parts. `kind` cannot itself contain
/// `:` (enforced by the fixed kind allowlist upstream), so a right-split on `:` twice is unambiguous
/// even if a future `key_id` contained a colon.
fn parse_slot_pointer(s: &str) -> Option<(String, String, u8)> {
    let (rest, slot) = s.rsplit_once(':')?;
    let (key_id, kind) = rest.rsplit_once(':')?;
    Some((key_id.to_string(), kind.to_string(), slot.parse().ok()?))
}

/// The fields one usage delta adds, as `(hash field, delta)` pairs for [`ADD_FLOORED_LUA`]: the two
/// request counters always, and every non-zero unit.
fn usage_fields(delta: &UsageDelta) -> Vec<(String, i64)> {
    let mut fields: Vec<(String, i64)> = vec![
        ("requests".to_string(), delta.requests),
        ("billable_requests".to_string(), delta.billable_requests),
    ];
    for m in &delta.models {
        for (unit, d) in &m.usage_units {
            if *d != 0 {
                fields.push((usage_field(&m.model, unit), *d));
            }
        }
    }
    fields
}

/// Queue one metering delta's writes on `pipe` (the caller makes it atomic): the row joins its
/// bucket's set, every counter is an `HINCRBY`, the identity fields are set, and the attribution
/// snapshot is first-write-wins.
fn queue_metering(pipe: &mut Pipeline, d: &MeteringDelta) {
    let row = metering_row(d.bucket, &d.key_id, &d.model, &d.provider, d.priced_from_ms);
    pipe.sadd(metering_set(d.bucket), &row).ignore();
    for (field, v) in [
        ("tokens_input", d.tokens_input),
        ("tokens_output", d.tokens_output),
        ("tokens_cache_read", d.tokens_cache_read),
        ("tokens_cache_write", d.tokens_cache_write),
        ("requests", d.requests),
        ("billable_requests", d.billable_requests),
    ] {
        pipe.cmd("HINCRBY")
            .arg(&row)
            .arg(field)
            .arg(clamp(v))
            .ignore();
    }
    for (class, v) in &d.usage_units {
        pipe.cmd("HINCRBY")
            .arg(&row)
            .arg(format!("{METERING_UNIT_PREFIX}{class}"))
            .arg(clamp(*v))
            .ignore();
    }
    pipe.hset_multiple(
        &row,
        &[
            ("key_id", d.key_id.as_str()),
            ("model", d.model.as_str()),
            ("provider", d.provider.as_str()),
        ],
    )
    .ignore()
    .hset(&row, "priced_from_ms", d.priced_from_ms.to_string())
    .ignore()
    // First-write-wins attribution snapshot: HSETNX only sets if the field is absent.
    .cmd("HSETNX")
    .arg(&row)
    .arg("key_group_at_use")
    .arg(&d.key_group_at_use)
    .ignore()
    .cmd("HSETNX")
    .arg(&row)
    .arg("pricing_version")
    .arg(&d.pricing_version)
    .ignore();
}

/// The refusal an audit append answers when `seq` already holds a DIFFERENT record.
fn audit_fork(stored: &AuditRecord, entry: &AuditRecord) -> String {
    format!(
        "append_audit: seq {} already holds a DIFFERENT record; the audit chain has forked \
         (stored action '{}', incoming '{}')",
        entry.seq, stored.action, entry.action
    )
}

/// THE 1.5.5 OP SET's bodies, each over the op's one connection `c` (the store door, `slots`,
/// runs each as one op through the host's connector). The un-deduped 1.5.5 writes (`add_usage`,
/// `add_metering`, `append_audit`, `append_plane_record`) reach the store as their `op_id` slots.
impl ValkeyStore {
    pub(crate) async fn put_key(&self, c: &mut Conn, key: &VirtualKey) -> RecordStoreResult<()> {
        let key = key.clone();
        let row_key = format!("{KEY_PREFIX}{}", key.id);
        with_conn!(self, |c| {
            // TOMBSTONE PRECONDITION (see `Store::put_key`): a live-shaped write must not overwrite
            // a tombstoned row, which would reissue an id the contract says is never reissued and
            // revive every token minted before the delete. WATCHed rather than read-then-written, so
            // a `delete_key` committing between the read and the SET aborts and retries instead of
            // slipping through — the same TOCTOU the caller-side checks in core cannot close.
            transaction!(c, &[row_key.as_str()], |c, pipe| {
                if key.deleted_at.is_none() {
                    let existing: Option<String> = c.get(&row_key).await?;
                    // A row that does not parse is left to the normal write path rather than being
                    // treated as a tombstone: refusing here would make a corrupt row permanently
                    // unwritable, and this method is not the one that should be adjudicating that.
                    if let Some(prior) = existing.as_deref().and_then(|r| key_from_json(r).ok()) {
                        if prior.deleted_at.is_some() {
                            return Err(RedisError::from((
                                ErrorKind::Client,
                                "put_key refused",
                                format!(
                                    "put_key: '{}' is tombstoned and its id is never reissued; \
                                     refusing to clear the tombstone",
                                    key.id
                                ),
                            )));
                        }
                    }
                }
                let mut key = key.clone();
                let rev = self.next_revision(c).await?;
                key.revision = rev;
                let json = serde_json::to_string(&key)
                    .map_err(|_e| RedisError::from((ErrorKind::Client, "encode")))?;
                pipe.atomic()
                    .set(&row_key, &json)
                    .ignore()
                    .sadd(KEYS_INDEX, &key.id)
                    .ignore()
                    .zadd(KEYS_BYREV, &key.id, rev)
                    .ignore()
                    .query(c)
                    .await
            })
        })
    }

    pub(crate) async fn get_key(
        &self,
        c: &mut Conn,
        id: &str,
    ) -> RecordStoreResult<Option<VirtualKey>> {
        let raw: Option<String> = with_conn!(self, |c| c.get(format!("{KEY_PREFIX}{id}")).await)?;
        raw.map(|r| key_from_json(&r)).transpose()
    }

    pub(crate) async fn list_keys(&self, c: &mut Conn) -> RecordStoreResult<Vec<VirtualKey>> {
        // Deliberately UNFILTERED — including tombstones. See the trait's own doc: this serves both
        // the admin-listing caller (which filters `is_live()` itself) and `list_keys_since`'s default
        // hydration fallback, which needs to SEE a tombstone to evict cached credentials.
        let ids: Vec<String> = with_conn!(self, |c| c.smembers(KEYS_INDEX).await)?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let raws: Vec<Option<String>> = with_conn!(self, |c| {
            let mut pipe = pipe();
            for id in &ids {
                pipe.get(format!("{KEY_PREFIX}{id}"));
            }
            pipe.query(c).await
        })?;
        let mut out = Vec::with_capacity(ids.len());
        for raw in raws.into_iter().flatten() {
            out.push(key_from_json(&raw)?);
        }
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    pub(crate) async fn list_keys_since(
        &self,
        c: &mut Conn,
        since: u64,
    ) -> RecordStoreResult<Vec<VirtualKey>> {
        // Real delta-fetch: ZRANGEBYSCORE the byrev index, not a full scan-and-filter — the whole
        // point of maintaining `keys:byrev`.
        let ids: Vec<String> = with_conn!(self, |c| c
            .zrangebyscore(KEYS_BYREV, format!("({since}"), "+inf")
            .await)?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let raws: Vec<Option<String>> = with_conn!(self, |c| {
            let mut pipe = pipe();
            for id in &ids {
                pipe.get(format!("{KEY_PREFIX}{id}"));
            }
            pipe.query(c).await
        })?;
        let mut out = Vec::with_capacity(ids.len());
        for raw in raws.into_iter().flatten() {
            out.push(key_from_json(&raw)?);
        }
        Ok(out)
    }

    pub(crate) async fn delete_key(&self, c: &mut Conn, id: &str) -> RecordStoreResult<()> {
        let ids_key = cred_ids_key(id);
        let key_row = format!("{KEY_PREFIX}{id}");
        // Usage windows: a non-blocking SCAN outside the transaction (mirrors the crate's prior
        // behavior). A deleted key's rate-limit windows are meaningless — best-effort cleanup, not a
        // correctness-critical invariant like the credential cascade below, so a concurrent
        // add_usage/put_usage racing a new window into existence between this SCAN and the EXEC is an
        // acceptable, already-documented gap (stale data, not an identity/auth issue).
        let pattern = format!("busbar:usage:{}:*", escape_glob(id));
        let usage_keys: Vec<String> = with_conn!(self, |c| {
            c.scan_match::<_, String>(&pattern)
                .await?
                .collect::<Result<Vec<String>, _>>()
        })?;
        // WATCH the key row, its credential-id index, AND every current member's own credential
        // row: a concurrent put_credential can rewrite a slot's row in place (reusing an existing
        // member of `ids_key`, so SADD never fires and `ids_key` itself doesn't change) — if only
        // `key_row`/`ids_key` were watched, that in-place rewrite would slip past WATCH entirely,
        // and this cascade would then destroy the row (and fail to clean up the NEW public_id's
        // reverse pointer) without ever having observed the change. Because the row-key set itself
        // depends on `ids_key`'s membership, and membership can also change between our pre-read
        // and the transaction's WATCH, this loops: any membership change aborts (ids_key is
        // watched) and we recompute the watch set from scratch against fresh state.
        with_conn!(self, |c| loop {
            let members: Vec<String> = c.smembers(&ids_key).await?;
            let row_keys: Vec<String> = members
                .iter()
                .filter_map(|m| parse_slot_pointer(&format!("{id}:{m}")))
                .map(|(_, kind, slot)| cred_row_key(id, &kind, slot))
                .collect();
            let mut watch_keys: Vec<&str> = vec![key_row.as_str(), ids_key.as_str()];
            watch_keys.extend(row_keys.iter().map(String::as_str));

            let outcome = transaction!(c, &watch_keys, |c, pipe| {
                let raw: Option<String> = c.get(&key_row).await?;
                let Some(raw) = raw else {
                    // Unknown id (never existed): a real error, matching the SQL backends'
                    // `delete_key`-on-unknown-id contract — distinct from "already tombstoned",
                    // which IS an idempotent no-op (see below).
                    return Err(RedisError::from((
                        ErrorKind::Client,
                        "delete_key: unknown id",
                    )));
                };
                let mut key: VirtualKey = serde_json::from_str(&raw)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "key decode")))?;
                if key.deleted_at.is_some() {
                    // Already tombstoned: idempotent no-op (do not re-bump revision or re-destroy
                    // credentials that are already gone).
                    pipe.atomic();
                    return pipe.query(c).await;
                }
                // `transaction!`'s own internal WATCH-abort retry reruns this body with
                // the SAME fixed `watch_keys` computed above -- it can't recompute which row keys
                // to watch. So re-read membership fresh here and compare against the outer
                // pre-read: if it changed, `ids_key` (which IS watched) will already have aborted
                // this EXEC, but we still need to bail out to the OUTER loop to rebuild `watch_keys`
                // against the new members' rows, rather than silently proceeding against the stale
                // set.
                let fresh_members: Vec<String> = c.smembers(&ids_key).await?;
                if fresh_members.len() != members.len()
                    || !fresh_members.iter().all(|m| members.contains(m))
                {
                    return Err(RedisError::from((
                        ErrorKind::Client,
                        DELETE_KEY_RETRY_SENTINEL,
                    )));
                }
                let rev = self.next_revision(c).await?;
                key.enabled = false;
                key.deleted_at = Some(crate::now());
                key.revision = rev;
                let key_json = serde_json::to_string(&key)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "key encode")))?;

                pipe.atomic();
                pipe.set(&key_row, &key_json).ignore();
                pipe.zadd(KEYS_BYREV, id, rev).ignore();
                for uk in &usage_keys {
                    pipe.del(uk).ignore();
                }
                // Destroy every credential row + its reverse-lookup pointers. Per the trait's own
                // hydration contract, a hard-deleted credential row is fine here (not a hazard) —
                // the CONSUMER evicts cached credentials off this key's OWN `deleted_at` delta, never
                // waiting for a credential-row delta that (by construction) will never come.
                for member in &members {
                    let Some((_, kind, slot)) = parse_slot_pointer(&format!("{id}:{member}"))
                    else {
                        continue;
                    };
                    let row_key = cred_row_key(id, &kind, slot);
                    // Need the row's public_id to clean up its reverse pointer — read it (still
                    // inside the WATCHed transaction closure, so this is consistent with the EXEC).
                    // A missing row is a legitimate no-op (already gone). A row that IS present but
                    // fails to decode must abort the whole cascade rather than be silently skipped
                    // — an `if let Ok(...) = ...` swallow here would still delete the row while
                    // leaving its `cred:pub:*`/`cred:id:*` reverse pointers permanently dangling,
                    // reporting `delete_key` as a success despite violating its own "destroy every
                    // credential row + pointers" contract. Every other decode path in this file
                    // (key_from_json, cred_from_json, list_metering) propagates a corrupt value as
                    // an error rather than silently under-delivering; this matches that.
                    if let Some(raw) = c.get::<_, Option<String>>(&row_key).await? {
                        let cred: CredentialSecret = serde_json::from_str(&raw).map_err(|_| {
                            RedisError::from((
                                ErrorKind::Client,
                                "delete_key: corrupt credential row",
                            ))
                        })?;
                        pipe.del(cred_pub_key(&kind, &cred.meta.public_id)).ignore();
                        pipe.del(cred_id_key(&cred.meta.id)).ignore();
                    }
                    pipe.del(&row_key).ignore();
                }
                pipe.del(&ids_key).ignore();
                pipe.query(c).await
            });

            match outcome {
                Err(e) if e.to_string().contains(DELETE_KEY_RETRY_SENTINEL) => continue,
                other => break other,
            }
        })
    }

    pub(crate) async fn scrub_key(&self, c: &mut Conn, id: &str) -> RecordStoreResult<()> {
        let key_row = format!("{KEY_PREFIX}{id}");
        with_conn!(self, |c| {
            transaction!(c, &[key_row.as_str()], |c, pipe| {
                let raw: Option<String> = c.get(&key_row).await?;
                let Some(raw) = raw else {
                    return Err(RedisError::from((
                        ErrorKind::Client,
                        "scrub_key: unknown id",
                    )));
                };
                let mut key: VirtualKey = serde_json::from_str(&raw)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "key decode")))?;
                if key.deleted_at.is_none() {
                    return Err(RedisError::from((
                        ErrorKind::Client,
                        "scrub_key: key is not tombstoned — delete_key it first",
                    )));
                }
                let rev = self.next_revision(c).await?;
                key.name = String::new();
                key.labels.clear();
                key.revision = rev;
                let json = serde_json::to_string(&key)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "key encode")))?;
                pipe.atomic();
                pipe.set(&key_row, &json).ignore();
                pipe.zadd(KEYS_BYREV, id, rev).ignore();
                pipe.query(c).await
            })
        })
    }

    pub(crate) async fn get_usage(
        &self,
        c: &mut Conn,
        bucket_id: &str,
        window_start: u64,
    ) -> RecordStoreResult<UsageLedger> {
        let k = usage_key(bucket_id, window_start);
        let fields: Vec<(String, i64)> = with_conn!(self, |c| c.hgetall(&k).await)?;
        if fields.is_empty() {
            return Ok(UsageLedger::default());
        }
        let mut ledger = UsageLedger::default();
        for (name, v) in fields {
            if name == "requests" {
                ledger.requests = read_u64(v);
                continue;
            }
            if name == "billable_requests" {
                ledger.billable_requests = read_u64(v);
                continue;
            }
            let Some((model, unit)) = parse_usage_field(&name) else {
                continue;
            };
            let entry = match ledger.models.iter_mut().find(|m| m.model == model) {
                Some(m) => m,
                None => {
                    ledger.models.push(ModelTokens {
                        model,
                        ..Default::default()
                    });
                    ledger.models.last_mut().expect("just pushed")
                }
            };
            // A zero counter is not carried: the map is sparse (`ModelTokens::is_zero` reads an
            // absent key and a zero one the same), and a v6 row wrote all four tiers, zeros included.
            let n = read_u64(v);
            if n != 0 {
                entry.usage_units.insert(unit, n);
            }
        }
        ledger.models.sort_by(|a, b| a.model.cmp(&b.model));
        Ok(ledger)
    }

    pub(crate) async fn put_usage(
        &self,
        c: &mut Conn,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        let k = usage_key(bucket_id, window_start);
        with_conn!(self, |c| {
            let mut pipe = pipe();
            pipe.atomic();
            pipe.del(&k).ignore();
            pipe.hset(&k, "requests", clamp(ledger.requests)).ignore();
            pipe.hset(&k, "billable_requests", clamp(ledger.billable_requests))
                .ignore();
            for m in &ledger.models {
                for (unit, n) in &m.usage_units {
                    pipe.hset(&k, usage_field(&m.model, unit), clamp(*n))
                        .ignore();
                }
            }
            pipe.query(c).await
        })
    }

    pub(crate) async fn list_metering(
        &self,
        c: &mut Conn,
        bucket: u64,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        let set = metering_set(bucket);
        let row_keys: Vec<String> = with_conn!(self, |c| c.smembers(&set).await)?;
        if row_keys.is_empty() {
            return Ok(Vec::new());
        }
        let all_fields: Vec<Vec<(String, String)>> = with_conn!(self, |c| {
            let mut pipe = pipe();
            for row_key in &row_keys {
                pipe.hgetall(row_key);
            }
            pipe.query(c).await
        })?;
        let mut out = Vec::with_capacity(row_keys.len());
        for fields in all_fields {
            if fields.is_empty() {
                continue;
            }
            let mut m = MeteringRow {
                key_id: String::new(),
                model: String::new(),
                provider: String::new(),
                tokens_input: 0,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 0,
                billable_requests: 0,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
                priced_from_ms: 0,
                usage_units: Default::default(),
            };
            for (name, val) in fields {
                // Every other decode path in this file (key_from_json, cred_from_json, audit
                // records) propagates a RecordStoreError on a corrupt value rather than silently
                // substituting a default -- a malformed numeric field here must not silently
                // read back as 0 and under-report billing/usage data.
                let num = |field: &str, val: &str| {
                    val.parse::<i64>().map_err(|e| {
                        RecordStoreError(format!("list_metering: bad {field} value {val:?}: {e}"))
                    })
                };
                if let Some(class) = name.strip_prefix(METERING_UNIT_PREFIX) {
                    let n = read_u64(num(&name, &val)?);
                    if n != 0 {
                        m.usage_units.insert(class.to_string(), n);
                    }
                    continue;
                }
                match name.as_str() {
                    "key_id" => m.key_id = val.clone(),
                    "model" => m.model = val.clone(),
                    "provider" => m.provider = val.clone(),
                    "tokens_input" => m.tokens_input = read_u64(num("tokens_input", &val)?),
                    "tokens_output" => m.tokens_output = read_u64(num("tokens_output", &val)?),
                    "tokens_cache_read" => {
                        m.tokens_cache_read = read_u64(num("tokens_cache_read", &val)?)
                    }
                    "tokens_cache_write" => {
                        m.tokens_cache_write = read_u64(num("tokens_cache_write", &val)?)
                    }
                    "requests" => m.requests = read_u64(num("requests", &val)?),
                    "billable_requests" => {
                        m.billable_requests = read_u64(num("billable_requests", &val)?)
                    }
                    "priced_from_ms" => {
                        m.priced_from_ms = val.parse::<u64>().map_err(|e| {
                            RecordStoreError(format!(
                                "list_metering: bad priced_from_ms value {val:?}: {e}"
                            ))
                        })?
                    }
                    "key_group_at_use" => m.key_group_at_use = val.clone(),
                    "pricing_version" => m.pricing_version = val.clone(),
                    _ => {}
                }
            }
            out.push(m);
        }
        Ok(out)
    }

    pub(crate) async fn put_credential(
        &self,
        c: &mut Conn,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let row_key = cred_row_key(&secret.meta.key_id, &secret.meta.kind, secret.meta.slot);
        let ids_key = cred_ids_key(&secret.meta.key_id);
        let pub_key = cred_pub_key(&secret.meta.kind, &secret.meta.public_id);
        let id_key = cred_id_key(&secret.meta.id);
        let key_row = format!("{KEY_PREFIX}{}", secret.meta.key_id);
        let mut secret = secret.clone();
        let slot_ptr = format!(
            "{}:{}:{}",
            secret.meta.key_id, secret.meta.kind, secret.meta.slot
        );
        with_conn!(self, |c| {
            // WATCH the OWNING KEY's row too: a credential must hang off a real, live key, and a
            // `delete_key` committing between that check and the write must abort this, never slip
            // under it (the tombstone cascade would otherwise be undone through this door).
            //
            // WATCH both the slot's own row AND the public_id pointer: the uniqueness check reads
            // `pub_key` here, immediately (not through the pipe, so its result is actually
            // inspected — a `SETNX` queued inside an `.ignore()`d pipe command would silently
            // discard the "already claimed" signal, which is exactly the bug this shape avoids). A
            // concurrent writer claiming this public_id between the read and EXEC touches the
            // watched `pub_key`, aborting and retrying this whole closure against fresh state.
            let watched = [row_key.as_str(), pub_key.as_str(), key_row.as_str()];
            transaction!(c, &watched, |c, pipe| {
                owner_is_live(c, &key_row, &secret.meta.key_id).await?;
                let existing: Option<String> = c.get(&row_key).await?;
                let mut old_pub: Option<String> = None;
                let mut old_id: Option<String> = None;
                if let Some(raw) = &existing {
                    let cur: CredentialSecret = serde_json::from_str(raw)
                        .map_err(|_| RedisError::from((ErrorKind::Client, "cred decode")))?;
                    if cur.meta.revoked_at.is_none() {
                        if cur.meta.id == secret.meta.id {
                            // Retry-safe no-op: the slot already holds THIS SAME credential
                            // (matched by its own id, never reused across mints). This is not a
                            // genuine second mint attempt — it is `with_conn`'s automatic
                            // reconnect-and-retry replaying this whole closure after a connection
                            // blip dropped the reply for an EXEC that had already committed
                            // server-side. Erroring here would report failure for a write that, in
                            // fact, already fully succeeded.
                            pipe.atomic();
                            return pipe.query(c).await;
                        }
                        // Slot occupied by a DIFFERENT live credential — an explicit mint into it
                        // would silently destroy a working credential mid-overlap-window. Fail
                        // loud.
                        return Err(RedisError::from((
                            ErrorKind::Client,
                            "put_credential: slot holds a live credential; revoke it first",
                        )));
                    }
                    old_pub = Some(cur.meta.public_id);
                    old_id = Some(cur.meta.id);
                }
                // UNIQUE(kind, public_id), enforced by an actual read-and-check (not a discarded
                // SETNX): if some OTHER slot already holds this public_id, reject before writing
                // anything. Reclaiming the SAME slot's own previous public_id is fine (that case is
                // `old_pub == Some(secret.meta.public_id)` and is not a collision).
                let pub_holder: Option<String> = c.get(&pub_key).await?;
                if let Some(holder) = &pub_holder {
                    if *holder != slot_ptr {
                        return Err(RedisError::from((
                            ErrorKind::Client,
                            "put_credential: public_id already claimed by a different credential",
                        )));
                    }
                }
                let rev = self.next_revision(c).await?;
                secret.meta.revision = rev;
                let json = cred_to_json(&secret)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "cred encode")))?;

                pipe.atomic();
                if let Some(old_pub) = &old_pub {
                    if *old_pub != secret.meta.public_id {
                        pipe.del(cred_pub_key(&secret.meta.kind, old_pub)).ignore();
                    }
                }
                if let Some(old_id) = &old_id {
                    // Reclaiming this slot with a DIFFERENT credential id: the previous occupant's
                    // `cred:id:<old_id>` pointer would otherwise keep resolving to this slot
                    // forever, now holding someone else's row. Left alive, a later call to
                    // `revoke_credential(old_id)` (an idempotent-retry, or simply a caller that
                    // still has the old id) would revoke and secret-wipe the NEW, unrelated
                    // occupant instead of being the no-op the trait's contract promises for a dead
                    // id. Delete it in the same atomic pipe as the reclaim so the two writes are
                    // never observed apart.
                    if *old_id != secret.meta.id {
                        pipe.del(cred_id_key(old_id)).ignore();
                    }
                }
                pipe.set(&pub_key, &slot_ptr).ignore();
                pipe.set(&id_key, &slot_ptr).ignore();
                pipe.set(&row_key, &json).ignore();
                pipe.sadd(
                    &ids_key,
                    format!("{}:{}", secret.meta.kind, secret.meta.slot),
                )
                .ignore();
                pipe.zadd(CREDS_BYREV, &slot_ptr, rev).ignore();
                pipe.query(c).await
            })
        })
    }

    pub(crate) async fn put_key_with_credential(
        &self,
        c: &mut Conn,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        if secret.meta.key_id != key.id {
            return Err(RecordStoreError(format!(
                "put_key_with_credential: the credential names key '{}', not the key '{}' being \
                 minted with it",
                secret.meta.key_id, key.id
            )));
        }
        // Atomic key+credential mint: WATCH both rows so neither write is observed without the
        // other. The credential row cannot pre-exist for a brand-new mint (a fresh id/slot), so this
        // is simpler than `put_credential`'s slot-reuse path — no old-pointer cleanup needed.
        let key_row = format!("{KEY_PREFIX}{}", key.id);
        let row_key = cred_row_key(&secret.meta.key_id, &secret.meta.kind, secret.meta.slot);
        let ids_key = cred_ids_key(&secret.meta.key_id);
        let pub_key = cred_pub_key(&secret.meta.kind, &secret.meta.public_id);
        let id_key = cred_id_key(&secret.meta.id);
        let mut key = key.clone();
        let mut secret = secret.clone();
        let slot_ptr = format!(
            "{}:{}:{}",
            secret.meta.key_id, secret.meta.kind, secret.meta.slot
        );
        with_conn!(self, |c| {
            // WATCH the key row, the credential's own row, AND the public_id pointer — a fresh
            // mint's public_id must not already be claimed (real check, not a discarded SETNX; see
            // `put_credential`'s identical reasoning).
            transaction!(
                c,
                &[key_row.as_str(), row_key.as_str(), pub_key.as_str()],
                |c, pipe| {
                    // The tombstone precondition `put_key` enforces, on the atomic mint too: a
                    // live-shaped key must not clear a stored tombstone.
                    if key.deleted_at.is_none() {
                        let prior: Option<String> = c.get(&key_row).await?;
                        if prior
                            .as_deref()
                            .and_then(|r| key_from_json(r).ok())
                            .is_some_and(|k| k.deleted_at.is_some())
                        {
                            return Err(RedisError::from((
                                ErrorKind::Client,
                                "put_key_with_credential refused",
                                format!(
                                    "put_key_with_credential: '{}' is tombstoned and its id is \
                                     never reissued",
                                    key.id
                                ),
                            )));
                        }
                    }
                    let pub_holder: Option<String> = c.get(&pub_key).await?;
                    if let Some(holder) = &pub_holder {
                        if *holder == slot_ptr {
                            // Possibly retry-safe: the public_id already points at THIS slot. This
                            // only happens for a genuinely fresh mint if `with_conn`'s automatic
                            // reconnect-and-retry is replaying this whole closure after a
                            // connection blip dropped the reply for an EXEC that had already
                            // committed server-side — so confirm by id before treating it as a
                            // no-op rather than a real collision.
                            let existing_row: Option<String> = c.get(&row_key).await?;
                            let same = existing_row
                                .as_deref()
                                .and_then(|r| serde_json::from_str::<CredentialSecret>(r).ok())
                                .is_some_and(|cur| cur.meta.id == secret.meta.id);
                            if same {
                                pipe.atomic();
                                return pipe.query(c).await;
                            }
                        }
                        return Err(RedisError::from((
                            ErrorKind::Client,
                            "put_key_with_credential: public_id already claimed",
                        )));
                    }
                    let key_rev = self.next_revision(c).await?;
                    let cred_rev = self.next_revision(c).await?;
                    key.revision = key_rev;
                    secret.meta.revision = cred_rev;
                    let key_json = serde_json::to_string(&key)
                        .map_err(|_| RedisError::from((ErrorKind::Client, "key encode")))?;
                    let cred_json = cred_to_json(&secret)
                        .map_err(|_| RedisError::from((ErrorKind::Client, "cred encode")))?;
                    pipe.atomic();
                    pipe.set(&key_row, &key_json).ignore();
                    pipe.sadd(KEYS_INDEX, &key.id).ignore();
                    pipe.zadd(KEYS_BYREV, &key.id, key_rev).ignore();
                    pipe.set(&pub_key, &slot_ptr).ignore();
                    pipe.set(&id_key, &slot_ptr).ignore();
                    pipe.set(&row_key, &cred_json).ignore();
                    pipe.sadd(
                        &ids_key,
                        format!("{}:{}", secret.meta.kind, secret.meta.slot),
                    )
                    .ignore();
                    pipe.zadd(CREDS_BYREV, &slot_ptr, cred_rev).ignore();
                    pipe.query(c).await
                },
            )
        })
    }

    pub(crate) async fn list_credentials(
        &self,
        c: &mut Conn,
        key_id: &str,
    ) -> RecordStoreResult<Vec<CredentialMeta>> {
        let members: Vec<String> = with_conn!(self, |c| c.smembers(cred_ids_key(key_id)).await)?;
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let row_keys: Vec<String> = members
            .iter()
            .filter_map(|m| {
                let (kind, slot) = m.split_once(':')?;
                Some(cred_row_key(key_id, kind, slot.parse().ok()?))
            })
            .collect();
        let raws: Vec<Option<String>> = with_conn!(self, |c| {
            let mut pipe = pipe();
            for k in &row_keys {
                pipe.get(k);
            }
            pipe.query(c).await
        })?;
        let mut out = Vec::with_capacity(raws.len());
        for raw in raws.into_iter().flatten() {
            // Decode the full CredentialSecret, then keep ONLY `.meta` — the secret never leaves
            // this function's stack. There is no separate on-disk "meta view" to drift from the
            // real row; this is the one and only decode path for a credential row.
            out.push(cred_from_json(&raw)?.meta);
        }
        Ok(out)
    }

    pub(crate) async fn lookup_credential_secret(
        &self,
        c: &mut Conn,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        let ptr: Option<String> = with_conn!(self, |c| c.get(cred_pub_key(kind, public_id)).await)?;
        let Some(ptr) = ptr else {
            return Ok(None);
        };
        let Some((key_id, kind, slot)) = parse_slot_pointer(&ptr) else {
            return Ok(None);
        };
        let raw: Option<String> =
            with_conn!(self, |c| c.get(cred_row_key(&key_id, &kind, slot)).await)?;
        raw.map(|r| cred_from_json(&r)).transpose()
    }

    pub(crate) async fn revoke_credential(
        &self,
        c: &mut Conn,
        id: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        let id_key = cred_id_key(id);
        with_conn!(self, |c| {
            transaction!(c, &[id_key.as_str()], |c, pipe| {
                let ptr: Option<String> = c.get(&id_key).await?;
                let Some(ptr) = ptr else {
                    // Unknown credential id: an ERROR. The trait's "idempotent" covers revoking an
                    // ALREADY-REVOKED id, not an id that names nothing — a silent no-op here lets
                    // an operator responding to a leak believe the credential is dead while it is
                    // still live and still authenticating.
                    return Err(RedisError::from((
                        ErrorKind::Client,
                        "revoke_credential refused",
                        format!("revoke_credential: unknown id '{id}'"),
                    )));
                };
                // A pointer that exists but does not parse is CORRUPTION, not an unknown id.
                // Returning Ok here would report a revocation that never happened: the row keeps
                // its secret, `revoked_at` stays unset, and the credential goes on authenticating
                // while the audit trail says it was revoked. `delete_key` already fails loud on
                // the sibling case (see `delete_key_fails_loud_on_a_corrupt_credential_row`).
                let Some((key_id, kind, slot)) = parse_slot_pointer(&ptr) else {
                    return Err(RedisError::from((
                        ErrorKind::Client,
                        "corrupt credential pointer",
                        format!("busbar:cred:id:{id} does not parse as <key_id>:<kind>:<slot>"),
                    )));
                };
                let row_key = cred_row_key(&key_id, &kind, slot);
                let raw: Option<String> = c.get(&row_key).await?;
                let Some(raw) = raw else {
                    pipe.atomic();
                    return pipe.query(c).await;
                };
                let mut cred: CredentialSecret = serde_json::from_str(&raw)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "cred decode")))?;
                if cred.meta.revoked_at.is_some() {
                    // Already revoked: idempotent no-op.
                    pipe.atomic();
                    return pipe.query(c).await;
                }
                let rev = self.next_revision(c).await?;
                cred.meta.revoked_at = Some(crate::now());
                cred.meta.revoke_reason = Some(reason.to_string());
                cred.meta.revision = rev;
                // Destroy the secret material on revoke — defense in depth: a revoked credential's
                // plaintext has no further legitimate reader, so there is no reason to retain it.
                cred.secret = String::new();
                let json = cred_to_json(&cred)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "cred encode")))?;
                pipe.atomic();
                pipe.set(&row_key, &json).ignore();
                pipe.zadd(CREDS_BYREV, format!("{key_id}:{kind}:{slot}"), rev)
                    .ignore();
                pipe.query(c).await
            })
        })
    }

    pub(crate) async fn list_credentials_since(
        &self,
        c: &mut Conn,
        since: u64,
    ) -> RecordStoreResult<Vec<CredentialSecret>> {
        let members: Vec<String> = with_conn!(self, |c| c
            .zrangebyscore(CREDS_BYREV, format!("({since}"), "+inf")
            .await)?;
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let row_keys: Vec<String> = members
            .iter()
            .filter_map(|m| {
                let (key_id, kind, slot) = parse_slot_pointer(m)?;
                Some(cred_row_key(&key_id, &kind, slot))
            })
            .collect();
        let raws: Vec<Option<String>> = with_conn!(self, |c| {
            let mut pipe = pipe();
            for k in &row_keys {
                pipe.get(k);
            }
            pipe.query(c).await
        })?;
        // A row that will not decode is SKIPPED, not propagated as an error for the whole call.
        //
        // This is the hydration delta, and it is a GLOBAL scan of every credential in the store, so
        // failing the call on one bad row turns a single corrupt row into a total credential
        // hydration failure for every key at once — the engine hydrates nothing and no credential
        // authenticates anywhere. Skipping degrades that to exactly one credential missing.
        //
        // Skipping is also the fail-CLOSED direction here, which is why it is safe: a credential
        // that cannot be decoded cannot be used to authenticate anyone, so omitting it from the
        // delta denies access rather than granting it. Core's own `load_by_credential` already
        // takes the same view, skipping credentials it cannot use rather than refusing to load.
        //
        // Deliberately NOT the same call as `delete_key`, which fails loud on a corrupt row: there,
        // continuing would orphan that row's reverse-lookup pointers, so silence would leave the
        // store inconsistent. Here nothing is written and nothing is left inconsistent.
        //
        // Reported on stderr because a plugin's `tracing` output does not reach the host (a cdylib
        // links its own dispatcher and nothing bridges them) — the same local workaround auth-oidc
        // and webrequest-hook already use. The row key names `key_id:kind:slot` and carries no
        // secret.
        let mut out = Vec::with_capacity(raws.len());
        for (i, raw) in raws.into_iter().enumerate() {
            let Some(raw) = raw else { continue };
            match cred_from_json(&raw) {
                Ok(cred) => out.push(cred),
                Err(e) => {
                    eprintln!(
                        "busbar-store-valkey: skipping undecodable credential row {} in the \
                         hydration delta ({e}); that credential cannot authenticate until the row \
                         is repaired, and the rest of the delta is unaffected",
                        row_keys.get(i).map(String::as_str).unwrap_or("<unknown>")
                    );
                }
            }
        }
        Ok(out)
    }

    pub(crate) async fn list_audit(&self, c: &mut Conn) -> RecordStoreResult<Vec<AuditRecord>> {
        let members: Vec<String> = with_conn!(self, |c| c.zrange(AUDIT_ZSET, 0, -1).await)?;
        let mut out = Vec::with_capacity(members.len());
        for m in members {
            let rec: AuditRecord = serde_json::from_str(&m)
                .map_err(|e| RecordStoreError(format!("audit decode failed: {e}")))?;
            out.push(rec);
        }
        Ok(out)
    }

    pub(crate) async fn list_audit_tail(
        &self,
        c: &mut Conn,
        limit: u64,
    ) -> RecordStoreResult<Vec<AuditRecord>> {
        let start: isize = isize::try_from(limit).map(|n| -n).unwrap_or(isize::MIN);
        let members: Vec<String> = with_conn!(self, |c| c.zrange(AUDIT_ZSET, start, -1).await)?;
        let mut out = Vec::with_capacity(members.len());
        for m in members {
            let rec: AuditRecord = serde_json::from_str(&m)
                .map_err(|e| RecordStoreError(format!("audit decode failed: {e}")))?;
            out.push(rec);
        }
        Ok(out)
    }

    pub(crate) async fn add_denylist(
        &self,
        c: &mut Conn,
        sub: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        with_conn!(self, |c| {
            pipe()
                .atomic()
                .set(format!("{DENYLIST_PREFIX}{sub}"), reason)
                .ignore()
                .sadd(DENYLIST_INDEX, sub)
                .ignore()
                .query(c)
                .await
        })
    }

    pub(crate) async fn list_denylist(&self, c: &mut Conn) -> RecordStoreResult<Vec<String>> {
        with_conn!(self, |c| c.smembers(DENYLIST_INDEX).await)
    }

    // ── THE NEUTRAL KIND-TAGGED PLANE-RECORD VERBS (1.6.0) ─────────────────────────────────────
    //
    // One keyspace per kind, for every kind; the store never decodes a body. See [`plane`] for the
    // layout and for why each step is a server-side script.

    pub(crate) async fn upsert_plane_record(
        &self,
        c: &mut Conn,
        record: PlaneRecordRef<'_>,
    ) -> RecordStoreResult<()> {
        plane::upsert(self, c, record).await
    }

    pub(crate) async fn get_plane_record(
        &self,
        c: &mut Conn,
        kind: &str,
        id: &str,
    ) -> RecordStoreResult<Option<Vec<u8>>> {
        plane::get(self, c, kind, id).await
    }

    pub(crate) async fn list_plane_records(
        &self,
        c: &mut Conn,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        plane::list(self, c, kind, selector).await
    }

    pub(crate) async fn list_plane_record_parents(
        &self,
        c: &mut Conn,
        kind: &str,
    ) -> RecordStoreResult<Vec<String>> {
        plane::parents(self, c, kind).await
    }

    pub(crate) async fn purge_plane_records_before(
        &self,
        c: &mut Conn,
        kind: &str,
        before: u64,
    ) -> RecordStoreResult<u64> {
        plane::purge_before(self, c, kind, before).await
    }

    pub(crate) async fn delete_plane_record(
        &self,
        c: &mut Conn,
        kind: &str,
        id: &str,
    ) -> RecordStoreResult<()> {
        plane::delete(self, c, kind, id).await
    }

    pub(crate) async fn redeem_plane_token(
        &self,
        c: &mut Conn,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        plane::redeem_token(self, c, kind, token, expires_at, now).await
    }

    pub(crate) async fn plane_token_live(
        &self,
        c: &mut Conn,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        plane::token_live(self, c, kind, token, expires_at, now).await
    }
}

/// Current unix time in seconds. A thin wrapper so tests can be deterministic about "now" only via
/// real elapsed time (no injected clock in this crate — governance timestamps are advisory metadata
/// here, never used for admission math inside the store itself).
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── THE DOOR (DECISIONS #2 rule (1): compiled in or dropped in, one contract, one loading path) ──
//
// The store's door lives HERE, in the logic crate (`slots`: `store_door!` over this store's
// `StoreSlots`): a busbar build that links this crate registers `door` as its compiled-in row
// (`LinkedRow::of(door)`), and the sibling `busbar-store-valkey-plugin` cdylib exports the same
// `door` as the image's one symbol (`export_door!`). One source, both doors.

/// The store's package name: the name its Statement states and its signed tarball carries.
pub const NAME: &str = "busbar-store-valkey";

impl ValkeyStore {
    /// Construct a Valkey-protocol store from the settings JSON the host hands `validate` and
    /// `open`:
    ///
    /// ```json
    /// { "url": "redis://:password@host:6379/0", "connect_timeout_ms": 10000 }
    /// ```
    ///
    /// It PARSES and connects to nothing: the first connection is `open`'s connect step
    /// ([`StoreSlots::connect`](busbar_contract::abi::sdk::store::StoreSlots::connect)), through the
    /// host's connector. `connect_timeout_ms` is optional (default [`DEFAULT_CONNECT_TIMEOUT`]).
    ///
    /// # Errors
    /// A text naming why the settings do not open a store (1.5.5's words).
    pub fn from_settings(settings: &[u8]) -> Result<Self, String> {
        let v: serde_json::Value = if settings.iter().all(u8::is_ascii_whitespace) {
            serde_json::Value::Object(Default::default())
        } else {
            serde_json::from_slice(settings)
                .map_err(|e| format!("invalid valkey plugin config: {e}"))?
        };
        let url = v.get("url").and_then(|x| x.as_str()).ok_or_else(|| {
            "valkey plugin config requires a \"url\" (a redis:// connection string)".to_string()
        })?;
        match v.get("connect_timeout_ms").and_then(|x| x.as_u64()) {
            Some(ms) => ValkeyStore::with_timeout(url, Duration::from_millis(ms)),
            None => ValkeyStore::new(url),
        }
        .map_err(|e| failed_to_connect(&e))
    }
}

/// The load's refusal for a store that does not connect, in 1.5.5's words.
fn failed_to_connect(e: &RecordStoreError) -> String {
    format!("valkey plugin: failed to connect: {}", e.0)
}

mod slots;

/// THE STORE DOOR (store v3, `busbar_contract::abi::store`): every slot of the store v3 table over
/// [`ValkeyStore`], through the contract's store SDK.
pub use slots::door;

#[cfg(test)]
mod tests;
